"""测量 50,000 帧的显示过滤耗时与 Qt 主线程响应。"""

import argparse
import os
import platform
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from PySide6 import __version__ as pyside_version
from PySide6.QtCore import QEventLoop, QSettings, Qt, QTimer
from PySide6.QtWidgets import QApplication, QVBoxLayout, QWidget

from sniffer.capture.pcap_io import read_capture, write_capture
from sniffer.gui.display_filter import DisplayFilterController
from sniffer.gui.filter_bar import DisplayFilterBar
from sniffer.gui.packet_table import PacketTable, PacketTableModel
from tools.compare_tshark import FILTER_CASES, SAMPLES

FRAME_COUNT = 50_000
HEARTBEAT_MS = 30


def measure(app, bar, controller, model, expression: str, expected_rows: list[int]):
    loop = QEventLoop()
    heartbeat = QTimer()
    heartbeat.setTimerType(Qt.TimerType.PreciseTimer)
    timeout = QTimer()
    timeout.setSingleShot(True)
    gaps = []
    errors = []
    finished = None

    def beat():
        nonlocal last_beat
        now = perf_counter()
        gaps.append(now - last_beat)
        last_beat = now

    def progress(evaluated, total):
        nonlocal finished
        if evaluated == total == FRAME_COUNT:
            finished = perf_counter()
            loop.quit()

    def fail(message):
        errors.append(message)
        loop.quit()

    heartbeat.timeout.connect(beat)
    timeout.timeout.connect(loop.quit)
    controller.progress.connect(progress)
    controller.failed.connect(fail)
    bar.editor.setText(expression)
    app.processEvents()
    try:
        timeout.start(30_000)
        started = last_beat = perf_counter()
        heartbeat.start(HEARTBEAT_MS)
        bar.apply_button.click()
        if not errors and finished is None:
            loop.exec()
    finally:
        heartbeat.stop()
        timeout.stop()
        controller.progress.disconnect(progress)
        controller.failed.disconnect(fail)

    if errors:
        raise RuntimeError(errors[0])
    if finished is None or not gaps:
        raise RuntimeError(f"过滤超时或 Qt 心跳无响应：{expression}")
    rows = [model.record_index(row) for row in range(model.rowCount())]
    if rows != expected_rows:
        raise RuntimeError(f"命中帧不一致：{expression}（实际 {len(rows)}，预期 {len(expected_rows)}）")
    return (finished - started) * 1000, max(*gaps, finished - last_beat) * 1000


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=3, help="每条表达式的测量次数")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs 至少为 1")

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication([])
    print(f"{platform.platform()} | Python {platform.python_version()} | "
          f"PySide6 {pyside_version} | Qt {app.platformName()}", flush=True)
    with TemporaryDirectory() as directory:
        sample = read_capture(SAMPLES / "display_filters.pcap")
        capture = Path(directory) / "display-filter-50000.pcap"
        write_capture(capture, [
            replace(sample[row % len(sample)], timestamp=Decimal(1_700_000_000) + Decimal(row).scaleb(-3))
            for row in range(FRAME_COUNT)
        ])

        window = QWidget()
        window.resize(1120, 720)
        layout = QVBoxLayout(window)
        settings = QSettings(str(Path(directory) / "filter.ini"), QSettings.Format.IniFormat)
        bar = DisplayFilterBar(settings=settings)
        model = PacketTableModel(window)
        controller = DisplayFilterController(model, window)
        bar.submitted.connect(controller.apply)
        controller.progress.connect(bar.show_progress)
        layout.addWidget(bar)
        layout.addWidget(PacketTable(model, window))
        model.replace(read_capture(capture))
        window.show()
        try:
            for attempt in range(1, args.runs + 1):
                for expression, _, expected in FILTER_CASES[:3]:
                    expected_rows = [row for row in range(FRAME_COUNT) if row % len(sample) + 1 in expected]
                    elapsed, gap = measure(app, bar, controller, model, expression, expected_rows)
                    print(f"{attempt} | {len(expected_rows)}/{FRAME_COUNT} | {elapsed:.1f} ms | "
                          f"Qt max gap {gap:.1f} ms | {expression}", flush=True)
        finally:
            controller.close()
            window.close()
            settings.sync()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
