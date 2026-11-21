import ctypes
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path


def _report_uncaught(exc_type, error, trace) -> None:
    local_app_data = os.environ.get("LOCALAPPDATA")
    directory = Path(local_app_data) if local_app_data else Path.home() / "AppData" / "Local"
    log = directory / "NetSniffer" / "crash.log"
    try:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a", encoding="utf-8") as output:
            output.write(f"\n{datetime.now().astimezone().isoformat(timespec='seconds')} · NetSniffer\n")
            traceback.print_exception(exc_type, error, trace, file=output)
    except OSError:
        message = f"NetSniffer 遇到未处理的错误。无法写入崩溃日志。\n{log}"
    else:
        message = f"NetSniffer 遇到未处理的错误。崩溃日志已保存。\n{log}"

    if sys.stderr is not None:
        sys.__excepthook__(exc_type, error, trace)
    if sys.platform == "win32":
        ctypes.windll.user32.MessageBoxW(None, message, "NetSniffer 错误", 0x10)


if __name__ == "__main__":
    # 在载入 Qt 和 Scapy 前安装，冻结程序的启动异常也能留下日志。
    sys.excepthook = _report_uncaught

from PySide6.QtWidgets import QApplication

from sniffer.gui.main_window import create_main_window
from sniffer.gui.theme import apply_theme


def main() -> int:
    app = QApplication(sys.argv)
    apply_theme(app)
    window = create_main_window()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
