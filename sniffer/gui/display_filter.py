from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal
from threading import Event

from PySide6.QtCore import QObject, QTimer, Signal

from sniffer.dissect.frame import dissect_frame
from sniffer.filter.evaluator import FilterProgram
from sniffer.gui.packet_table import PacketTableModel
from sniffer.model.packet import PacketRecord

BATCH_SIZE = 512


def _matching_rows(
    program: FilterProgram, start: int, records: list[PacketRecord],
    previous_time: Decimal | None, cancelled: Event,
) -> list[int]:
    matches = []
    for row, record in enumerate(records, start):
        if cancelled.is_set():
            break
        if program.matches(dissect_frame(record, row + 1, previous_time)):
            matches.append(row)
        previous_time = record.timestamp
    return matches


class DisplayFilterController(QObject):
    progress = Signal(int, int)
    failed = Signal(str)

    def __init__(self, model: PacketTableModel, parent=None):
        super().__init__(parent)
        self._model = model
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer display filter")
        self._program: FilterProgram | None = None
        self._generation = 0
        self._evaluated = 0
        self._cancelled = Event()
        self._job: tuple[int, int, Future] | None = None
        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._poll)
        model.records_appended.connect(self._schedule)
        model.records_replaced.connect(self._restart)

    def apply(self, program: FilterProgram | None) -> None:
        self._program = program
        self._model.begin_filter(program is not None)
        self._restart()

    def close(self) -> None:
        self._cancelled.set()
        self._timer.stop()
        self._executor.shutdown(wait=False, cancel_futures=True)

    def _restart(self) -> None:
        self._cancelled.set()
        self._cancelled = Event()
        self._generation += 1
        self._evaluated = 0
        self._schedule()

    def _schedule(self) -> None:
        if self._program is None:
            self.progress.emit(0, 0)
            return
        records = self._model.records
        total = len(records)
        self.progress.emit(self._evaluated, total)
        if self._job is not None or self._evaluated >= total:
            return
        start = self._evaluated
        end = min(start + BATCH_SIZE, total)
        previous = records[start - 1].timestamp if start else None
        # 工作线程只持有本批不可变包的引用。换文件或换表达式时，旧结果由代数丢弃。
        future = self._executor.submit(_matching_rows, self._program, start, records[start:end], previous, self._cancelled)
        self._job = self._generation, end, future
        self._timer.start()

    def _poll(self) -> None:
        if self._job is None or not self._job[2].done():
            return
        generation, end, job = self._job
        self._job = None
        self._timer.stop()
        if generation == self._generation:
            try:
                rows = job.result()
            except Exception as error:
                self.apply(None)
                self.failed.emit(f"显示过滤失败 · {error}")
                return
            self._evaluated = end
            self._model.append_matches(rows)
        self._schedule()
