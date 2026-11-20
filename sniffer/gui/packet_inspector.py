from collections import OrderedDict
from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QLabel, QSplitter, QVBoxLayout, QWidget

from sniffer.dissect.field import Field
from sniffer.dissect.frame import dissect_frame
from sniffer.gui.detail_tree import DetailTree
from sniffer.gui.hex_view import HexView
from sniffer.gui.packet_table import PacketTable, PacketTableModel
from sniffer.model.packet import PacketRecord

Key = tuple[int, int]
MAX_CACHED_TREES = 128


class PacketInspector(QSplitter):
    def __init__(self, model: PacketTableModel, table: PacketTable, parent=None):
        super().__init__(Qt.Orientation.Vertical, parent)
        self._packets = model
        self._revision = 0
        self._current: tuple[Key, PacketRecord, Decimal | None] | None = None
        self._job: tuple[Key, Future] | None = None
        self._cache: OrderedDict[Key, Field] = OrderedDict()
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer dissector")

        self.details = DetailTree()
        self.hex_view = HexView()
        lower = QSplitter(Qt.Orientation.Horizontal)
        lower.addWidget(self._panel("协议详情", self.details))
        lower.addWidget(self._panel("十六进制 / ASCII", self.hex_view))
        lower.setStretchFactor(0, 2)
        lower.setStretchFactor(1, 3)
        lower.setChildrenCollapsible(False)
        self.addWidget(table)
        self.addWidget(lower)
        self.setStretchFactor(0, 3)
        self.setStretchFactor(1, 2)
        self.setSizes([380, 270])
        self.setChildrenCollapsible(False)

        table.selectionModel().currentRowChanged.connect(self._select_packet)
        model.modelAboutToBeReset.connect(self._reset)
        self.details.field_selected.connect(self._highlight_field)
        self.hex_view.byte_selected.connect(self.details.select_byte)
        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._poll)

    @staticmethod
    def _panel(label: str, content: QWidget) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(6, 4, 6, 4)
        layout.setSpacing(4)
        title = QLabel(label)
        font = title.font()
        font.setBold(True)
        title.setFont(font)
        layout.addWidget(title)
        layout.addWidget(content)
        return panel

    def close_worker(self) -> None:
        self._timer.stop()
        self._worker.shutdown(wait=False, cancel_futures=True)

    def _reset(self) -> None:
        self._revision += 1
        self._cache.clear()
        self._clear()

    def _clear(self) -> None:
        self._current = None
        self.hex_view.set_packet(b"")
        self.details.show_message("选择一个包以查看协议字段。")

    def _select_packet(self, index, _previous) -> None:
        row = index.row()
        if row < 0 or row >= self._packets.rowCount():
            self._clear()
            return
        record = self._packets.records[row]
        previous_time = self._packets.records[row - 1].timestamp if row else None
        key = self._revision, row
        self._current = key, record, previous_time
        self.hex_view.set_packet(record.raw)
        if key in self._cache:
            self._cache.move_to_end(key)
            self.details.show_fields(self._cache[key])
            return
        self.details.show_message("正在解析选中的包…")
        self._start_job()

    def _start_job(self) -> None:
        if self._job is not None or self._current is None:
            return
        key, record, previous_time = self._current
        if key in self._cache:
            return
        self._job = key, self._worker.submit(dissect_frame, record, key[1] + 1, previous_time)
        self._timer.start()

    def _poll(self) -> None:
        if self._job is None or not self._job[1].done():
            return
        key, result = self._job
        self._job = None
        self._timer.stop()
        current = self._current is not None and self._current[0] == key
        try:
            tree = result.result()
        except Exception as error:
            if current:
                self.details.show_message(f"解析失败 · {error}")
                return
        else:
            if key[0] == self._revision:
                self._cache[key] = tree
                if len(self._cache) > MAX_CACHED_TREES:
                    self._cache.popitem(last=False)
            if current:
                self.details.show_fields(tree)
        self._start_job()

    def _highlight_field(self, field: Field | None) -> None:
        if field is not None:
            self.hex_view.highlight(field.offset, field.length)
        else:
            self.hex_view.highlight(0, 0)
