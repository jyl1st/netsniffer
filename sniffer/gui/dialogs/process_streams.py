from concurrent.futures import ThreadPoolExecutor

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QTimer, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHeaderView, QHBoxLayout, QLabel, QTableView, QVBoxLayout,
)

from sniffer.analysis.follow import endpoint_label
from sniffer.analysis.process_flows import ProcessStream, summarize_process_streams
from sniffer.analysis.process_map import ProcessOwner
from sniffer.model.packet import PacketRecord

_COLUMNS = ("TCP 流", "远端地址", "已关联包数", "已关联字节")


class _StreamTable(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.streams: tuple[ProcessStream, ...] = ()

    def replace(self, streams: tuple[ProcessStream, ...]) -> None:
        self.beginResetModel()
        self.streams = streams
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.streams)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(_COLUMNS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return _COLUMNS[section] if 0 <= section < len(_COLUMNS) else None
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        stream = self.streams[index.row()]
        column = index.column()
        if column == 1:
            return "、".join(endpoint_label(peer) for peer in stream.peers)
        return (stream.number, None, f"{stream.packets:,}", f"{stream.wire_bytes:,}")[column]


class ProcessStreamsDialog(QDialog):
    def __init__(self, records: tuple[PacketRecord, ...], parent=None):
        super().__init__(parent)
        self.setWindowTitle("按进程查看 TCP 流")
        self.resize(690, 460)
        self.stream_number: int | None = None
        self._groups: list[tuple[ProcessOwner, tuple[ProcessStream, ...]]] = []
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer process streams")
        self._job = self._worker.submit(summarize_process_streams, records)

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        label = QLabel("进程")
        self._owners = QComboBox()
        self._owners.setEnabled(False)
        label.setBuddy(self._owners)
        controls.addWidget(label)
        controls.addWidget(self._owners, 1)
        layout.addLayout(controls)

        table = QTableView()
        self._model = _StreamTable(table)
        table.setModel(self._model)
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.verticalHeader().hide()
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        table.doubleClicked.connect(self._open_stream)
        self._owners.currentIndexChanged.connect(self._show_owner)
        layout.addWidget(table, 1)

        self._status = QLabel("正在汇总已捕获的 TCP 流…")
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._status)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll)
        self._timer.start(25)

    def done(self, result: int) -> None:
        self._timer.stop()
        self._worker.shutdown(wait=False, cancel_futures=True)
        super().done(result)

    def _poll(self) -> None:
        if not self._job.done():
            return
        self._timer.stop()
        try:
            self._groups = self._job.result()
        except Exception as error:
            self._status.setText(f"无法汇总 TCP 流。{error}")
            return
        if not self._groups:
            self._status.setText("当前抓包暂无与进程关联的 TCP 流。")
            return
        self._owners.addItems([owner.label for owner, _ in self._groups])
        self._owners.setEnabled(True)

    def _show_owner(self, index: int) -> None:
        streams = self._groups[index][1] if index >= 0 else ()
        self._model.replace(streams)
        self._status.setText(f"{len(streams):,} 条 TCP 流。双击应用该流的显示过滤。")

    def _open_stream(self, index: QModelIndex) -> None:
        if index.isValid():
            self.stream_number = self._model.streams[index.row()].number
            self.accept()
