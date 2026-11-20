from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from sniffer.model.packet import PacketRecord

HEADERS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
MAX_PACKETS = 100_000
MAX_BYTES = 128 * 1024 * 1024


class PacketTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.records: list[PacketRecord] = []
        self._first_time = None
        self._stored_bytes = 0

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.records)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (0, 1, 5):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None

        row = index.row()
        record = self.records[row]
        elapsed = "—"
        if record.timestamp is not None and self._first_time is not None:
            elapsed = f"{record.timestamp - self._first_time:.6f}"
        summary = record.summary
        return (
            row + 1, elapsed, summary.source, summary.destination,
            summary.protocol, record.wire_length, summary.info,
        )[index.column()]

    def append(self, records: list[PacketRecord]) -> int:
        additions = []
        for record in records[:MAX_PACKETS - len(self.records)]:
            data_size = len(record.raw)
            if self._stored_bytes + data_size > MAX_BYTES:
                break
            self._stored_bytes += data_size
            additions.append(record)
        if additions:
            if self._first_time is None:
                self._first_time = next(
                    (item.timestamp for item in additions if item.timestamp is not None), None
                )
            first = len(self.records)
            self.beginInsertRows(QModelIndex(), first, first + len(additions) - 1)
            self.records.extend(additions)
            self.endInsertRows()
        return len(records) - len(additions)

    def replace(self, records: list[PacketRecord]) -> None:
        self.beginResetModel()
        self.records = records
        self._stored_bytes = sum(len(record.raw) for record in records)
        self._first_time = next(
            (item.timestamp for item in records if item.timestamp is not None), None
        )
        self.endResetModel()


class PacketTable(QTableView):
    def __init__(self, model: PacketTableModel, parent=None):
        super().__init__(parent)
        self.setModel(model)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setWordWrap(False)
        self.verticalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(26)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.horizontalHeader().setStretchLastSection(True)
        for column, width in enumerate((64, 112, 177, 177, 88, 76, 180)):
            self.setColumnWidth(column, width)
