from datetime import datetime
from enum import Enum

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from sniffer.gui.dialogs.packet_colors import DEFAULT_COLORS, readable_text
from sniffer.model.packet import MAX_BYTES, MAX_PACKETS, PacketRecord

HEADERS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
COLOR_ALIASES = {"mDNS": "DNS", "ICMPv6": "ICMP"}


class TimeMode(Enum):
    ABSOLUTE = "绝对时间"
    FIRST = "相对首包"
    PREVIOUS = "相对上一包"


class PacketTableModel(QAbstractTableModel):
    records_appended = Signal()
    records_replaced = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.records: list[PacketRecord] = []
        self._visible: list[int] | None = None
        self._first_time = None
        self._stored_bytes = 0
        self._time_mode = TimeMode.FIRST
        self.set_colors(DEFAULT_COLORS)

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid():
            return 0
        return len(self.records) if self._visible is None else len(self._visible)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole and 0 <= section < len(HEADERS):
            return HEADERS[section]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = self.record_index(index.row())
        record = self.records[row]
        summary = record.summary
        if role in (Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole):
            protocol = COLOR_ALIASES.get(summary.protocol, summary.protocol)
            group = "错误包" if summary.error and self.colors.get("错误包") else protocol
            rules = self._foreground if role == Qt.ItemDataRole.ForegroundRole else self._background
            return rules.get(group)
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (0, 1, 5):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        if index.column() == 1:
            return self._display_time(row)
        return (
            row + 1, None, summary.source, summary.destination,
            summary.protocol, record.wire_length, summary.info,
        )[index.column()]

    def _display_time(self, row: int) -> str:
        stamp = self.records[row].timestamp
        if stamp is None:
            return "—"
        if self._time_mode == TimeMode.ABSOLUTE:
            try:
                # 先转成整数微秒，再拆为秒与小数部分，避免大 Unix 时间戳的浮点误差。
                seconds, micros = divmod(round(stamp * 1_000_000), 1_000_000)
                local = datetime.fromtimestamp(seconds)
                return f"{local:%Y-%m-%d %H:%M:%S}.{micros:06d}"
            except (OverflowError, OSError, ValueError):
                return f"{stamp:.6f}"
        if self._time_mode == TimeMode.PREVIOUS:
            origin = self.records[row - 1].timestamp if row else stamp
        else:
            origin = self._first_time
        return f"{stamp - origin:.6f}" if origin is not None else "—"

    def set_time_mode(self, mode: TimeMode) -> None:
        self._time_mode = mode
        if self.rowCount():
            self.dataChanged.emit(self.index(0, 1), self.index(self.rowCount() - 1, 1))

    def set_colors(self, colors: dict[str, str | None]) -> None:
        self.colors = dict(colors)
        self._background = {name: QColor(value) for name, value in colors.items() if value}
        self._foreground = {name: readable_text(value) for name, value in self._background.items()}
        if self.rowCount():
            self.dataChanged.emit(
                self.index(0, 0), self.index(self.rowCount() - 1, len(HEADERS) - 1),
                [Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole],
            )

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
            if self._visible is None:
                first = len(self.records)
                self.beginInsertRows(QModelIndex(), first, first + len(additions) - 1)
                self.records.extend(additions)
                self.endInsertRows()
            else:
                self.records.extend(additions)
            self.records_appended.emit()
        return len(records) - len(additions)

    def replace(self, records: list[PacketRecord]) -> None:
        self.beginResetModel()
        self.records = records
        if self._visible is not None:
            self._visible = []
        self._stored_bytes = sum(len(record.raw) for record in records)
        self._first_time = next(
            (item.timestamp for item in records if item.timestamp is not None), None
        )
        self.endResetModel()
        self.records_replaced.emit()

    def record_index(self, visible_row: int) -> int:
        return visible_row if self._visible is None else self._visible[visible_row]

    def begin_filter(self, enabled: bool) -> None:
        self.beginResetModel()
        self._visible = [] if enabled else None
        self.endResetModel()

    def append_matches(self, original_rows: list[int]) -> None:
        if not original_rows or self._visible is None:
            return
        first = len(self._visible)
        self.beginInsertRows(QModelIndex(), first, first + len(original_rows) - 1)
        self._visible.extend(original_rows)
        self.endInsertRows()


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
