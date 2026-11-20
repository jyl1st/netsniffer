from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QFontDatabase, QPalette
from PySide6.QtWidgets import QAbstractItemView, QTableView

BYTES_PER_ROW = 16
ASCII_FIRST = BYTES_PER_ROW + 1
COLUMNS = BYTES_PER_ROW * 2 + 1


class HexModel(QAbstractTableModel):
    def __init__(self, palette: QPalette, parent=None):
        super().__init__(parent)
        self.raw = b""
        self._first = self._end = 0
        self._palette = palette

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else (len(self.raw) + BYTES_PER_ROW - 1) // BYTES_PER_ROW

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else COLUMNS

    def offset_at(self, index: QModelIndex) -> int | None:
        column = index.column()
        if not index.isValid() or column == 0:
            return None
        offset = index.row() * BYTES_PER_ROW + (column - 1) % BYTES_PER_ROW
        return offset if offset < len(self.raw) else None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return Qt.AlignmentFlag.AlignCenter
        if index.column() == 0:
            if role == Qt.ItemDataRole.DisplayRole:
                return f"{index.row() * BYTES_PER_ROW:06X}"
            if role == Qt.ItemDataRole.ForegroundRole:
                return self._palette.brush(QPalette.ColorRole.PlaceholderText)
            return None
        offset = self.offset_at(index)
        if offset is None:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            value = self.raw[offset]
            if index.column() < ASCII_FIRST:
                return f"{value:02X}"
            return chr(value) if 32 <= value < 127 else "."
        if self._first <= offset < self._end:
            if role == Qt.ItemDataRole.BackgroundRole:
                return self._palette.brush(QPalette.ColorRole.Highlight)
            if role == Qt.ItemDataRole.ForegroundRole:
                return self._palette.brush(QPalette.ColorRole.HighlightedText)
        if role == Qt.ItemDataRole.ToolTipRole:
            return f"偏移 {offset}（0x{offset:X}）"
        return None

    def replace(self, raw: bytes) -> None:
        self.beginResetModel()
        self.raw = raw
        self._first = self._end = 0
        self.endResetModel()

    def highlight(self, offset: int, length: int) -> None:
        start, end = min(offset, len(self.raw)), min(offset + length, len(self.raw))
        old_start, old_end = self._first, self._end
        self._first, self._end = start, end
        roles = [Qt.ItemDataRole.BackgroundRole, Qt.ItemDataRole.ForegroundRole]
        for low, high in ((old_start, old_end), (start, end)):
            if low < high:
                first_row, last_row = low // BYTES_PER_ROW, (high - 1) // BYTES_PER_ROW
                self.dataChanged.emit(self.index(first_row, 1), self.index(last_row, COLUMNS - 1), roles)


class HexView(QTableView):
    byte_selected = Signal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bytes = HexModel(self.palette(), self)
        self.setModel(self._bytes)
        self.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().hide()
        self.horizontalHeader().hide()
        self.verticalHeader().setDefaultSectionSize(24)
        self.horizontalHeader().setMinimumSectionSize(8)
        self.setColumnWidth(0, 64)
        for column in range(1, COLUMNS):
            self.setColumnWidth(column, 24 if column < ASCII_FIRST else 12)
        self.clicked.connect(self._byte_clicked)

    def set_packet(self, raw: bytes) -> None:
        self._bytes.replace(raw)
        self.scrollToTop()

    def highlight(self, offset: int, length: int) -> None:
        self._bytes.highlight(offset, length)
        if length > 0:
            self.scrollTo(self._bytes.index(offset // BYTES_PER_ROW, 0))

    def _byte_clicked(self, index: QModelIndex) -> None:
        offset = self._bytes.offset_at(index)
        if offset is not None:
            self.byte_selected.emit(offset)
