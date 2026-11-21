from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableView

from sniffer.analysis.process_map import ProcessMatch
from sniffer.analysis.streams import StreamIndex
from sniffer.gui.dialogs.packet_colors import DEFAULT_COLORS, readable_text
from sniffer.model.packet import MAX_BYTES, MAX_PACKETS, PacketRecord

HEADERS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "进程", "Info")
PROCESS_COLUMN = HEADERS.index("进程")
COLOR_ALIASES = {"mDNS": "DNS", "ICMPv6": "ICMP"}


class TimeMode(Enum):
    ABSOLUTE = "绝对时间"
    FIRST = "相对首包"
    PREVIOUS = "相对上一包"


@dataclass(slots=True)
class _StreamProcesses:
    rows: list[int] = field(default_factory=list)
    observed: dict[int, tuple[ProcessMatch, ...]] = field(default_factory=dict)
    matches: tuple[ProcessMatch, ...] | None = ()

    def add(self, row: int, matches: tuple[ProcessMatch, ...]) -> bool:
        self.rows.append(row)
        if self.matches is None or not matches:
            return False
        self.observed[row] = matches
        if matches == self.matches:
            return False
        known = {match.local: match for match in self.matches}
        for match in matches:
            current = known.get(match.local)
            if current is not None and current.owner.pid != match.owner.pid:
                # 四元组复用后这个流号跨越多个归属，撤销所有推断。
                self.matches = None
                return True
            if current is None or current.owner.name is None:
                known[match.local] = match
        updated = tuple(known.values())
        changed = updated != self.matches
        self.matches = updated
        return changed


class PacketTableModel(QAbstractTableModel):
    records_appended = Signal()
    records_replaced = Signal()
    processes_changed = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.records: list[PacketRecord] = []
        self._streams = StreamIndex()
        self._tcp_processes: dict[int, _StreamProcesses] = defaultdict(_StreamProcesses)
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
            protocol = COLOR_ALIASES.get(record.protocol, record.protocol)
            group = "错误包" if summary.error and self.colors.get("错误包") else protocol
            rules = self._foreground if role == Qt.ItemDataRole.ForegroundRole else self._background
            return rules.get(group)
        if role == Qt.ItemDataRole.TextAlignmentRole and index.column() in (0, 1, 5):
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole):
            return None
        if index.column() == 1:
            return self._display_time(row)
        if index.column() == PROCESS_COLUMN:
            return "、".join(owner.label for owner in record.process_owners)
        return (
            row + 1, None, summary.source, summary.destination,
            record.protocol, record.wire_length, None, record.info,
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
            additions.append(record.with_stream(self._streams))
        if additions:
            first = len(self.records)
            changed = self._backfill_processes(additions, first)
            if self._first_time is None:
                self._first_time = next(
                    (item.timestamp for item in additions if item.timestamp is not None), None
                )
            if self._visible is None:
                self.beginInsertRows(QModelIndex(), first, first + len(additions) - 1)
                self.records.extend(additions)
                self.endInsertRows()
            else:
                self.records.extend(additions)
            if changed:
                self._notify_processes_changed(changed)
            self.records_appended.emit()
        return len(records) - len(additions)

    def _backfill_processes(self, additions: list[PacketRecord], first: int) -> list[int]:
        rows_to_tag = []
        changed_streams = set()
        for index, record in enumerate(additions):
            flow, number = record.summary.flow, record.stream_id
            if flow is None or flow.protocol != "tcp" or number is None:
                continue
            state = self._tcp_processes[number]
            if state.add(first + index, record.processes):
                changed_streams.add(number)
            rows_to_tag.append((index, state))

        changed = []
        # 先看完整批次，再回填旧帧和新帧，避免在同一批中间传播冲突的归属。
        for number in changed_streams:
            state = self._tcp_processes[number]
            for row in state.rows:
                if row >= first:
                    break
                record = self.records[row]
                matches = state.matches if state.matches is not None else state.observed.get(row, ())
                if record.processes != matches:
                    self.records[row] = replace(record, processes=matches)
                    changed.append(row)
            if state.matches is None:
                state.observed.clear()
        for index, state in rows_to_tag:
            record = additions[index]
            if state.matches and state.matches != record.processes:
                additions[index] = replace(record, processes=state.matches)
        return changed

    def _notify_processes_changed(self, rows: list[int]) -> None:
        rows.sort()
        first, last = rows[0], rows[-1]
        if self._visible is not None:
            first = bisect_left(self._visible, first)
            last = bisect_right(self._visible, last) - 1
        if first <= last:
            self.dataChanged.emit(
                self.index(first, PROCESS_COLUMN), self.index(last, PROCESS_COLUMN),
                [Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.ToolTipRole],
            )
        self.processes_changed.emit(tuple(rows))

    def replace(self, records: list[PacketRecord], *, streams: StreamIndex | None = None) -> None:
        if streams is None:
            streams = StreamIndex()
            records = [record.with_stream(streams) for record in records]
        else:
            records = list(records)
        self.beginResetModel()
        self.records = records
        self._streams = streams
        self._tcp_processes.clear()
        self._backfill_processes(records, 0)
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

    def truncate_matches(self, start: int) -> None:
        if self._visible is None:
            return
        first = bisect_left(self._visible, start)
        if first < len(self._visible):
            self.beginRemoveRows(QModelIndex(), first, len(self._visible) - 1)
            del self._visible[first:]
            self.endRemoveRows()


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
        for column, width in enumerate((64, 112, 177, 177, 88, 76, 156, 180)):
            self.setColumnWidth(column, width)
