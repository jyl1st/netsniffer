from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from decimal import Decimal

from PySide6.QtCore import QAbstractItemModel, QAbstractTableModel, QModelIndex, QTimer, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QHeaderView, QHBoxLayout, QLabel, QTableView, QTreeView, QVBoxLayout,
)

from sniffer.analysis.expert import ExpertKind, ExpertSeverity, analyze_expert
from sniffer.analysis.ids import SecurityAlert, analyze_alerts
from sniffer.gui.packet_table import PacketTableModel
from sniffer.gui.theme import BadgeDelegate
from sniffer.model.packet import PacketRecord

_TABLE_COLUMNS = ("相对时间（秒）", "类型", "严重程度", "来源", "描述（已打码）", "相关帧数")
_TREE_COLUMNS = ("严重程度 / 类型", "帧号", "简述")
_DISPLAY = Qt.ItemDataRole.DisplayRole
_TOOLTIP = Qt.ItemDataRole.ToolTipRole
_SEVERITY_BADGES = {
    "高": ("#f9e1e2", "#9a2935"),
    "警告": ("#fcebd7", "#974b16"),
    "Warning": ("#fcebd7", "#974b16"),
    "Note": ("#e5edf5", "#405875"),
}


def _timed_alerts(records: tuple[PacketRecord, ...]) -> tuple[tuple[SecurityAlert, Decimal | None], ...]:
    origin = next((record.timestamp for record in records if record.timestamp is not None), None)
    rows = []
    for alert in analyze_alerts(records):
        stamp = records[alert.first_frame - 1].timestamp
        rows.append((alert, stamp - origin if stamp is not None and origin is not None else None))
    return tuple(rows)


class _AlertTable(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rows: tuple[tuple[SecurityAlert, Decimal | None], ...] = ()

    def replace(self, rows: tuple[tuple[SecurityAlert, Decimal | None], ...]) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(_TABLE_COLUMNS)

    def headerData(self, section, orientation, role=_DISPLAY):
        if orientation == Qt.Orientation.Horizontal and role == _DISPLAY and 0 <= section < len(_TABLE_COLUMNS):
            return _TABLE_COLUMNS[section]
        return None

    def data(self, index, role=_DISPLAY):
        if not index.isValid() or role not in (_DISPLAY, _TOOLTIP):
            return None
        alert, timestamp = self.rows[index.row()]
        if role == _TOOLTIP and index.column() == 5:
            frames = ", ".join(str(frame) for frame in alert.frames[:30])
            return f"帧 {frames}" + (" …" if len(alert.frames) > 30 else "")
        return (
            f"{timestamp:.6f}" if timestamp is not None else "—",
            alert.kind.value, alert.severity.value, alert.source, alert.description, f"{len(alert.frames):,}",
        )[index.column()]


@dataclass(slots=True)
class _TreeNode:
    title: str = ""
    frame: int | None = None
    description: str = ""
    parent: "_TreeNode | None" = None
    row: int = 0
    children: list["_TreeNode"] = field(default_factory=list)

    def append(self, title: str, frame: int | None = None, description: str = "") -> "_TreeNode":
        node = _TreeNode(title, frame, description, self, len(self.children))
        self.children.append(node)
        return node


def _grouped_expert(records: tuple[PacketRecord, ...]) -> tuple[_TreeNode, int]:
    events = analyze_expert(records)
    groups = defaultdict(list)
    for event in events:
        groups[event.severity, event.kind].append(event)
    root = _TreeNode()
    for severity in ExpertSeverity:
        count = sum(len(groups[severity, kind]) for kind in ExpertKind)
        if count == 0:
            continue
        branch = root.append(f"{severity.value} ({count:,})")
        for kind in ExpertKind:
            entries = groups[severity, kind]
            if entries:
                sub = branch.append(f"{kind.value} ({len(entries):,})")
                for entry in entries:
                    sub.append("", entry.frame, entry.description)
    return root, len(events)


class _ExpertTree(QAbstractItemModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.root = _TreeNode()

    def replace(self, root: _TreeNode) -> None:
        self.beginResetModel()
        self.root = root
        self.endResetModel()

    def index(self, row, column, parent=QModelIndex()):
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        node = parent.internalPointer() if parent.isValid() else self.root
        return self.createIndex(row, column, node.children[row])

    def parent(self, index):
        if not index.isValid():
            return QModelIndex()
        parent = index.internalPointer().parent
        if parent is None or parent is self.root:
            return QModelIndex()
        return self.createIndex(parent.row, 0, parent)

    def rowCount(self, parent=QModelIndex()):
        if parent.column() > 0:
            return 0
        node = parent.internalPointer() if parent.isValid() else self.root
        return len(node.children)

    def columnCount(self, parent=QModelIndex()):
        return len(_TREE_COLUMNS)

    def headerData(self, section, orientation, role=_DISPLAY):
        if orientation == Qt.Orientation.Horizontal and role == _DISPLAY and 0 <= section < len(_TREE_COLUMNS):
            return _TREE_COLUMNS[section]
        return None

    def data(self, index, role=_DISPLAY):
        if not index.isValid() or role not in (_DISPLAY, _TOOLTIP):
            return None
        node = index.internalPointer()
        return (node.title, node.frame, node.description)[index.column()]


class _AnalysisDialog(QDialog):
    def __init__(self, packets: PacketTableModel, title: str, analyze, *, refresh: bool = False, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.frame_number: int | None = None
        self.capture_records = packets.records
        self._packets = packets
        self._analyze = analyze
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer capture analysis")
        self._job: Future | None = None
        self._snapshot_size = 0

        self._view_layout = QVBoxLayout(self)
        footer = QHBoxLayout()
        self._status = QLabel()
        self._status.setWordWrap(True)
        footer.addWidget(self._status, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        buttons.rejected.connect(self.reject)
        self._refresh = None
        if refresh:
            self._refresh = buttons.addButton("刷新", QDialogButtonBox.ButtonRole.ActionRole)
            self._refresh.clicked.connect(self._start)
        footer.addWidget(buttons)
        self._view_layout.addLayout(footer)

        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._poll)

    def _start(self) -> None:
        self.capture_records = self._packets.records
        snapshot = tuple(self.capture_records)
        self._snapshot_size = len(snapshot)
        self._status.setText(f"正在分析 {self._snapshot_size:,} 帧…")
        if self._refresh is not None:
            self._refresh.setEnabled(False)
        self.view.setEnabled(False)
        self._job = self._worker.submit(self._analyze, snapshot)
        self._timer.start()

    def _poll(self) -> None:
        if self._job is None or not self._job.done():
            return
        job = self._job
        self._job = None
        self._timer.stop()
        if self._refresh is not None:
            self._refresh.setEnabled(True)
        try:
            count = self._show_result(job.result())
        except Exception:
            self._status.setText("分析失败，请重试。")
            return
        self.view.setEnabled(True)
        detail = " · 双击条目定位原始帧" if count else ""
        self._status.setText(f"已分析 {self._snapshot_size:,} 帧 · {count:,} 条{detail}")

    def _jump(self, frame: int) -> None:
        self.frame_number = frame
        self.accept()

    def done(self, result: int) -> None:
        self._timer.stop()
        self._worker.shutdown(wait=False, cancel_futures=True)
        super().done(result)


class SecurityAlertsDialog(_AnalysisDialog):
    def __init__(self, packets: PacketTableModel, parent=None):
        super().__init__(packets, "安全告警", _timed_alerts, refresh=True, parent=parent)
        self.resize(1180, 460)
        self.view = QTableView()
        self._model = _AlertTable(self.view)
        self.view.setModel(self._model)
        self.view.setItemDelegateForColumn(2, BadgeDelegate(_SEVERITY_BADGES, self.view))
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.view.verticalHeader().hide()
        self.view.verticalHeader().setDefaultSectionSize(51)
        self.view.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 115), (1, 95), (2, 75), (3, 230), (5, 82)):
            self.view.setColumnWidth(column, width)
        self.view.doubleClicked.connect(self._open_row)
        self._view_layout.insertWidget(0, self.view, 1)
        self._start()

    def _show_result(self, rows) -> int:
        self._model.replace(rows)
        return len(rows)

    def _open_row(self, index: QModelIndex) -> None:
        if index.isValid():
            self._jump(self._model.rows[index.row()][0].first_frame)


class ExpertInfoDialog(_AnalysisDialog):
    def __init__(self, packets: PacketTableModel, parent=None):
        super().__init__(packets, "专家信息", _grouped_expert, parent=parent)
        self.resize(850, 420)
        self.view = QTreeView()
        self._model = _ExpertTree(self.view)
        self.view.setModel(self._model)
        self.view.setItemDelegateForColumn(0, BadgeDelegate(_SEVERITY_BADGES, self.view))
        self.view.setUniformRowHeights(True)
        self.view.setAlternatingRowColors(True)
        self.view.setExpandsOnDoubleClick(True)
        self.view.setColumnWidth(0, 230)
        self.view.setColumnWidth(1, 85)
        self.view.doubleClicked.connect(self._open_row)
        self._view_layout.insertWidget(0, self.view, 1)
        self._start()

    def _show_result(self, result: tuple[_TreeNode, int]) -> int:
        root, count = result
        self._model.replace(root)
        self.view.expandToDepth(1)
        return count

    def _open_row(self, index: QModelIndex) -> None:
        if index.isValid():
            frame = index.internalPointer().frame
            if frame is not None:
                self._jump(frame)
