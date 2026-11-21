from concurrent.futures import Future, ThreadPoolExecutor
from decimal import Decimal

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QTimer, Qt
from PySide6.QtWidgets import (
    QAbstractItemView, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView, QLabel, QMenu, QTabWidget, QTableView,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from sniffer.analysis.stats import ADDRESS_GROUPS, Conversation, Counts, conversations, protocol_hierarchy
from sniffer.gui.packet_table import PacketTableModel


class StatisticsDialog(QDialog):
    def __init__(self, packets: PacketTableModel, title: str, analyze, parent=None):
        super().__init__(parent)
        self._packets = packets
        self._title = title
        self._analyze = analyze
        self.capture_records = packets.records
        self.requested_filter: str | None = None
        self.requested_stream: int | None = None
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer statistics")
        self._job: Future | None = None
        self._count = 0
        self.layout_main = QVBoxLayout(self)

        footer = QHBoxLayout()
        self._status = QLabel()
        footer.addWidget(self._status, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        buttons.rejected.connect(self.reject)
        self._refresh = buttons.addButton("刷新", QDialogButtonBox.ButtonRole.ActionRole)
        self._refresh.clicked.connect(self.refresh)
        footer.addWidget(buttons)
        self.layout_main.addLayout(footer)

        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._poll)

    def refresh(self) -> None:
        if self._job is not None:
            return
        self.capture_records = self._packets.records
        snapshot, filtered = self._packets.statistics_snapshot()
        self.setWindowTitle(self._title + ("（仅显示的帧）" if filtered else ""))
        self._count = len(snapshot.frames)
        self._status.setText(f"正在统计 {self._count:,} 帧…")
        self._refresh.setEnabled(False)
        self.view.setEnabled(False)
        self._job = self._executor.submit(self._analyze, snapshot)
        self._timer.start()

    def _poll(self) -> None:
        if self._job is None or not self._job.done():
            return
        job, self._job = self._job, None
        self._timer.stop()
        self._refresh.setEnabled(True)
        try:
            self.show_result(job.result())
        except Exception as error:
            self._status.setText("统计失败，请重试。")
            self._status.setToolTip(str(error))
            return
        self.view.setEnabled(True)
        self._status.setToolTip("")
        self._status.setText(f"已统计 {self._count:,} 帧")

    def done(self, result: int) -> None:
        self._timer.stop()
        self._executor.shutdown(wait=False, cancel_futures=True)
        super().done(result)


class ProtocolHierarchyDialog(StatisticsDialog):
    def __init__(self, packets: PacketTableModel, parent=None):
        super().__init__(packets, "协议层级", protocol_hierarchy, parent)
        self.resize(800, 480)
        self.view = QTreeWidget()
        self.view.setHeaderLabels(("协议", "帧数", "帧占比", "字节数", "字节占比"))
        self.view.setAlternatingRowColors(True)
        self.view.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.layout_main.insertWidget(0, self.view, 1)
        self.refresh()

    def show_result(self, nodes: dict[tuple[str, ...], Counts]) -> None:
        self.view.clear()
        total = nodes[("Frame",)]
        items = {}
        for path, counts in nodes.items():
            frame_ratio = counts.frames / total.frames if total.frames else 0
            byte_ratio = counts.bytes / total.bytes if total.bytes else 0
            item = QTreeWidgetItem((path[-1], f"{counts.frames:,}", f"{frame_ratio:.2%}",
                                    f"{counts.bytes:,}", f"{byte_ratio:.2%}"))
            if path[:-1] in items:
                items[path[:-1]].addChild(item)
            else:
                self.view.addTopLevelItem(item)
            items[path] = item
        self.view.expandAll()


class _StatsTable(QAbstractTableModel):
    def __init__(self, columns, parent=None):
        super().__init__(parent)
        self.columns = columns
        self.rows = []

    def replace(self, rows) -> None:
        self.beginResetModel()
        self.rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if (orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole
                and 0 <= section < len(self.columns)):
            return self.columns[section][0]
        return None

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role not in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.UserRole):
            return None
        value = self.columns[index.column()][1](self.rows[index.row()])
        if role == Qt.ItemDataRole.UserRole:
            if value is None:
                return -1
            return float(value) if isinstance(value, Decimal) else value
        if value is None:
            return "—"
        return f"{value:.6f}" if isinstance(value, Decimal) else value


class _AddressStatsDialog(StatisticsDialog):
    def __init__(self, packets, title, analyze, columns, parent=None):
        super().__init__(packets, title, analyze, parent)
        self.resize(1160, 530)
        self.view = QTabWidget()
        self._models = {}
        for group in ADDRESS_GROUPS:
            table = QTableView()
            model = _StatsTable(columns, table)
            proxy = QSortFilterProxyModel(table)
            proxy.setSourceModel(model)
            proxy.setSortRole(Qt.ItemDataRole.UserRole)
            table.setModel(proxy)
            table.setSortingEnabled(True)
            table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
            table.setAlternatingRowColors(True)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.verticalHeader().hide()
            table.horizontalHeader().setStretchLastSection(True)
            table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            table.customContextMenuRequested.connect(
                lambda pos, group=group, table=table: self._row_menu(group, table, pos)
            )
            self._models[group] = model
            self.view.addTab(table, group)
        self.layout_main.insertWidget(0, self.view, 1)

    def show_result(self, groups) -> None:
        for group, entries in groups.items():
            self._models[group].replace(entries)

    def _row_menu(self, group, table, pos) -> None:
        proxy = table.model()
        index = proxy.mapToSource(table.indexAt(pos))
        if index.isValid():
            self.open_row_menu(group, proxy.sourceModel().rows[index.row()], table.viewport().mapToGlobal(pos))

    def apply_filter(self, expression: str) -> None:
        self.requested_filter = expression
        self.accept()


_CONVERSATION_COLUMNS = (
    ("地址 A", lambda row: row.a[0]), ("端口 A", lambda row: row.a[1]),
    ("地址 B", lambda row: row.b[0]), ("端口 B", lambda row: row.b[1]),
    ("总帧数", lambda row: row.frames), ("总字节数", lambda row: row.bytes),
    ("A→B 帧数", lambda row: row.forward.frames), ("A→B 字节", lambda row: row.forward.bytes),
    ("B→A 帧数", lambda row: row.reverse.frames), ("B→A 字节", lambda row: row.reverse.bytes),
    ("起始时间 (s)", lambda row: row.start), ("持续时间 (s)", lambda row: row.duration),
    ("流编号", lambda row: row.stream),
)


class ConversationStatsDialog(_AddressStatsDialog):
    def __init__(self, packets, parent=None):
        super().__init__(packets, "会话", conversations, _CONVERSATION_COLUMNS, parent)
        for index in range(self.view.count()):
            table = self.view.widget(index)
            for column in (0, 2):
                table.setColumnWidth(column, 145)
            for column in (1, 3, 12):
                table.setColumnWidth(column, 60)
            for column in range(4, 10):
                table.setColumnWidth(column, 73)
            for column in (10, 11):
                table.setColumnWidth(column, 102)
            if index < 2:
                for column in (1, 3, 12):
                    table.setColumnHidden(column, True)
        self.refresh()

    def open_row_menu(self, group: str, row: Conversation, position) -> None:
        menu = QMenu(self)
        apply = menu.addAction("以此会话过滤")
        graph = menu.addAction("时序图") if group == "TCP" and row.stream is not None else None
        ip_group = group in ("IPv4", "IPv6")
        apply.setEnabled(ip_group or row.stream is not None)
        selected = menu.exec(position)
        if selected == apply:
            if ip_group:
                field = "ip.addr" if group == "IPv4" else "ipv6.addr"
                self.apply_filter(f"{field} == {row.a[0]} && {field} == {row.b[0]}")
            else:
                self.apply_filter(f"{group.lower()}.stream == {row.stream}")
        elif graph is not None and selected == graph:
            self.requested_stream = row.stream
            self.accept()
