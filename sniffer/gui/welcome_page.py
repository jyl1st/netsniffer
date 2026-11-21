from collections import deque

from PySide6.QtCore import QPointF, QSignalBlocker, Qt, QTimer, Signal
from PySide6.QtGui import QPainter, QPalette, QPen, QPolygonF
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sniffer.capture.interfaces import Adapter, preferred_adapter, read_counters
from sniffer.gui.theme import APP_VERSION, BadgeDelegate

_ADAPTER_BADGES = {
    "有线": ("#dcefeb", "#205950"), "无线": ("#dcefeb", "#205950"),
    "虚拟": ("#edf2f2", "#475e60"), "回环": ("#edf2f2", "#475e60"),
    "其他": ("#edf2f2", "#475e60"),
}


class TrafficPlot(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._samples = deque(maxlen=30)
        self._selected = False

    def set_selected(self, selected: bool) -> None:
        if self._selected != selected:
            self._selected = selected
            self.update()

    def append(self, rate: float) -> None:
        self._samples.append(rate)
        self.setToolTip(f"收发合计 {rate / 1024:,.1f} KiB/s")
        self.update()

    def paintEvent(self, event) -> None:
        if not self._samples:
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        role = QPalette.ColorRole.HighlightedText if self._selected else QPalette.ColorRole.Highlight
        painter.setPen(QPen(self.palette().color(role), 1.5))
        width, height = max(1, self.width() - 14), max(1, self.height() - 12)
        peak = max(1, max(self._samples))
        points = [
            QPointF(7 + (30 - len(self._samples) + index) * width / 29, 6 + height * (1 - rate / peak))
            for index, rate in enumerate(self._samples)
        ]
        if len(points) == 1:
            painter.drawPoint(points[0])
        else:
            painter.drawPolyline(QPolygonF(points))


class WelcomePage(QWidget):
    capture_requested = Signal()
    selection_changed = Signal()

    def __init__(self, adapters: list[Adapter], notice: str = "", parent=None):
        super().__init__(parent)
        self.adapters = adapters
        self._previous_sample = None
        self._manual_selection = False

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 16)
        heading = QHBoxLayout()
        title = QLabel("NetSniffer")
        font = title.font()
        font.setPointSize(22)
        font.setBold(True)
        title.setFont(font)
        heading.addWidget(title)
        version = QLabel(APP_VERSION)
        version.setObjectName("versionBadge")
        heading.addWidget(version, 0, Qt.AlignmentFlag.AlignVCenter)
        heading.addStretch()
        layout.addLayout(heading)

        description = QLabel("捕获网络数据包，查看协议、连接时序与安全告警。")
        description.setObjectName("welcomeDescription")
        description.setWordWrap(True)
        layout.addWidget(description)

        hint = QLabel(notice or "双击网卡开始抓包。流量曲线显示最近 30 秒的收发速率。")
        hint.setObjectName("welcomeHint")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.table = QTableWidget(len(adapters), 6)
        self.table.setHorizontalHeaderLabels(("名称", "描述", "类型", "IP 地址", "MAC 地址", "流量"))
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setItemDelegateForColumn(2, BadgeDelegate(_ADAPTER_BADGES, self.table))
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(42)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        for column, width in ((0, 180), (2, 58), (3, 180), (4, 133), (5, 110)):
            self.table.setColumnWidth(column, width)
        layout.addWidget(self.table)

        self._plots = []
        for row, adapter in enumerate(adapters):
            addresses = "\n".join(adapter.ipv4 + adapter.ipv6)
            values = (adapter.name, adapter.description, adapter.kind, addresses or "—", adapter.mac)
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, column, item)
            plot = TrafficPlot()
            self._plots.append(plot)
            self.table.setCellWidget(row, 5, plot)

        self._select_default({})
        self.table.currentCellChanged.connect(self._record_selection)
        self.table.cellClicked.connect(self._record_selection)
        self.table.cellDoubleClicked.connect(lambda *_: self.capture_requested.emit())
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._sample)
        if adapters:
            self._sample()
            self._timer.start()

    @property
    def selected_adapter(self) -> Adapter | None:
        row = self.table.currentRow()
        return self.adapters[row] if row >= 0 else None

    def _record_selection(self, *_):
        self._manual_selection = True
        self._update_plot_selection()
        self.selection_changed.emit()

    def _select_default(self, rates: dict[str, float]) -> None:
        row = preferred_adapter(self.adapters, rates)
        if row >= 0 and row != self.table.currentRow():
            with QSignalBlocker(self.table):
                self.table.setCurrentCell(row, 0)
            self._update_plot_selection()
            self.selection_changed.emit()

    def _update_plot_selection(self) -> None:
        selected = self.table.currentRow()
        for row, plot in enumerate(self._plots):
            plot.set_selected(row == selected)

    def _sample(self) -> None:
        try:
            current = read_counters()
        except OSError:
            return

        previous = self._previous_sample
        self._previous_sample = current
        if previous is None:
            return

        now, totals = current
        old_time, old_totals = previous
        interval = max(0.001, now - old_time)
        rates = {
            name: max(0, total - old_totals[name]) / interval
            for name, total in totals.items()
            if name in old_totals
        }
        for adapter, plot in zip(self.adapters, self._plots):
            if adapter.name in rates:
                plot.append(rates[adapter.name])
        if not self._manual_selection:
            self._select_default(rates)
