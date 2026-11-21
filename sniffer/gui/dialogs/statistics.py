from concurrent.futures import Future, ThreadPoolExecutor

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView, QLabel, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
)

from sniffer.analysis.stats import Counts, protocol_hierarchy
from sniffer.gui.packet_table import PacketTableModel


class StatisticsDialog(QDialog):
    def __init__(self, packets: PacketTableModel, title: str, analyze, parent=None):
        super().__init__(parent)
        self._packets = packets
        self._title = title
        self._analyze = analyze
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
