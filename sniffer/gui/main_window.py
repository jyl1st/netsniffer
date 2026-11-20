import ctypes
import sys
from concurrent.futures import Future, ThreadPoolExecutor
from ipaddress import ip_address
from pathlib import Path

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QActionGroup, QKeySequence
from PySide6.QtWidgets import (
    QCheckBox, QFileDialog, QLabel, QMainWindow, QMessageBox, QStackedWidget, QVBoxLayout, QWidget,
)
from scapy.all import conf

from sniffer.capture.engine import CaptureSession, CaptureSettings
from sniffer.capture.interfaces import list_adapters
from sniffer.capture.pcap_io import read_capture_preview, write_capture
from sniffer.filter.fields import known_field
from sniffer.gui.capture_filter import CaptureFilterBox
from sniffer.gui.dialogs.packet_colors import PacketColorsDialog
from sniffer.gui.display_filter import DisplayFilterController
from sniffer.gui.filter_bar import DisplayFilterBar
from sniffer.gui.packet_inspector import PacketInspector
from sniffer.gui.packet_table import HEADERS, PacketTable, PacketTableModel, TimeMode
from sniffer.gui.welcome_page import WelcomePage


def startup_status() -> tuple[bool, str]:
    if sys.platform != "win32":
        return False, "实时抓包需要 Windows 和 Npcap。"
    if not (conf.use_pcap and conf.use_npcap):
        return False, "未检测到 Npcap。请安装 Npcap 后重新启动。"
    if not ctypes.windll.shell32.IsUserAnAdmin():
        return True, "已检测到 Npcap。当前非管理员，若抓包失败，请以管理员身份运行。"
    return True, "已检测到 Npcap"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSniffer")
        self.resize(1120, 720)
        self._capture_available, self._startup_notice = startup_status()
        self._session: CaptureSession | None = None
        self._last_settings: CaptureSettings | None = None
        self._restart_settings: CaptureSettings | None = None
        self._stopping = False
        self._capture_initialized = False
        self._close_pending = False
        self._model_drops = 0
        self._received = 0
        self._discarded = 0
        self._files = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer pcap")
        self._file_task: tuple[Path, Future] | None = None

        self.pages = QStackedWidget()
        notice = "" if self._capture_available else self._startup_notice
        self.welcome = WelcomePage(list_adapters(), notice)
        self.packet_model = PacketTableModel(self)
        self.packet_table = PacketTable(self.packet_model)
        self.packet_inspector = PacketInspector(self.packet_model, self.packet_table)
        self.display_filter = DisplayFilterBar()
        self._display_controller = DisplayFilterController(self.packet_model, self)
        self.display_filter.submitted.connect(self._display_controller.apply)
        self._display_controller.progress.connect(self.display_filter.show_progress)
        self._display_controller.failed.connect(self.display_filter.show_failure)
        self.packet_page = QWidget()
        packet_layout = QVBoxLayout(self.packet_page)
        packet_layout.setContentsMargins(0, 0, 0, 0)
        packet_layout.setSpacing(0)
        packet_layout.addWidget(self.display_filter)
        packet_layout.addWidget(self.packet_inspector, 1)
        self.packet_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_table.customContextMenuRequested.connect(self._packet_filter_menu)
        self.packet_inspector.details.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.packet_inspector.details.customContextMenuRequested.connect(self._field_filter_menu)
        self.pages.addWidget(self.welcome)
        self.pages.addWidget(self.packet_page)
        self.setCentralWidget(self.pages)
        self.welcome.capture_requested.connect(self.start_capture)
        self.welcome.selection_changed.connect(self._update_controls)

        self._setup_toolbar()
        files = self.menuBar().addMenu("文件(&F)")
        self._open_action = files.addAction("打开抓包文件…", self.open_capture)
        self._open_action.setShortcut(QKeySequence(QKeySequence.StandardKey.Open))
        self._save_action = files.addAction("另存为…", self.save_capture)
        self._save_action.setShortcut(QKeySequence(QKeySequence.StandardKey.SaveAs))
        self._setup_view_menu()
        self._counts = QLabel()
        self._counts.setToolTip("丢弃包括应用队列、会话容量和停止时 Npcap 报告的缓冲区丢包。")
        self.statusBar().addPermanentWidget(self._counts)
        self.statusBar().showMessage(self._startup_notice)
        self._update_counts(0, 0)
        self.packet_model.rowsInserted.connect(self._visible_rows_added)
        self.packet_model.modelReset.connect(self._refresh_counts)
        self._update_controls()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll_capture)
        self._timer.timeout.connect(self._poll_file)
        self._timer.start(100)

    def _setup_toolbar(self) -> None:
        toolbar = self.addToolBar("抓包")
        toolbar.setMovable(False)
        self._interfaces_action = toolbar.addAction("网卡", self._show_interfaces)
        self._start_action = toolbar.addAction("开始", self.start_capture)
        self._stop_action = toolbar.addAction("停止", self.stop_capture)
        self._restart_action = toolbar.addAction("重新开始", self.restart_capture)
        self._clear_action = toolbar.addAction("清空", self.clear_capture)
        toolbar.addSeparator()

        toolbar.addWidget(QLabel("抓包过滤"))
        self.capture_filter = CaptureFilterBox()
        self.capture_filter.lineEdit().returnPressed.connect(self.start_capture)
        toolbar.addWidget(self.capture_filter)
        toolbar.addWidget(self.capture_filter.feedback)

        self.promiscuous = QCheckBox("混杂模式")
        toolbar.addWidget(self.promiscuous)
        self.auto_scroll = QCheckBox("自动滚动")
        self.auto_scroll.setChecked(True)
        toolbar.addWidget(self.auto_scroll)

    def _setup_view_menu(self) -> None:
        view = self.menuBar().addMenu("视图(&V)")
        columns = view.addMenu("显示列")
        for index, title in enumerate(HEADERS):
            action = columns.addAction(title)
            action.setCheckable(True)
            action.setChecked(True)
            action.toggled.connect(lambda shown, column=index: self.packet_table.setColumnHidden(column, not shown))
        times = view.addMenu("时间格式")
        modes = QActionGroup(times)
        for mode in TimeMode:
            action = times.addAction(mode.value)
            action.setCheckable(True)
            modes.addAction(action)
            action.setChecked(mode == TimeMode.FIRST)
            action.triggered.connect(lambda _checked, choice=mode: self._set_time_mode(choice))
        view.addAction("着色规则…", self._edit_colors)

    def _set_time_mode(self, mode: TimeMode) -> None:
        if mode == TimeMode.ABSOLUTE:
            self.packet_table.setColumnWidth(1, 190)
        else:
            self.packet_table.setColumnWidth(1, 112)
        self.packet_model.set_time_mode(mode)

    def _edit_colors(self) -> None:
        dialog = PacketColorsDialog(self.packet_model.colors, self)
        if dialog.exec():
            self.packet_model.set_colors(dialog.colors())

    def _update_controls(self) -> None:
        file_busy = self._file_task is not None
        idle = self._session is None
        available = idle and not file_busy
        has_packets = bool(self.packet_model.records)
        adapter = self.welcome.selected_adapter
        self._open_action.setEnabled(available)
        self._save_action.setEnabled(available and has_packets)
        self._interfaces_action.setEnabled(available)
        self._start_action.setEnabled(
            available and self._capture_available and adapter is not None
        )
        self._stop_action.setEnabled(not idle and not self._stopping)
        self._restart_action.setEnabled(
            not file_busy and self._last_settings is not None and not self._stopping
            and (idle or self._capture_initialized)
        )
        self._clear_action.setEnabled(available and has_packets)
        device = adapter.device if adapter else None
        if self._session is not None:
            device = self._session.settings.device
        self.capture_filter.set_validation_device(device if self._capture_available else None)
        self.capture_filter.setEnabled(available and self._capture_available)
        self.promiscuous.setEnabled(available and self._capture_available)

    def _update_counts(self, received: int, discarded: int) -> None:
        self._received, self._discarded = received, discarded
        self._refresh_counts()

    def _refresh_counts(self) -> None:
        self._counts.setText(
            f"已捕获 {self._received:,}   已显示 {self.packet_model.rowCount():,}   丢弃 {self._discarded:,}"
        )

    def _visible_rows_added(self, *_args) -> None:
        if self._session is not None and self.auto_scroll.isChecked():
            self.packet_table.scrollToBottom()
        self._refresh_counts()

    def _field_filter_menu(self, position) -> None:
        view = self.packet_inspector.details
        item = view.itemAt(position)
        if item is None:
            return
        field = item.data(0, Qt.ItemDataRole.UserRole)
        if field is None:
            return
        ancestor = item.parent()
        while ancestor is not None:
            parent_field = ancestor.data(0, Qt.ItemDataRole.UserRole)
            if parent_field is not None and parent_field.name == "app.port_hint":
                return
            ancestor = ancestor.parent()
        view.setCurrentItem(item)
        self.display_filter.field_menu(field.name, field.value, view.viewport().mapToGlobal(position))

    def _packet_filter_menu(self, position) -> None:
        index = self.packet_table.indexAt(position)
        if not index.isValid():
            return
        self.packet_table.selectRow(index.row())
        row = self.packet_model.record_index(index.row())
        record = self.packet_model.records[row]
        summary = record.summary
        column = index.column()
        name, value = "frame.number", row + 1
        if column in (2, 3):
            is_source = column == 2
            direction = "src" if is_source else "dst"
            text = summary.source if is_source else summary.destination
            if text:
                try:
                    version = ip_address(text).version
                except ValueError:
                    name = f"eth.{direction}"
                else:
                    name = f"ip.{direction}" if version == 4 else f"ipv6.{direction}"
                    if summary.protocol == "ARP" and version == 4:
                        name = f"arp.{direction}.proto_ipv4"
                value = text
        elif column == 4:
            protocol = {"IPv4": "ip", "Ethernet": "eth"}.get(summary.protocol, summary.protocol.casefold())
            if known_field(protocol):
                name, value = protocol, None
        elif column == 5:
            name, value = "frame.len", record.wire_length
        self.display_filter.field_menu(name, value, self.packet_table.viewport().mapToGlobal(position))

    def _show_interfaces(self) -> None:
        self.pages.setCurrentWidget(self.welcome)
        self.statusBar().showMessage(self._startup_notice)

    def start_capture(self) -> None:
        adapter = self.welcome.selected_adapter
        if not self._start_action.isEnabled() or adapter is None:
            return
        self._start_capture(CaptureSettings(
            adapter.device, self.capture_filter.currentText().strip(), self.promiscuous.isChecked()
        ))

    def _start_capture(self, settings: CaptureSettings) -> None:
        self._session = CaptureSession(settings)
        self._stopping = False
        self._capture_initialized = False
        # 等实际句柄和 BPF 都准备好，再用新会话替换上一次记录。
        self.statusBar().showMessage("正在打开网卡…")
        self._session.start()
        self._update_controls()

    def stop_capture(self) -> None:
        if self._session is not None:
            self._stopping = True
            self._session.stop()
            self.statusBar().showMessage("正在停止抓包…")
            self._update_controls()

    def restart_capture(self) -> None:
        if not self._restart_action.isEnabled() or self._last_settings is None:
            return
        if self._session is None:
            self._start_capture(self._last_settings)
        else:
            self._restart_settings = self._last_settings
            self.stop_capture()

    def clear_capture(self) -> None:
        if self._clear_action.isEnabled():
            self.packet_model.replace([])
            self._model_drops = 0
            self._update_counts(0, 0)
            self._update_controls()

    def _poll_capture(self) -> None:
        session = self._session
        if session is None:
            return
        if not session.ready.is_set():
            if session.done.is_set() and not session.ready.is_set():
                self._finish_capture(session)
            return
        if not self._capture_initialized:
            self._capture_initialized = True
            self._last_settings = session.settings
            self.packet_model.replace([])
            self._model_drops = 0
            self.pages.setCurrentWidget(self.packet_page)
            if not self._stopping:
                self.statusBar().showMessage("正在抓包")
            self._update_controls()

        batch = session.drain()
        if batch:
            self._model_drops += self.packet_model.append(batch)
        received, discarded = session.counts()
        self._update_counts(received, discarded + self._model_drops)
        if session.done.is_set() and not batch:
            self._finish_capture(session)

    def _finish_capture(self, session: CaptureSession) -> None:
        self._session = None
        self._stopping = False
        restart = self._restart_settings
        self._restart_settings = None
        if self._close_pending:
            self.close()
            return
        if restart is not None:
            self._start_capture(restart)
            return
        message = session.error or "抓包已停止"
        self.statusBar().showMessage(message)
        self._update_controls()

    def open_capture(self) -> None:
        if not self._open_action.isEnabled():
            return
        filename, _ = QFileDialog.getOpenFileName(
            self, "打开抓包文件", "", "抓包文件 (*.pcap *.pcapng);;所有文件 (*)"
        )
        if filename:
            path = Path(filename)
            self.statusBar().showMessage("正在读取抓包文件…")
            self._file_task = path, self._files.submit(read_capture_preview, path)
            self._update_controls()

    def save_capture(self) -> None:
        if not self._save_action.isEnabled():
            return
        filename, selected = QFileDialog.getSaveFileName(
            self, "另存抓包文件", "", "PCAP (*.pcap);;PCAPNG (*.pcapng)"
        )
        if not filename:
            return
        path = Path(filename)
        if path.suffix.casefold() not in (".pcap", ".pcapng"):
            extension = ".pcapng" if selected.startswith("PCAPNG") else ".pcap"
            path = path.with_name(path.name + extension)
            if path.exists() and QMessageBox.question(
                self, "替换文件", f"替换现有文件 {path.name}？"
            ) != QMessageBox.StandardButton.Yes:
                return
        self.statusBar().showMessage("正在保存抓包文件…")
        self._file_task = path, self._files.submit(write_capture, path, self.packet_model.records)
        self._update_controls()

    def _poll_file(self) -> None:
        if self._file_task is None:
            return
        path, task = self._file_task
        if not task.done():
            return
        self._file_task = None
        try:
            preview = task.result()
        except Exception as error:
            self.statusBar().showMessage(f"文件操作失败。{error}")
        else:
            if preview is None:
                self.statusBar().showMessage(f"已保存 {path.name}")
            else:
                records = preview.records
                self.packet_model.replace(records)
                self._model_drops = 0
                self.pages.setCurrentWidget(self.packet_page)
                self.packet_table.scrollToTop()
                if self.packet_model.rowCount():
                    self.packet_table.selectRow(0)
                self._update_counts(len(records), 0)
                message = f"已打开 {path.name}"
                if preview.truncated:
                    message += f" · 达到会话上限，仅加载前 {len(records):,} 包"
                self.statusBar().showMessage(message)
        if self._close_pending:
            self.close()
        else:
            self._update_controls()

    def closeEvent(self, event) -> None:
        if self._session is not None:
            self._close_pending = True
            self.stop_capture()
            event.ignore()
        elif self._file_task is not None:
            self._close_pending = True
            event.ignore()
        else:
            self.capture_filter.close_validator()
            self._display_controller.close()
            self.packet_inspector.close_worker()
            self._files.shutdown(wait=False)
            super().closeEvent(event)


def create_main_window() -> QMainWindow:
    return MainWindow()
