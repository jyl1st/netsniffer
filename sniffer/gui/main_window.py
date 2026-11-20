import ctypes
import sys

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QCheckBox, QComboBox, QLabel, QMainWindow, QStackedWidget
from scapy.all import conf

from sniffer.capture.engine import FILTER_PRESETS, CaptureSession, CaptureSettings
from sniffer.capture.interfaces import list_adapters
from sniffer.gui.packet_table import PacketTable, PacketTableModel
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

        self.pages = QStackedWidget()
        notice = "" if self._capture_available else self._startup_notice
        self.welcome = WelcomePage(list_adapters(), notice)
        self.packet_model = PacketTableModel(self)
        self.packet_table = PacketTable(self.packet_model)
        self.pages.addWidget(self.welcome)
        self.pages.addWidget(self.packet_table)
        self.setCentralWidget(self.pages)
        self.welcome.capture_requested.connect(self.start_capture)
        self.welcome.selection_changed.connect(self._update_controls)

        self._setup_toolbar()
        self._counts = QLabel()
        self._counts.setToolTip("丢弃包括应用队列、会话容量和停止时 Npcap 报告的缓冲区丢包。")
        self.statusBar().addPermanentWidget(self._counts)
        self.statusBar().showMessage(self._startup_notice)
        self._update_counts(0, 0)
        self._update_controls()

        self._timer = QTimer(self)
        self._timer.timeout.connect(self._poll_capture)
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
        self.capture_filter = QComboBox()
        self.capture_filter.setEditable(True)
        self.capture_filter.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.capture_filter.addItem("")
        self.capture_filter.addItems(FILTER_PRESETS)
        self.capture_filter.setMinimumWidth(170)
        self.capture_filter.lineEdit().setPlaceholderText("BPF 表达式")
        self.capture_filter.lineEdit().returnPressed.connect(self.start_capture)
        toolbar.addWidget(self.capture_filter)

        self.promiscuous = QCheckBox("混杂模式")
        toolbar.addWidget(self.promiscuous)
        self.auto_scroll = QCheckBox("自动滚动")
        self.auto_scroll.setChecked(True)
        toolbar.addWidget(self.auto_scroll)

    def _update_controls(self) -> None:
        idle = self._session is None
        self._interfaces_action.setEnabled(idle)
        self._start_action.setEnabled(idle and self._capture_available and self.welcome.selected_adapter is not None)
        self._stop_action.setEnabled(not idle and not self._stopping)
        self._restart_action.setEnabled(self._last_settings is not None and not self._stopping)
        self._clear_action.setEnabled(idle and self.packet_model.rowCount() > 0)
        self.capture_filter.setEnabled(idle and self._capture_available)
        self.promiscuous.setEnabled(idle and self._capture_available)

    def _update_counts(self, received: int, discarded: int) -> None:
        self._counts.setText(
            f"已捕获 {received:,}   已显示 {self.packet_model.rowCount():,}   丢弃 {discarded:,}"
        )

    def _show_interfaces(self) -> None:
        self.pages.setCurrentWidget(self.welcome)
        self.statusBar().showMessage(self._startup_notice)

    def start_capture(self) -> None:
        adapter = self.welcome.selected_adapter
        if self._session is not None or not self._capture_available or adapter is None:
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
        if self._last_settings is None or self._stopping:
            return
        if self._session is None:
            self._start_capture(self._last_settings)
        else:
            self._restart_settings = self._last_settings
            self.stop_capture()

    def clear_capture(self) -> None:
        if self._session is None:
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
            self.pages.setCurrentWidget(self.packet_table)
            if not self._stopping:
                self.statusBar().showMessage("正在抓包")
            self._update_controls()

        batch = session.drain()
        if batch:
            self._model_drops += self.packet_model.append(batch)
            if self.auto_scroll.isChecked():
                self.packet_table.scrollToBottom()
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

    def closeEvent(self, event) -> None:
        if self._session is not None:
            self._close_pending = True
            self.stop_capture()
            event.ignore()
        else:
            super().closeEvent(event)


def create_main_window() -> QMainWindow:
    return MainWindow()
