from PySide6.QtCore import QSize, Qt
from PySide6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QVBoxLayout

from sniffer.gui.theme import APP_VERSION


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("关于 NetSniffer")
        self.setMinimumWidth(455)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        icon = QLabel()
        icon.setPixmap(self.windowIcon().pixmap(QSize(48, 48), self.devicePixelRatioF()))
        header.addWidget(icon)
        title = QLabel("NetSniffer")
        font = title.font()
        font.setPointSize(20)
        font.setBold(True)
        title.setFont(font)
        header.addWidget(title)
        version = QLabel(APP_VERSION)
        version.setObjectName("versionBadge")
        header.addWidget(version, 0, Qt.AlignmentFlag.AlignVCenter)
        header.addStretch()
        layout.addLayout(header)

        description = QLabel("在 Windows 上抓包，分析协议、TCP 时序、流量和安全告警。")
        description.setWordWrap(True)
        layout.addWidget(description)

        details = QFormLayout()
        for label, url, text in (
            ("源代码", "https://github.com/jyl1st/netsniffer", "GitHub · jyl1st/netsniffer"),
            ("抓包驱动", "https://npcap.com", "Npcap 下载"),
        ):
            link = QLabel(f'<a href="{url}">{text}</a>')
            link.setOpenExternalLinks(True)
            details.addRow(label, link)
        details.addRow("许可证", QLabel("MIT"))
        details.addRow("技术栈", QLabel("Python · PySide6 · Npcap · Scapy · pyqtgraph"))
        layout.addLayout(details)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
