import sys

from PySide6.QtWidgets import QMainWindow
from scapy.all import conf


def create_main_window() -> QMainWindow:
    window = QMainWindow()
    window.setWindowTitle("NetSniffer")
    window.resize(960, 640)

    if sys.platform != "win32":
        status = "Npcap 仅适用于 Windows"
    elif conf.use_pcap and conf.use_npcap:
        status = "已检测到 Npcap"
    else:
        status = "未检测到 Npcap"
    window.statusBar().showMessage(status)
    return window
