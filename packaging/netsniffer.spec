# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path


project = Path(SPECPATH).parent

# scapy.layers.all 的内置 hook 收集 Scapy 动态载入的协议层。显式保留 Windows 抓包入口。
analysis = Analysis(
    [str(project / "main.py")],
    pathex=[str(project)],
    hiddenimports=["scapy.arch.libpcap", "scapy.arch.windows", "scapy.libs.winpcapy"],
    excludes=[
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
        "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
        "PySide6.Qt3DExtras", "PySide6.Qt3DAnimation",
        "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtQuickControls2",
        "pytest", "_pytest", "tkinter",
    ],
)

# Scapy 运行时从系统安装目录载入 Npcap，构建机的 DLL、驱动和工具不得随包分发。
npcap_names = {"wpcap.dll", "packet.dll", "npcap.dll", "npcap.sys", "npf.sys", "npcaphelper.exe", "wlanhelper.exe"}


def include_entry(entry):
    for path in entry[:2]:
        name = Path(path).name.casefold()
        if name in npcap_names:
            return False
        # QtGui hook 会收集虚拟键盘插件，它会额外链接 QtQuick 和 QtQml。
        if name == "qtvirtualkeyboardplugin.dll" or name.startswith(("qt6virtualkeyboard", "qt6quick", "qt6qml")):
            return False
    return True


analysis.binaries = [entry for entry in analysis.binaries if include_entry(entry)]
analysis.datas = [entry for entry in analysis.datas if include_entry(entry)]

# QtWidgets hook 自动收集平台插件。缺少 Windows 插件时让构建直接失败。
if not any(Path(name).name.casefold() == "qwindows.dll" for name, _, _ in analysis.binaries):
    raise RuntimeError("PySide6 的 Windows 平台插件 qwindows.dll 未收集。")

pyz = PYZ(analysis.pure)
exe = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="NetSniffer",
    icon=str(project / "packaging" / "netsniffer.ico"),
    console=False,
    uac_admin=True,
    upx=False,
)
