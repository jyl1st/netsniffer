# -*- mode: python ; coding: utf-8 -*-
import os
import sys
from pathlib import Path


project = Path(SPECPATH).parent

# 构建时只从 Windows 和当前 Python 环境寻找 DLL，避免把其他工具的同名 DLL 打进包。
windows = Path(os.environ["SystemRoot"])
environment = Path(sys.prefix)
original_path = os.environ.get("PATH", "")
os.environ["PATH"] = os.pathsep.join(map(str, (
    windows / "System32", windows, environment, environment / "DLLs",
    environment / "Library" / "bin", environment / "Scripts",
)))
try:
    # scapy.layers.all 的内置 hook 收集动态协议层。显式保留 Windows 抓包入口。
    analysis = Analysis(
        [str(project / "main.py")],
        pathex=[str(project)],
        datas=[
            (str(project / "sniffer/gui/theme.qss"), "sniffer/gui"),
            (str(project / "sniffer/gui/icons"), "sniffer/gui/icons"),
            (str(project / "packaging/netsniffer.ico"), "packaging"),
        ],
        hiddenimports=["scapy.arch.libpcap", "scapy.arch.windows", "scapy.libs.winpcapy"],
        excludes=[
            "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
            "PySide6.Qt3DCore", "PySide6.Qt3DRender", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
            "PySide6.Qt3DExtras", "PySide6.Qt3DAnimation",
            "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuickWidgets", "PySide6.QtQuickControls2",
            "pytest", "_pytest", "tkinter",
        ],
    )
finally:
    os.environ["PATH"] = original_path

# Scapy 运行时从系统安装目录载入 Npcap，构建机的 DLL、驱动和工具不得随包分发。
npcap_names = {"wpcap.dll", "packet.dll", "npcap.dll", "npcap.sys", "npf.sys", "npcaphelper.exe", "wlanhelper.exe"}
# Qt 使用 Windows 自带的 ICU 入口，其他工具的同名 DLL 可能只导出带版本后缀的符号。
windows_icu_names = {"icu.dll", "icuin.dll", "icuuc.dll"}


def include_entry(entry):
    for path in entry[:2]:
        name = Path(path).name.casefold()
        if name in npcap_names or name in windows_icu_names:
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
