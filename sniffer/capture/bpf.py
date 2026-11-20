from ctypes import byref

from scapy.all import conf
from scapy.utils import decode_locale_str

FILTER_PRESETS = ("tcp port 443", "tcp", "udp", "port 53", "ip", "ip6", "icmp or icmp6", "arp")


class CaptureFilterError(ValueError):
    """表达式无法为所选网卡编译。"""


def check_capture_filter(device: str, expression: str) -> None:
    if not conf.use_pcap:
        raise OSError("Npcap 不可用。")
    with conf.L2listen(iface=device, promisc=False) as listener:
        _compile_capture_filter(listener.pcap_fd.pcap, expression, install=False)


def install_capture_filter(handle, expression: str) -> None:
    _compile_capture_filter(handle, expression, install=True)


def _compile_capture_filter(handle, expression: str, *, install: bool) -> None:
    expression = expression.strip()
    if not expression:
        return
    if "\x00" in expression:
        raise CaptureFilterError("BPF 表达式含有空字符。")

    from scapy.libs.winpcapy import (
        bpf_program, pcap_compile, pcap_freecode, pcap_geterr, pcap_setfilter,
    )

    # 与实际抓包使用同一链路类型。编译与安装结束后释放 libpcap 分配的字节码。
    program = bpf_program()
    program_ptr = byref(program)
    if pcap_compile(handle, program_ptr, expression.encode(), 1, 0xFFFFFFFF) != 0:
        raise CaptureFilterError(f"BPF 编译失败。{decode_locale_str(pcap_geterr(handle) or b'')}")
    try:
        if install and pcap_setfilter(handle, program_ptr) != 0:
            raise OSError(f"BPF 安装失败。{decode_locale_str(pcap_geterr(handle) or b'')}")
    finally:
        pcap_freecode(program_ptr)
