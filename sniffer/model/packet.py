from dataclasses import dataclass
from decimal import Decimal
from ipaddress import ip_address
from struct import unpack_from

# 文件中的链路类型编号与 Windows 网卡的 ifType 是两套不同的编号。
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
TCP_FLAGS = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
MAX_PACKETS = 100_000
MAX_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PacketSummary:
    source: str
    destination: str
    protocol: str
    info: str = ""


@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: Decimal | None
    raw: bytes
    linktype: int
    wire_length: int
    summary: PacketSummary

    @classmethod
    def from_bytes(
        cls, timestamp: Decimal | None, raw: bytes, linktype: int, wire_length: int
    ) -> "PacketRecord":
        return cls(timestamp, raw, linktype, wire_length, summarize(raw, linktype))


def summarize(raw: bytes, linktype: int) -> PacketSummary:
    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return PacketSummary("", "", "Ethernet", "报头截断")
        source, destination = raw[6:12].hex(":"), raw[:6].hex(":")
        ether_type, = unpack_from("!H", raw, 12)
        offset = 14
        while ether_type in (0x8100, 0x88A8) and len(raw) >= offset + 4:
            ether_type, = unpack_from("!H", raw, offset + 2)
            offset += 4
        if ether_type in (0x0800, 0x86DD):
            return _ip_summary(raw, offset)
        if ether_type == 0x0806:
            if raw[offset:offset + 6] == b"\x00\x01\x08\x00\x06\x04" and len(raw) >= offset + 28:
                source = str(ip_address(raw[offset + 14:offset + 18]))
                destination = str(ip_address(raw[offset + 24:offset + 28]))
                operation, = unpack_from("!H", raw, offset + 6)
                info = {1: "请求", 2: "应答"}.get(operation, f"操作 {operation}")
                return PacketSummary(source, destination, "ARP", info)
            return PacketSummary(source, destination, "ARP")
        return PacketSummary(source, destination, "Ethernet", f"EtherType 0x{ether_type:04x}")
    if linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        return _ip_summary(raw, 4)
    if linktype in (LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6):
        return _ip_summary(raw, 0)
    return PacketSummary("", "", "Unknown", f"链路类型 {linktype}")


def _ip_summary(raw: bytes, offset: int) -> PacketSummary:
    if offset >= len(raw):
        return PacketSummary("", "", "IP", "报头截断")
    version = raw[offset] >> 4
    if version == 4 and len(raw) >= offset + 20:
        source = str(ip_address(raw[offset + 12:offset + 16]))
        destination = str(ip_address(raw[offset + 16:offset + 20]))
        header_length = (raw[offset] & 0x0F) * 4
        total_length, = unpack_from("!H", raw, offset + 2)
        flags_and_offset, = unpack_from("!H", raw, offset + 6)
        if header_length < 20 or total_length < header_length or offset + header_length > len(raw):
            return PacketSummary(source, destination, "IPv4", "报头长度异常")
        if flags_and_offset & 0x1FFF:
            return PacketSummary(source, destination, "IPv4", "后续分片")
        end = min(len(raw), offset + total_length)
        return _transport(raw, offset + header_length, end, raw[offset + 9], source, destination, "IPv4")
    if version == 6 and len(raw) >= offset + 40:
        source = str(ip_address(raw[offset + 8:offset + 24]))
        destination = str(ip_address(raw[offset + 24:offset + 40]))
        payload_length, = unpack_from("!H", raw, offset + 4)
        end = min(len(raw), offset + 40 + payload_length)
        return _transport(raw, offset + 40, end, raw[offset + 6], source, destination, "IPv6")
    return PacketSummary("", "", "IP", "报头未知或截断")


def _transport(
    raw: bytes, offset: int, end: int, protocol: int, source: str, destination: str, network: str
) -> PacketSummary:
    name = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(protocol, network)
    size = end - offset
    if protocol in (6, 17) and size >= 4:
        source_port, destination_port = unpack_from("!HH", raw, offset)
        info = f"{source_port} → {destination_port}"
        if protocol == 6 and size >= 14:
            value = raw[offset + 13]
            flags = ", ".join(flag for bit, flag in enumerate(TCP_FLAGS) if value & (1 << bit))
            if flags:
                info += f" [{flags}]"
        return PacketSummary(source, destination, name, info)
    if protocol in (1, 58) and size >= 2:
        return PacketSummary(source, destination, name, f"Type {raw[offset]}, Code {raw[offset + 1]}")
    return PacketSummary(source, destination, name)
