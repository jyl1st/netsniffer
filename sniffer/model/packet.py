from dataclasses import dataclass, field, replace
from decimal import Decimal
from ipaddress import ip_address
from struct import unpack_from

from sniffer.analysis.process_map import ProcessMatch, ProcessOwner
from sniffer.analysis.streams import StreamIndex, TransportFlow
from sniffer.analysis.tcp import TcpApplication, TcpSegment
from sniffer.dissect.app_detect import identify_application
from sniffer.dissect.checksum import checksum_valid, transport_checksum
from sniffer.dissect.ethernet import VLAN_TYPES
from sniffer.dissect.field import ParseError, Span
from sniffer.dissect.ip import IPV6_EXTENSIONS, ipv6_extension_size
from sniffer.dissect.registry import IPContext
from sniffer.dissect.transport import TCP_FLAGS

# 文件中的链路类型编号与 Windows 网卡的 ifType 是两套不同的编号。
LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229
MAX_PACKETS = 100_000
MAX_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PacketSummary:
    source: str
    destination: str
    protocol: str
    info: str = ""
    error: bool = False
    flow: TransportFlow | None = None
    tcp: TcpSegment | None = None
    udp_payload: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class PacketRecord:
    timestamp: Decimal | None
    raw: bytes
    linktype: int
    wire_length: int
    summary: PacketSummary
    # 编号由帧入库时的抓包顺序决定，不属于帧本身。
    stream_id: int | None = field(default=None, compare=False)
    tcp_application: TcpApplication | None = field(default=None, compare=False)
    processes: tuple[ProcessMatch, ...] = field(default=(), compare=False)

    @property
    def process_owners(self) -> tuple[ProcessOwner, ...]:
        if not self.processes:
            return ()
        return tuple(dict.fromkeys(match.owner for match in self.processes))

    @property
    def protocol(self) -> str:
        return self.tcp_application.protocol if self.tcp_application else self.summary.protocol

    @property
    def info(self) -> str:
        return self.tcp_application.info if self.tcp_application else self.summary.info

    @classmethod
    def from_bytes(
        cls, timestamp: Decimal | None, raw: bytes, linktype: int, wire_length: int
    ) -> "PacketRecord":
        return cls(timestamp, raw, linktype, wire_length, summarize(raw, linktype))

    def with_stream(self, streams: StreamIndex) -> "PacketRecord":
        if self.summary.flow is None:
            return self
        return replace(self, stream_id=streams.number(self.summary.flow))


def summarize(raw: bytes, linktype: int) -> PacketSummary:
    if linktype == LINKTYPE_ETHERNET:
        if len(raw) < 14:
            return PacketSummary("", "", "Ethernet", "报头截断")
        source, destination = raw[6:12].hex(":"), raw[:6].hex(":")
        ether_type, = unpack_from("!H", raw, 12)
        offset = 14
        while ether_type in VLAN_TYPES and offset < 46 and len(raw) >= offset + 4:
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
        src, dst = raw[offset + 12:offset + 16], raw[offset + 16:offset + 20]
        source, destination = str(ip_address(src)), str(ip_address(dst))
        header_length = (raw[offset] & 0x0F) * 4
        total_length, = unpack_from("!H", raw, offset + 2)
        flags_and_offset, = unpack_from("!H", raw, offset + 6)
        if header_length < 20 or total_length < header_length or offset + header_length > len(raw):
            return PacketSummary(source, destination, "IPv4", "报头长度异常", error=True)
        bad_checksum = not checksum_valid(memoryview(raw)[offset:offset + header_length])
        if flags_and_offset & 0x1FFF:
            return PacketSummary(source, destination, "IPv4", "后续分片", bad_checksum)
        end = min(len(raw), offset + total_length)
        network = IPContext(4, src, dst, not (flags_and_offset & 0x2000) and offset + total_length <= len(raw))
        return _transport(raw, offset + header_length, end, raw[offset + 9], source, destination, network, bad_checksum)
    if version == 6 and len(raw) >= offset + 40:
        return _ipv6_summary(raw, offset)
    return PacketSummary("", "", "IP", "报头未知或截断")


def _ipv6_summary(raw: bytes, offset: int) -> PacketSummary:
    src, dst = raw[offset + 8:offset + 24], raw[offset + 24:offset + 40]
    source, destination = str(ip_address(src)), str(ip_address(dst))
    payload_length, = unpack_from("!H", raw, offset + 4)
    expected_end = offset + 40 + payload_length
    end = min(len(raw), expected_end)
    complete = expected_end <= len(raw)
    protocol, cursor = raw[offset + 6], offset + 40
    if protocol in IPV6_EXTENSIONS:
        section = Span(raw, offset, end)
        try:
            for _ in range(16):
                if protocol not in IPV6_EXTENSIONS:
                    break
                relative = cursor - offset
                size = ipv6_extension_size(section, relative, protocol)
                section.require(relative, size)
                if protocol == 44:
                    fragment, = unpack_from("!H", raw, cursor + 2)
                    if fragment >> 3:
                        return PacketSummary(source, destination, "IPv6", "后续分片")
                    complete &= not bool(fragment & 1)
                if protocol == 43 and raw[cursor + 3]:
                    complete = False
                protocol = raw[cursor]
                cursor += size
        except ParseError:
            return PacketSummary(source, destination, "IPv6", "扩展报头截断")
    return _transport(raw, cursor, end, protocol, source, destination, IPContext(6, src, dst, complete))


def _transport(
    raw: bytes, offset: int, end: int, protocol: int, source: str, destination: str,
    network: IPContext, bad_checksum: bool = False,
) -> PacketSummary:
    name = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}.get(protocol, f"IPv{network.version}")
    size = end - offset
    if protocol in (6, 17) and size >= 4:
        source_port, destination_port = unpack_from("!HH", raw, offset)
        info = f"{source_port} → {destination_port}"
        payload_start = end
        checksum_end = None
        reset = False
        keepalive = False
        has_base_header = False
        if protocol == 6 and size >= 14:
            value = raw[offset + 13]
            reset = bool(value & 4)
            flags = ", ".join(flag for bit, flag in enumerate(TCP_FLAGS) if value & (1 << bit))
            if flags:
                info += f" [{flags}]"
            header_size = (raw[offset + 12] >> 4) * 4
            has_base_header = size >= 20 and header_size >= 20
            if 20 <= header_size <= size:
                payload_start, checksum_end = offset + header_size, end
                keepalive = (value == 0x10 and not raw[offset + 12] & 15
                             and network.complete and end - payload_start == 1)
        if protocol == 17 and size >= 8:
            udp_length, udp_checksum = unpack_from("!HH", raw, offset + 4)
            if udp_length >= 8:
                has_base_header = True
                payload_start = offset + 8
                end = min(end, offset + udp_length)
                if udp_length <= size and (udp_checksum or network.version == 6):
                    checksum_end = end
        transport_info = info
        application = identify_application(raw, payload_start, end, protocol, source_port, destination_port)
        if application:
            if application.protocol:
                name = application.protocol
                info = f"{application.info} · {name}（{application.basis}） · {info}"
            else:
                info += f" · {application.info}"
        if keepalive:
            info = f"TCP Keep-Alive? · {info}"
            transport_info = f"TCP Keep-Alive? · {transport_info}"
        if checksum_end is not None and network.complete:
            bad_checksum |= transport_checksum(Span(raw, offset, checksum_end), network, protocol) is False
        if bad_checksum:
            info += " · 校验和异常"
            transport_info += " · 校验和异常"
        flow = None
        if has_base_header:
            flow = TransportFlow(
                "tcp" if protocol == 6 else "udp",
                (network.source, source_port), (network.destination, destination_port),
            )
        tcp = None
        if protocol == 6 and checksum_end is not None:
            sequence, = unpack_from("!I", raw, offset + 4)
            tcp = TcpSegment(sequence, value, payload_start, end, transport_info)
        udp_payload = (payload_start, end) if protocol == 17 and has_base_header else None
        return PacketSummary(source, destination, name, info, reset or bad_checksum, flow, tcp, udp_payload)
    if protocol in (1, 58) and size >= 2:
        if size >= 4 and network.complete:
            if protocol == 1:
                bad_checksum |= not checksum_valid(memoryview(raw)[offset:end])
            else:
                bad_checksum |= transport_checksum(Span(raw, offset, end), network, 58) is False
        info = f"Type {raw[offset]}, Code {raw[offset + 1]}"
        if bad_checksum:
            info += " · 校验和异常"
        return PacketSummary(source, destination, name, info, bad_checksum)
    return PacketSummary(source, destination, name, "校验和异常" if bad_checksum else "", bad_checksum)
