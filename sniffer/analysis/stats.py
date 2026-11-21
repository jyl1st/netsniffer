"""对抓包快照中已有的帧摘要做统计。"""

from dataclasses import dataclass
from decimal import Decimal

from sniffer.model.packet import LINKTYPE_ETHERNET, LINKTYPE_LOOP, LINKTYPE_NULL, PacketRecord


@dataclass(frozen=True, slots=True)
class StatsSnapshot:
    frames: tuple[tuple[int, PacketRecord], ...]
    origin: Decimal | None

    @classmethod
    def from_records(cls, records: list[PacketRecord]) -> "StatsSnapshot":
        origin = next((frame.timestamp for frame in records if frame.timestamp is not None), None)
        return cls(tuple(enumerate(records, 1)), origin)


@dataclass(slots=True)
class Counts:
    frames: int = 0
    bytes: int = 0

    def add(self, length: int) -> None:
        self.frames += 1
        self.bytes += length


def _ip_layer(packet: PacketRecord) -> str | None:
    summary = packet.summary
    if summary.protocol in ("ARP", "Ethernet", "Unknown"):
        return None
    if ":" in summary.source:
        return "IPv6"
    if "." in summary.source:
        return "IPv4"
    return None


def _protocol_path(packet: PacketRecord) -> tuple[str, ...]:
    summary = packet.summary
    path = ("Frame",)
    if packet.linktype == LINKTYPE_ETHERNET:
        path += ("Ethernet",)
    elif packet.linktype in (LINKTYPE_NULL, LINKTYPE_LOOP):
        path += ("Loopback",)
    if summary.protocol == "ARP":
        return path + ("ARP",)
    ip = _ip_layer(packet)
    if ip is None:
        return path
    path += (ip,)
    if summary.flow is not None:
        transport = summary.flow.protocol.upper()
        path += (transport,)
        if summary.protocol != transport:
            path += (summary.protocol,)
    elif summary.protocol in ("TCP", "UDP", "ICMP", "ICMPv6"):
        path += (summary.protocol,)
    return path


def protocol_hierarchy(snapshot: StatsSnapshot) -> dict[tuple[str, ...], Counts]:
    """每帧给路径上的各层累计一次，字节使用帧在线路上的原始长度。"""
    nodes = {("Frame",): Counts()}
    for _, packet in snapshot.frames:
        path = _protocol_path(packet)
        for depth in range(1, len(path) + 1):
            prefix = path[:depth]
            if prefix not in nodes:
                nodes[prefix] = Counts()
            nodes[prefix].add(packet.wire_length)
    return nodes
