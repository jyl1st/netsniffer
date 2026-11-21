"""对抓包快照中已有的帧摘要做统计。"""

from dataclasses import dataclass, field
from decimal import Decimal, ROUND_FLOOR

from sniffer.model.packet import LINKTYPE_ETHERNET, LINKTYPE_LOOP, LINKTYPE_NULL, PacketRecord

ADDRESS_GROUPS = ("IPv4", "IPv6", "TCP", "UDP")
IO_INTERVALS = (Decimal("0.1"), Decimal(1), Decimal(10))
Address = tuple[str, int | None]


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


def _address_pairs(packet: PacketRecord):
    summary = packet.summary
    ip = _ip_layer(packet)
    if ip is not None:
        yield ip, (summary.source, None), (summary.destination, None), None
    if summary.flow is not None:
        yield (summary.flow.protocol.upper(), (summary.source, summary.flow.source[1]),
               (summary.destination, summary.flow.destination[1]), packet.stream_id)


@dataclass(slots=True)
class Conversation:
    a: Address
    b: Address
    stream: int | None
    origin: Decimal | None
    forward: Counts = field(default_factory=Counts)
    reverse: Counts = field(default_factory=Counts)
    first: Decimal | None = None
    last: Decimal | None = None

    @property
    def frames(self) -> int:
        return self.forward.frames + self.reverse.frames

    @property
    def bytes(self) -> int:
        return self.forward.bytes + self.reverse.bytes

    @property
    def start(self) -> Decimal | None:
        if self.first is not None and self.origin is not None:
            return self.first - self.origin
        return None

    @property
    def duration(self) -> Decimal | None:
        if self.first is not None and self.last is not None:
            return self.last - self.first
        return None

    def add(self, source: Address, packet: PacketRecord) -> None:
        counts = self.forward if source == self.a else self.reverse
        counts.add(packet.wire_length)
        timestamp = packet.timestamp
        if timestamp is not None:
            if self.first is None or timestamp < self.first:
                self.first = timestamp
            if self.last is None or timestamp > self.last:
                self.last = timestamp


def conversations(snapshot: StatsSnapshot) -> dict[str, list[Conversation]]:
    """回包归入同一会话。显示方向以快照里首次观察到的源端为 A。"""
    groups: dict[str, dict[int | frozenset[Address], Conversation]] = {name: {} for name in ADDRESS_GROUPS}
    for _, packet in snapshot.frames:
        for group, source, destination, stream in _address_pairs(packet):
            # TCP/UDP 复用入库分配的流号。缺少流号时仍能按双向端点统计。
            key = stream if stream is not None else frozenset((source, destination))
            entries = groups[group]
            if key not in entries:
                entries[key] = Conversation(source, destination, stream, snapshot.origin)
            entries[key].add(source, packet)
    return {name: list(entries.values()) for name, entries in groups.items()}


@dataclass(slots=True)
class EndpointStats:
    address: Address
    sent: Counts = field(default_factory=Counts)
    received: Counts = field(default_factory=Counts)

    @property
    def frames(self) -> int:
        return self.sent.frames + self.received.frames

    @property
    def bytes(self) -> int:
        return self.sent.bytes + self.received.bytes


def endpoints(snapshot: StatsSnapshot) -> dict[str, list[EndpointStats]]:
    """每帧给源端累加发送量、给目的端累加接收量。"""
    groups: dict[str, dict[Address, EndpointStats]] = {name: {} for name in ADDRESS_GROUPS}
    for _, packet in snapshot.frames:
        for group, source, destination, _ in _address_pairs(packet):
            entries = groups[group]
            if source not in entries:
                entries[source] = EndpointStats(source)
            if destination not in entries:
                entries[destination] = EndpointStats(destination)
            entries[source].sent.add(packet.wire_length)
            entries[destination].received.add(packet.wire_length)
    return {name: list(entries.values()) for name, entries in groups.items()}


@dataclass(slots=True)
class IOBucket:
    index: int
    first_frame: int
    counts: Counts = field(default_factory=Counts)


def io_buckets(snapshot: StatsSnapshot, interval: Decimal = Decimal(1)) -> list[IOBucket]:
    """按左闭右开的时间区间分桶。快照没有流量的桶隐含为零。"""
    if interval <= 0:
        raise ValueError("分桶间隔必须大于零。")
    if snapshot.origin is None:
        return []
    buckets: dict[int, IOBucket] = {}
    for frame, packet in snapshot.frames:
        if packet.timestamp is None:
            continue
        offset = packet.timestamp - snapshot.origin
        index = int((offset / interval).to_integral_value(rounding=ROUND_FLOOR))
        if index not in buckets:
            buckets[index] = IOBucket(index, frame)
        buckets[index].counts.add(packet.wire_length)
    return [buckets[index] for index in sorted(buckets)]
