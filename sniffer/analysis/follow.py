from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from heapq import heappop, heappush, merge
from ipaddress import ip_address
from itertools import chain

from sniffer.analysis.streams import Endpoint, TransportProtocol
from sniffer.model.packet import PacketRecord

_SYN = 0x02
_ACK = 0x10
_HALF_SEQUENCE_SPACE = 1 << 31
_SEQUENCE_MASK = (1 << 32) - 1
_EMPTY = memoryview(b"")


@dataclass(frozen=True, slots=True)
class StreamChunk:
    direction: int
    offset: int
    data: memoryview
    missing: int = 0


@dataclass(frozen=True, slots=True)
class FollowStream:
    endpoints: tuple[Endpoint, Endpoint]
    chunks: tuple[StreamChunk, ...]


@dataclass(frozen=True, slots=True)
class _Segment:
    start: int
    frame: int
    data: memoryview

    @property
    def end(self) -> int:
        return self.start + len(self.data)


@dataclass(slots=True)
class _TcpDirection:
    segments: list[_Segment] = field(default_factory=list)
    reference: int | None = None
    origin: int | None = None

    def add(self, frame: int, sequence: int, syn: bool, data: memoryview) -> None:
        # 用同方向已观察到的序号展开回绕。SYN 消耗一个序号。
        start = sequence + syn
        reference = self.reference
        if reference is not None:
            start = reference + ((start - reference + _HALF_SEQUENCE_SPACE) & _SEQUENCE_MASK) - _HALF_SEQUENCE_SPACE
        self.reference = start + len(data) if reference is None else max(reference, start + len(data))
        if syn and self.origin is None:
            self.origin = start
        if data:
            self.segments.append(_Segment(start, frame, data))


def endpoint_label(endpoint: Endpoint) -> str:
    address, port = ip_address(endpoint[0]), endpoint[1]
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def assemble_stream(records: Sequence[PacketRecord], protocol: TransportProtocol, number: int) -> FollowStream:
    selected = (
        (index, record) for index, record in enumerate(records)
        if record.stream_id == number and record.summary.flow is not None and record.summary.flow.protocol == protocol
    )
    first = next(selected, None)
    if first is None:
        raise ValueError("当前抓包中没有该流。")
    first_record = first[1]
    flow = first_record.summary.flow
    assert flow is not None
    endpoints = flow.source, flow.destination
    segment = first_record.summary.tcp
    if segment is not None and segment.flags & (_SYN | _ACK) == (_SYN | _ACK):
        endpoints = flow.destination, flow.source
    frames = chain((first,), selected)
    chunks = _tcp_chunks(frames, endpoints[0]) if protocol == "tcp" else _udp_chunks(frames, endpoints[0])
    return FollowStream(endpoints, tuple(chunks))


def _udp_chunks(frames: Iterator[tuple[int, PacketRecord]], first: Endpoint) -> Iterator[StreamChunk]:
    offsets = [0, 0]
    for _, record in frames:
        bounds = record.summary.udp_payload
        flow = record.summary.flow
        if bounds is None or flow is None or bounds[0] == bounds[1]:
            continue
        direction = int(flow.source != first)
        data = memoryview(record.raw)[bounds[0]:bounds[1]]
        yield StreamChunk(direction, offsets[direction], data)
        offsets[direction] += len(data)


def _tcp_chunks(frames: Iterator[tuple[int, PacketRecord]], first: Endpoint) -> Iterator[StreamChunk]:
    directions = (_TcpDirection(), _TcpDirection())
    initial_syn = None
    for frame, record in frames:
        segment, flow = record.summary.tcp, record.summary.flow
        if segment is None or flow is None:
            continue
        direction = int(flow.source != first)
        syn = bool(segment.flags & _SYN)
        if syn and not segment.flags & _ACK:
            key = direction, segment.sequence
            if key != initial_syn and any(side.segments for side in directions):
                # 同一流号可能包含四元组复用的连接，新的初始 SYN 单独展开序号。
                yield from _merge_directions(directions)
                directions = (_TcpDirection(), _TcpDirection())
            initial_syn = key
        data = memoryview(record.raw)[segment.start:segment.end]
        directions[direction].add(frame, segment.sequence, syn, data)
    yield from _merge_directions(directions)


def _merge_directions(directions: tuple[_TcpDirection, _TcpDirection]) -> Iterator[StreamChunk]:
    ordered = merge(
        _ordered_chunks(0, directions[0]), _ordered_chunks(1, directions[1]), key=lambda item: item[0],
    )
    for _, chunk in ordered:
        yield chunk


def _ordered_chunks(direction: int, state: _TcpDirection) -> Iterator[tuple[int, StreamChunk]]:
    segments = iter(sorted(state.segments, key=lambda item: item.start))
    upcoming = next(segments, None)
    if upcoming is None:
        return
    origin = upcoming.start if state.origin is None else state.origin
    cursor = origin
    active: list[tuple[int, _Segment]] = []
    frame = 0
    while upcoming is not None or active:
        while upcoming is not None and upcoming.start <= cursor:
            heappush(active, (upcoming.frame, upcoming))
            upcoming = next(segments, None)
        while active and active[0][1].end <= cursor:
            heappop(active)
        if not active:
            if upcoming is None:
                break
            frame = max(frame, upcoming.frame)
            yield frame, StreamChunk(direction, cursor - origin, _EMPTY, upcoming.start - cursor)
            cursor = upcoming.start
            continue

        # 同一序号有多份数据时，堆顶是最先被捕获的那一份。
        _, winner = active[0]
        stop = winner.end if upcoming is None else min(winner.end, upcoming.start)
        frame = max(frame, winner.frame)
        data = winner.data[cursor - winner.start:stop - winner.start]
        yield frame, StreamChunk(direction, cursor - origin, data)
        cursor = stop
