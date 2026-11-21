from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum

from sniffer.analysis.process_map import ProcessOwner
from sniffer.analysis.streams import Endpoint
from sniffer.analysis.tcp import ACK, HALF_SEQUENCE_SPACE, RST, SEQUENCE_MASK, SYN, TcpSegment
from sniffer.dissect.transport import TCP_FLAGS
from sniffer.model.packet import PacketRecord

MAX_GRAPH_PACKETS = 5_000
FIN = 0x01
_FLAG_ORDER = (1, 0, 2, 3, 4, 5, 6, 7)


class FlowPhaseKind(Enum):
    HANDSHAKE = "三次握手"
    CLOSE_FOUR = "四次挥手"
    CLOSE_THREE = "三次挥手"
    RESET = "RST 中断"


@dataclass(frozen=True, slots=True)
class FlowPhase:
    kind: FlowPhaseKind
    first: int  # 事件下标，包含边界
    last: int


@dataclass(frozen=True, slots=True)
class FlowEvent:
    frame: int
    time: Decimal | None
    direction: int  # 0 为 A→B，1 为 B→A
    flags: int
    flag_text: str
    seq: int
    ack: int | None
    length: int
    window: int


@dataclass(frozen=True, slots=True)
class FlowGraph:
    endpoints: tuple[Endpoint, Endpoint] | None
    owners: tuple[tuple[ProcessOwner, ...], tuple[ProcessOwner, ...]]
    events: tuple[FlowEvent, ...]
    phases: tuple[FlowPhase, ...]
    has_syn: bool
    total: int


def build_flow_graph(records: Sequence[PacketRecord], stream_number: int) -> FlowGraph:
    """从抓包快照读取指定 TCP 流，保留原始帧编号与捕获顺序。"""
    frames: list[tuple[int, Decimal | None, Endpoint, TcpSegment]] = []
    first_sequence: dict[Endpoint, int] = {}
    syn_sequence: dict[Endpoint, int] = {}
    owners: dict[Endpoint, set[ProcessOwner]] = {}
    endpoints = None
    initial_sender = None
    origin = None
    total = 0
    for frame, record in enumerate(records, 1):
        flow, tcp = record.summary.flow, record.summary.tcp
        if record.stream_id != stream_number or flow is None or flow.protocol != "tcp" or tcp is None:
            continue
        total += 1
        if endpoints is None:
            endpoints = flow.source, flow.destination
        if origin is None:
            origin = record.timestamp
        first_sequence.setdefault(flow.source, tcp.sequence)
        if tcp.flags & SYN:
            syn_sequence.setdefault(flow.source, tcp.sequence)
            if not tcp.flags & ACK and initial_sender is None:
                initial_sender = flow.source
        for match in record.processes:
            owners.setdefault(match.local, set()).add(match.owner)
        if len(frames) < MAX_GRAPH_PACKETS:
            frames.append((frame, record.timestamp, flow.source, tcp))

    if endpoints is None:
        return FlowGraph(None, ((), ()), (), (), False, 0)
    if initial_sender == endpoints[1]:
        endpoints = endpoints[1], endpoints[0]
    a, b = endpoints
    # 两端分别维护 ISN。SYN/ACK 中的 SYN 也会提供该方向的 ISN。
    bases = first_sequence | syn_sequence
    endpoint_owners = tuple(
        tuple(sorted(owners.get(endpoint, ()), key=lambda owner: (owner.pid, owner.name or "")))
        for endpoint in endpoints
    )
    events = []
    segments = []
    for frame, timestamp, source, tcp in frames:
        direction = int(source != a)
        peer_base = bases.get(a if direction else b)
        # TCP 序号按 2^32 取模，跨过 0 时仍按字节数递增。
        relative_ack = (tcp.ack - peer_base) & SEQUENCE_MASK if tcp.flags & ACK and peer_base is not None else None
        events.append(FlowEvent(
            frame, timestamp - origin if timestamp is not None and origin is not None else None,
            direction, tcp.flags, "/".join(TCP_FLAGS[bit] for bit in _FLAG_ORDER if tcp.flags & (1 << bit)) or "—",
            (tcp.sequence - bases[source]) & SEQUENCE_MASK, relative_ack, tcp.payload_len, tcp.window,
        ))
        segments.append((direction, tcp))
    return FlowGraph(endpoints, endpoint_owners, tuple(events), _phases(segments), initial_sender is not None, total)


def _acknowledges(ack: int, end: int) -> bool:
    # ACK 可累计确认多个段。模差落在序号空间的前半区间才表示已覆盖目标。
    return ((ack - end) & SEQUENCE_MASK) < HALF_SEQUENCE_SPACE


def _phases(segments: Sequence[tuple[int, TcpSegment]]) -> tuple[FlowPhase, ...]:
    phases = []
    syn: tuple[int, int, int] | None = None  # 事件下标、方向、首个未确认序号
    syn_ack: int | None = None
    fins: dict[int, tuple[int, int]] = {}  # 方向 → (事件下标, FIN 后的序号)
    fin_acks: dict[int, int] = {}
    for index, (direction, tcp) in enumerate(segments):
        flags = tcp.flags
        peer = 1 - direction
        if flags & RST:
            phases.append(FlowPhase(FlowPhaseKind.RESET, index, index))
            syn, syn_ack = None, None
            fins.clear()
            fin_acks.clear()
            continue

        # SYN 和 FIN 各消耗一个序号，共用数据段时还要跳过负载。
        control_end = (tcp.sequence + tcp.payload_len + 1) & SEQUENCE_MASK
        if flags & (SYN | ACK) == SYN:
            if syn is None or syn[1:] != (direction, control_end):
                syn, syn_ack = (index, direction, control_end), None
                fins.clear()
                fin_acks.clear()
        elif syn is not None:
            if flags & (SYN | ACK) == (SYN | ACK) and direction != syn[1] and _acknowledges(tcp.ack, syn[2]):
                syn_ack = control_end
            elif syn_ack is not None and direction == syn[1] and flags & ACK and _acknowledges(tcp.ack, syn_ack):
                phases.append(FlowPhase(FlowPhaseKind.HANDSHAKE, syn[0], index))
                syn, syn_ack = None, None

        # 先确认对端已有的 FIN，再记录本包的 FIN，以识别同包合并的挥手。
        if flags & ACK and peer in fins and _acknowledges(tcp.ack, fins[peer][1]):
            fin_acks.setdefault(peer, index)
        if flags & FIN:
            fins.setdefault(direction, (index, control_end))
        if len(fin_acks) == 2:
            control_frames = {fins[0][0], fins[1][0], fin_acks[0], fin_acks[1]}
            kind = FlowPhaseKind.CLOSE_THREE if len(control_frames) == 3 else FlowPhaseKind.CLOSE_FOUR
            phases.append(FlowPhase(kind, min(control_frames), index))
            fins.clear()
            fin_acks.clear()
    return tuple(sorted(phases, key=lambda phase: phase.first))
