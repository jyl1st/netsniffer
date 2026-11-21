from bisect import bisect_right
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from operator import itemgetter

from sniffer.analysis.streams import Endpoint
from sniffer.analysis.tcp import ACK, HALF_SEQUENCE_SPACE, RST, SEQUENCE_MASK, SYN
from sniffer.model.packet import PacketRecord

FIN = 0x01


class ExpertSeverity(Enum):
    WARNING = "Warning"
    NOTE = "Note"


class ExpertKind(Enum):
    RETRANSMISSION = "TCP 重传"
    DUPLICATE_ACK = "重复 ACK"
    ZERO_WINDOW = "零窗口"
    RESET = "RST"


@dataclass(frozen=True, slots=True)
class ExpertEvent:
    severity: ExpertSeverity
    kind: ExpertKind
    frame: int
    description: str


@dataclass(slots=True)
class _Direction:
    highest: int | None = None
    sent: list[tuple[int, int]] = field(default_factory=list)
    last_ack: tuple[int, int] | None = None

    def retransmits(self, sequence: int, length: int) -> bool:
        # 以已见最高序号为参考展开 32 位回绕，便于比较连续区间。
        highest = self.highest
        start = sequence if highest is None else highest + (
            (sequence - highest + HALF_SEQUENCE_SPACE) & SEQUENCE_MASK
        ) - HALF_SEQUENCE_SPACE
        end = start + length
        self.highest = end if highest is None else max(highest, end)
        # 只有整段落在已捕获的区间才算重传。低于最高序号但补了缺口的包不算。
        index = bisect_right(self.sent, start, key=itemgetter(0))
        if index and self.sent[index - 1][1] >= start:
            index -= 1
            old_start, old_end = self.sent[index]
            if end <= old_end:
                return True
            start = old_start
        stop = index
        while stop < len(self.sent) and self.sent[stop][0] <= end:
            end = max(end, self.sent[stop][1])
            stop += 1
        self.sent[index:stop] = [(start, end)]
        return False


@dataclass(slots=True)
class _Connection:
    initial_syn: tuple[Endpoint, int] | None = None
    directions: dict[Endpoint, _Direction] = field(default_factory=dict)


def analyze_expert(records: Sequence[PacketRecord]) -> tuple[ExpertEvent, ...]:
    """按捕获顺序检查 TCP 摘要，保留原始帧号。"""
    events: list[ExpertEvent] = []
    connections: dict[tuple[Endpoint, Endpoint], _Connection] = {}
    warning = ExpertSeverity.WARNING
    for frame, record in enumerate(records, 1):
        flow, tcp = record.summary.flow, record.summary.tcp
        if flow is None or tcp is None:
            continue
        flags = tcp.flags
        key = flow.endpoints
        if flags & RST:
            events.append(ExpertEvent(warning, ExpertKind.RESET, frame, "TCP 连接收到 RST。"))
            connections.pop(key, None)
            continue
        connection = connections.get(key)
        if connection is None:
            connection = connections[key] = _Connection()
        if flags & (SYN | ACK) == SYN:
            initial = flow.source, tcp.sequence
            if connection.initial_syn != initial:
                # 四元组复用时清除历史。同序号的初始 SYN 则仍可识别为重传。
                connection.initial_syn = initial
                connection.directions.clear()
        direction = connection.directions.get(flow.source)
        if direction is None:
            direction = connection.directions[flow.source] = _Direction()

        length = tcp.payload_len + bool(flags & SYN) + bool(flags & FIN)
        if length and direction.retransmits(tcp.sequence, length):
            events.append(ExpertEvent(
                warning, ExpertKind.RETRANSMISSION, frame,
                f"从 Seq={tcp.sequence} 开始的 {length} 个序号已在本方向发过。",
            ))
        if flags & ACK:
            signature = tcp.ack, tcp.window
            if not length and direction.last_ack == signature:
                events.append(ExpertEvent(
                    ExpertSeverity.NOTE, ExpertKind.DUPLICATE_ACK, frame,
                    f"确认号 {tcp.ack} 和原始窗口 {tcp.window} 与该方向上一个 ACK 相同。",
                ))
            direction.last_ack = signature
        if tcp.window == 0:
            events.append(ExpertEvent(warning, ExpertKind.ZERO_WINDOW, frame, "TCP 报头通告窗口为 0。"))
    return tuple(events)
