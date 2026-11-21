from dataclasses import dataclass

SYN = 0x02
RST = 0x04
ACK = 0x10
SEQUENCE_MASK = (1 << 32) - 1
HALF_SEQUENCE_SPACE = 1 << 31
WINDOW_BYTES = 128 * 1024
MAX_RANGES = 64


@dataclass(frozen=True, slots=True)
class TcpSegment:
    sequence: int
    flags: int
    start: int
    end: int
    transport_info: str


@dataclass(frozen=True, slots=True)
class ReassembledMessage:
    parser: str
    data: bytes


@dataclass(frozen=True, slots=True)
class TcpApplication:
    protocol: str
    keep_local_fields: bool
    messages: tuple[ReassembledMessage, ...]
    info: str


@dataclass(slots=True)
class _Range:
    start: int
    data: bytearray

    @property
    def end(self) -> int:
        return self.start + len(self.data)


class TcpSequenceBuffer:
    """保存一个方向的连续字节和等待缺口补齐的区间。"""

    def __init__(self):
        self._reference: int | None = None
        self._next: int | None = None
        self._ranges: list[_Range] = []

    @property
    def position(self) -> int | None:
        if self._next is not None:
            return self._next
        return self._ranges[0].start if self._ranges else None

    @property
    def anchored(self) -> bool:
        return self._next is not None

    def contiguous(self) -> bytearray | None:
        if self._ranges and self._ranges[0].start == self.position:
            return self._ranges[0].data
        return None

    def add(self, sequence: int, payload: bytes, *, syn: bool = False) -> int:
        # 用当前位置展开 32 位序号。SYN 自身占用一个序号，负载从下一个序号开始。
        if self._reference is None:
            self._reference = sequence
        reference = self._reference if self._next is None else self._next
        delta = ((sequence + syn - reference + HALF_SEQUENCE_SPACE) & SEQUENCE_MASK) - HALF_SEQUENCE_SPACE
        start = reference + delta
        if syn and self._next is None:
            self._discard_before(start)
        if not payload:
            return start

        floor = self._next if self._next is not None else reference - WINDOW_BYTES
        end = min(start + len(payload), reference + WINDOW_BYTES)
        cursor = max(start, floor)
        if cursor >= end:
            return start

        # 只插入还没捕获的区间。重传或重叠来得更晚时保留原字节。
        gaps = []
        for part in self._ranges:
            if part.end <= cursor:
                continue
            if part.start >= end:
                break
            if cursor < part.start:
                gaps.append(_Range(cursor, bytearray(payload[cursor - start:part.start - start])))
            cursor = max(cursor, part.end)
            if cursor >= end:
                break
        if cursor < end:
            gaps.append(_Range(cursor, bytearray(payload[cursor - start:end - start])))
        if gaps:
            self._merge(gaps)
        return start

    def _merge(self, gaps: list[_Range]) -> None:
        merged: list[_Range] = []
        for part in sorted([*self._ranges, *gaps], key=lambda item: item.start):
            if merged and merged[-1].end == part.start:
                merged[-1].data.extend(part.data)
            elif len(merged) < MAX_RANGES:
                merged.append(part)
        self._ranges = merged

    def advance(self, size: int) -> None:
        """消费已解析的消息或略过长度已知的 HTTP 消息体。"""
        position = self.position
        if position is not None:
            self._discard_before(position + size)

    def clear(self) -> None:
        self._ranges.clear()

    def _discard_before(self, position: int) -> None:
        self._next = position
        while self._ranges and self._ranges[0].end <= position:
            self._ranges.pop(0)
        if self._ranges and self._ranges[0].start < position:
            part = self._ranges[0]
            del part.data[:position - part.start]
            part.start = position
