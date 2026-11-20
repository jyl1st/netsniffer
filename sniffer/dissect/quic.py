from dataclasses import dataclass
from struct import unpack_from

from sniffer.dissect.field import Field, ParseError, Span

VERSION_1 = 0x00000001
VERSION_2 = 0x6B3343CF
QUIC_TYPES = ("Initial", "0-RTT", "Handshake", "Retry")
QUIC_V2_TYPES = ("Retry", "Initial", "0-RTT", "Handshake")


@dataclass(frozen=True, slots=True)
class LongHeader:
    version: int
    kind: str
    destination_length: int
    source_length: int
    remainder: int


def quic_long_header(raw: bytes, start: int, end: int, *, on_443: bool) -> LongHeader | None:
    if end - start < 7 or not raw[start] & 0x80:
        return None
    flags = raw[start]
    version, = unpack_from("!I", raw, start + 1)
    known = version in (VERSION_1, VERSION_2) or version & 0xFFFFFF00 == 0xFF000000
    if not (on_443 or known) or (version and not flags & 0x40):
        return None
    dcid = raw[start + 5]
    source_length_at = start + 6 + dcid
    if dcid > 20 or source_length_at >= end:
        return None
    scid = raw[source_length_at]
    cursor = source_length_at + 1 + scid
    if scid > 20 or cursor >= end:
        return None
    remainder = cursor - start
    if version == 0:
        if (end - cursor) % 4:
            return None
        return LongHeader(version, "Version Negotiation", dcid, scid, remainder)
    kinds = QUIC_V2_TYPES if version == VERSION_2 else QUIC_TYPES
    kind = kinds[(flags >> 4) & 3]
    if kind == "Retry":
        # 未知版本的 Retry 没有可校验的长度边界，仅靠 443 不足以确认。
        return LongHeader(version, kind, dcid, scid, remainder) if known and end - cursor >= 17 else None
    try:
        if kind == "Initial":
            if end - start < 1200:
                return None
            token_size, cursor = _varint(raw, cursor, end)
            cursor += token_size
        length, cursor = _varint(raw, cursor, end)
    except ParseError:
        return None
    if not 17 <= length <= end - cursor:
        return None
    if not known and length != end - cursor:
        return None
    return LongHeader(version, kind if known else "长报头", dcid, scid, remainder)


def _varint(raw: bytes, cursor: int, end: int) -> tuple[int, int]:
    if cursor >= end:
        raise ParseError("QUIC 缺少变长整数")
    first = raw[cursor]
    size = 1 << (first >> 6)
    if cursor + size > end:
        raise ParseError("QUIC 变长整数截断")
    value = int.from_bytes(raw[cursor:cursor + size], "big")
    return value & ((1 << (size * 8 - 2)) - 1), cursor + size


def parse_quic(span: Span, _registry, _network) -> Field:
    header = quic_long_header(span.raw, span.start, span.end, on_443=True)
    if header is None:
        raise ParseError("QUIC 长报头或长度不完整")
    dest, src = header.destination_length, header.source_length
    fields = [
        span.number("quic.flags", "首字节", 0, hexadecimal=True),
        span.number("quic.version", "版本", 1, 4, hexadecimal=True),
        span.field("quic.dcid", "目标连接标识", span.bytes(6, dest).hex(), 6, dest),
        span.field("quic.scid", "源连接标识", span.bytes(7 + dest, src).hex(), 7 + dest, src),
        span.payload(header.remainder, label="QUIC 剩余数据"),
    ]
    return span.layer("quic", f"QUIC · {header.kind}", fields)
