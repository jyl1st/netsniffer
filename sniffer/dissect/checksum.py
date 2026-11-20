from struct import pack
from sys import byteorder

from sniffer.dissect.field import Field, Span
from sniffer.dissect.registry import IPContext


def checksum_valid(data: bytes | memoryview, prefix: bytes = b"") -> bool:
    # 伪首部长度为偶数。验证时全体 16 位字交换字节顺序不影响结果。
    view = memoryview(data)
    even = len(view) & ~1
    total = sum(view[:even].cast("H"))
    if prefix:
        total += sum(memoryview(prefix).cast("H"))
    if len(view) != even:
        total += view[-1] << (8 if byteorder == "big" else 0)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def transport_checksum(span: Span, network: IPContext | None, protocol: int) -> bool | None:
    if network is None or not network.complete:
        return None
    prefix = network.source + network.destination
    if network.version == 4:
        prefix += pack("!BBH", 0, protocol, len(span))
    else:
        prefix += pack("!I3xB", len(span), protocol)
    return checksum_valid(memoryview(span.raw)[span.start:span.end], prefix)


def checksum_field(span: Span, name: str, offset: int, valid: bool | None) -> Field:
    value = span.uint(offset, 2)
    status = "未验证" if valid is None else "有效" if valid else "异常"
    detail = Field(f"{name}.valid", f"验证状态 · {status}", valid, span.start + offset, 2)
    return Field(name, f"校验和: 0x{value:04x}（{status}）", value, span.start + offset, 2, (detail,))
