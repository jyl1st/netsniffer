from collections.abc import Iterator
from dataclasses import dataclass
from decimal import Decimal
from struct import calcsize, unpack_from

FieldValue = bool | int | float | Decimal | str | bytes | None


class ParseError(ValueError):
    """捕获范围内的协议数据不完整或格式异常。"""


@dataclass(frozen=True, slots=True)
class Field:
    name: str
    show: str
    value: FieldValue
    offset: int
    length: int
    children: tuple["Field", ...] = ()

    @property
    def end(self) -> int:
        return self.offset + self.length

    def walk(self) -> Iterator["Field"]:
        yield self
        for child in self.children:
            yield from child.walk()

    def at_byte(self, offset: int) -> "Field | None":
        if not self.offset <= offset < self.end:
            return None
        best = self
        for child in self.children:
            match = child.at_byte(offset)
            if match is not None and (best is self or match.length < best.length):
                best = match
        return best


@dataclass(frozen=True, slots=True)
class Span:
    raw: bytes
    start: int
    end: int

    def __len__(self) -> int:
        return self.end - self.start

    def require(self, offset: int, length: int) -> int:
        if offset < 0 or length < 0 or offset + length > len(self):
            raise ParseError(f"偏移 {self.start + offset} 需要 {length} 字节，超出当前报文范围")
        return self.start + offset

    def bytes(self, offset: int, length: int) -> bytes:
        start = self.require(offset, length)
        return self.raw[start:start + length]

    def uint(self, offset: int, length: int = 1, *, signed: bool = False) -> int:
        return int.from_bytes(self.bytes(offset, length), "big", signed=signed)

    def unpack(self, fmt: str, offset: int) -> tuple:
        start = self.require(offset, calcsize(fmt))
        return unpack_from(fmt, self.raw, start)

    def sub(self, offset: int, length: int | None = None) -> "Span":
        size = len(self) - offset if length is None else length
        start = self.require(offset, size)
        return Span(self.raw, start, start + size)

    def field(
        self, name: str, label: str, value: FieldValue, offset: int, length: int,
        *, text: str | None = None,
    ) -> Field:
        start = self.require(offset, length)
        display = f"{label}: {value if text is None else text}" if value is not None else label
        return Field(name, display, value, start, length)

    def number(
        self, name: str, label: str, offset: int, length: int = 1, *, signed=False, hexadecimal=False,
    ) -> Field:
        value = self.uint(offset, length, signed=signed)
        text = f"0x{value:0{length * 2}x}" if hexadecimal else None
        return self.field(name, label, value, offset, length, text=text)

    def layer(
        self, name: str, label: str, children: list[Field] | tuple[Field, ...], value: FieldValue = None,
    ) -> Field:
        return Field(name, label, value, self.start, len(self), tuple(children))

    def payload(self, offset: int = 0, name: str = "data", label: str = "数据") -> Field:
        return self.field(name, f"{label}（{len(self) - offset} 字节）", None, offset, len(self) - offset)
