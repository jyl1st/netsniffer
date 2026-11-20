from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from sniffer.dissect.field import Field, ParseError, Span

Table = Literal["link", "ether", "ip", "app"]


@dataclass(frozen=True, slots=True)
class IPContext:
    version: int
    source: bytes
    destination: bytes
    complete: bool


Parser = Callable[[Span, "Registry", IPContext | None], Field]


class Registry:
    def __init__(self):
        self._parsers: dict[tuple[Table, int | str], Parser] = {}

    def register(self, table: Table, key: int | str, parser: Parser) -> None:
        entry = table, key
        if entry in self._parsers:
            raise ValueError(f"解析器已注册: {table}/{key}")
        self._parsers[entry] = parser

    def dispatch(
        self, table: Table, key: int | str, span: Span, network: IPContext | None = None,
    ) -> Field:
        parser = self._parsers.get((table, key))
        if parser is None:
            return span.payload(label=f"未识别的数据（{table}/{key}）")
        try:
            return parser(span, self, network)
        except ParseError as error:
            return span.layer("malformed", f"报文截断或格式异常 · {error}", (), str(error))
