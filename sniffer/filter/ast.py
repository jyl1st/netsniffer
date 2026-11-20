from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Literal

from PySide6.QtCore import QRegularExpression

Value = str | bool | int | Decimal | IPv4Address | IPv6Address | IPv4Network | IPv6Network


@dataclass(frozen=True, slots=True)
class Exists:
    field: str


@dataclass(frozen=True, slots=True)
class Compare:
    field: str
    operator: str
    value: Value | tuple[Value, ...] | QRegularExpression


@dataclass(frozen=True, slots=True)
class Not:
    expression: Expression


@dataclass(frozen=True, slots=True)
class Logical:
    operator: Literal["and", "or"]
    expressions: tuple[Expression, ...]


Expression = Exists | Compare | Not | Logical
