from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network, ip_address
from operator import ge, gt, le, lt

from sniffer.dissect.field import Field, FieldValue
from sniffer.filter.ast import Compare, Exists, Expression, Logical, Not, Value
from sniffer.filter.fields import ALIASES, concrete_fields
from sniffer.filter.parser import parse_filter

ORDERED = {">": gt, "<": lt, ">=": ge, "<=": le}
ADDRESS_TYPES = (IPv4Address, IPv6Address)
NETWORK_TYPES = (IPv4Network, IPv6Network)


@dataclass(frozen=True, slots=True)
class FilterProgram:
    expression: Expression
    required: frozenset[str]

    def matches(self, tree: Field) -> bool:
        values: dict[str, list[FieldValue]] = {}
        pending = [tree]
        while pending:
            node = pending.pop()
            if not node.filterable:
                continue
            name = node.name
            if name in self.required:
                values.setdefault(name, []).append(node.value)
            children = node.children
            if children and name != "app.port_hint":
                pending.extend(children)
        return _evaluate(self.expression, values)


def compile_filter(source: str) -> FilterProgram | None:
    if not source.strip():
        return None
    root = parse_filter(source)
    return FilterProgram(root, concrete_fields(_names(root)))


def _names(root: Expression):
    if isinstance(root, Logical):
        for term in root.expressions:
            yield from _names(term)
    elif isinstance(root, Not):
        yield from _names(root.expression)
    else:
        yield root.field


def _evaluate(expression: Expression, values: dict[str, list[FieldValue]]) -> bool:
    if isinstance(expression, Logical):
        decisions = (_evaluate(term, values) for term in expression.expressions)
        return all(decisions) if expression.operator == "and" else any(decisions)
    if isinstance(expression, Not):
        return not _evaluate(expression.expression, values)

    names = ALIASES.get(expression.field, (expression.field,))
    candidates = [item for name in names for item in values.get(name, ())]
    if isinstance(expression, Exists):
        # 标志位存在于报头时可能为假；普通数值 0 仍然是一个存在的值。
        return any(item is not False for item in candidates)
    candidates = [item for item in candidates if item is not None]
    if not candidates:
        return False
    if expression.operator == "!=":
        return all(not _equals(item, expression.value) for item in candidates)
    return any(_compare(item, expression) for item in candidates)


def _equals(actual: FieldValue, expected: Value) -> bool:
    if isinstance(expected, (*ADDRESS_TYPES, *NETWORK_TYPES)):
        try:
            address = ip_address(actual) if isinstance(actual, str) else None
        except ValueError:
            return False
        if address is None:
            return False
        if isinstance(expected, NETWORK_TYPES):
            return address in expected
        return address == expected
    return actual == expected


def _compare(actual: FieldValue, expression: Compare) -> bool:
    operator, expected = expression.operator, expression.value
    if operator == "==":
        return _equals(actual, expected)
    if operator == "in":
        return any(_equals(actual, item) for item in expected)
    if operator == "contains":
        if isinstance(actual, bytes):
            return expected.encode("utf-8", "replace") in actual
        return isinstance(actual, str) and expected in actual
    if operator == "matches":
        if isinstance(actual, bytes):
            actual = actual.decode("utf-8", "replace")
        return isinstance(actual, str) and expected.match(actual).hasMatch()
    try:
        if isinstance(expected, ADDRESS_TYPES):
            actual = ip_address(actual) if isinstance(actual, str) else None
        return ORDERED[operator](actual, expected)
    except (TypeError, ValueError, ArithmeticError):
        return False
