import pytest

from sniffer.dissect.field import Span
from sniffer.dissect.registry import Registry


def test_dispatch_retains_absolute_spans_and_can_locate_a_byte():
    registry = Registry()

    def parse(span, _registry, _network):
        value = span.number("example.value", "Value", 1, 2)
        return span.layer("example", "Example", [value])

    registry.register("app", "example", parse)
    region = Span(bytes.fromhex("ab cd 01 02 03 ff"), 2, 5)
    tree = registry.dispatch("app", "example", region)
    value = tree.at_byte(4)
    assert (value.name, value.value, value.offset, value.length) == ("example.value", 0x0203, 3, 2)
    assert tree.at_byte(5) is None
    assert [item.name for item in tree.walk()] == ["example", "example.value"]

    assert registry.dispatch("app", "other", region).name == "data"
    malformed = registry.dispatch("app", "example", region.sub(0, 2))
    assert malformed.name == "malformed"
    assert (malformed.offset, malformed.length) == (2, 2)
    with pytest.raises(ValueError, match="已注册"):
        registry.register("app", "example", parse)
