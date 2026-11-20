from pathlib import Path

import pytest

from sniffer.capture.pcap_io import read_capture
from sniffer.dissect.field import Field
from sniffer.dissect.frame import dissect_frame
from sniffer.filter.evaluator import compile_filter
from sniffer.filter.lexer import FilterError, tokenize

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture(scope="module")
def trees():
    result = []
    previous = None
    for number, record in enumerate(read_capture(SAMPLES / "display_filters.pcap"), 1):
        result.append(dissect_frame(record, number, previous))
        previous = record.timestamp
    return result


@pytest.mark.parametrize("source,expected", [
    ("(http || dns) && ip.src == 192.168.0.0/16", [1, 2]),
    ("tcp.flags.syn && !tcp.flags.ack", [4]),
    ('tls.handshake.extensions_server_name contains "bilibili"', [6]),
    ("http || dns && ip.src == 192.168.0.0/16", [1, 2]),
    ("!(http or dns) and not tls", [4, 5]),
    ("tcp.port in {80, 443, 8080}", [1, 4, 5, 6, 7]),
    ("tcp.port != 443", [1]),
    ("ip.addr in {192.168.0.0/16, 192.0.2.53, 192.0.2.10}", [1, 2, 3, 4, 5, 6, 7]),
    ("udp.port == 53", [2, 3]),
    ("tcp.flags.ack == false", [4]),
    ("tcp.flags.push && tcp.len > 0", [1, 6, 7]),
    ("frame.number >= 5 && frame.number < 7", [5, 6]),
    ("frame.time_delta == 0.010", [2, 3, 4, 5, 6, 7]),
    ('http.host matches "^SNIFFER\\.EXAMPLE$"', [1]),
    ('http.host contains "sniffer"', [1]),
    ("eth.src == 02:00:00:00:00:10", [1, 2, 4, 6, 7]),
])
def test_matches_samples(trees, source, expected):
    program = compile_filter(source)
    assert [i for i, tree in enumerate(trees, 1) if program.matches(tree)] == expected


def test_ipv6_alias_boolean_presence_and_unconfirmed_subtree():
    tree = Field("frame", "Frame", None, 0, 0, (
        Field("ipv6.src", "addr", "2001:db8::42", 0, 0),
        Field("udp.length", "size", 0, 0, 0),
        Field("dns.flags.response", "response", False, 0, 0),
        Field("app.port_hint", "hint", None, 0, 0, (Field("dns", "DNS", None, 0, 0),)),
    ))
    assert compile_filter("ipv6.addr == 2001:db8::/32 && udp.length && !dns.flags.response").matches(tree)
    assert not compile_filter("dns").matches(tree)
    assert not compile_filter('http.host != "x"').matches(tree)
    assert compile_filter("   ") is None


@pytest.mark.parametrize("source,position", [
    ("udp & tcp", 4), ("dns &&", 6), ("(tcp or udp", 11),
    ('http.host == "abc', 13), ("tcp.no_such_field", 0),
    ("tcp.port in {53 443}", 16), ("ip.src == 192.0.2.999", 10),
])
def test_filter_errors_report_position(source, position):
    with pytest.raises(FilterError) as error:
        compile_filter(source)
    assert error.value.position == position


def test_regex_keeps_escape_and_bounds_backtracking():
    tokens = tokenize(r'http.host matches "\d+"')
    assert tokens[2].text == r"\d+"
    with pytest.raises(FilterError, match="正则表达式无效"):
        compile_filter('http.host matches "["')
    subject = Field("http.host", "Host", "a" * 4000 + "!", 0, 0)
    assert not compile_filter('http.host matches "^(a+)+$"').matches(subject)
