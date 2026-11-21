from pathlib import Path

import pytest
from scapy.all import Ether, IP, IPv6, IPv6ExtHdrFragment, TCP, UDP

from sniffer.analysis.streams import StreamIndex
from sniffer.capture.pcap_io import read_capture, read_capture_preview, write_capture
from sniffer.dissect.frame import dissect_frame
from sniffer.filter.evaluator import compile_filter
from sniffer.gui import packet_table
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def record(packet, captured_length=None):
    raw = bytes(Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02") / packet)
    return PacketRecord.from_bytes(None, raw[:captured_length], LINKTYPE_ETHERNET, len(raw))


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_imported_streams_filter_bidirectionally(tmp_path, suffix):
    http = read_capture(SAMPLES / "tcp_http.pcap")
    dns = read_capture(SAMPLES / "dns.pcap")
    tls = read_capture(SAMPLES / "tls_client_hello.pcap")
    path = tmp_path / f"streams{suffix}"
    write_capture(path, [*http, *dns, *tls])
    records = read_capture(path)
    trees = [dissect_frame(item) for item in records]
    for expression, expected in (
        ("tcp.stream == 0", http),
        ("udp.stream == 0", dns),
        ("tcp.stream == 1", tls),
        ("udp.stream", dns),
    ):
        program = compile_filter(expression)
        assert [item for item, tree in zip(records, trees) if program.matches(tree)] == expected

    stream = next(field for field in trees[0].walk() if field.name == "tcp.stream")
    assert stream.value == 0
    assert stream.length == 0


def test_addresses_and_ports_keep_their_pairing_and_protocol():
    a, b = "192.0.2.1", "192.0.2.2"
    streams = StreamIndex()
    frames = [
        record(IP(src=a, dst=b) / TCP(sport=1000, dport=2000)),
        record(IP(src=b, dst=a) / TCP(sport=2000, dport=1000)),
        record(IP(src=a, dst=b) / TCP(sport=2000, dport=1000)),
        record(IP(src=a, dst=b) / UDP(sport=1000, dport=2000)),
        record(IP(src=b, dst=a) / UDP(sport=2000, dport=1000)),
        record(IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=1000, dport=2000)),
        record(IPv6(src="2001:db8::2", dst="2001:db8::1") / UDP(sport=2000, dport=1000)),
    ]
    assert [item.with_stream(streams).stream_id for item in frames] == [0, 0, 1, 0, 0, 1, 1]


def test_fragment_and_truncation_stream_fields_require_transport_header():
    udp = UDP(sport=1000, dport=2000)
    v4 = IP(src="192.0.2.1", dst="192.0.2.2")
    v6 = IPv6(src="2001:db8::1", dst="2001:db8::2")
    streams = StreamIndex()
    frames = [
        record(v4 / udp, captured_length=14 + 20 + 4),
        record(IP(src=v4.src, dst=v4.dst, frag=1) / udp),
        record(v6 / IPv6ExtHdrFragment(offset=1) / udp),
        record(v6 / IPv6ExtHdrFragment(m=1) / udp),
        record(v4 / udp),
    ]
    assert [item.with_stream(streams).stream_id for item in frames] == [None, None, None, 0, 1]


def test_live_numbering_only_indexes_stored_frames_and_resets(monkeypatch):
    ip = IP(src="192.0.2.1", dst="192.0.2.2")
    first = record(ip / TCP(sport=1000, dport=2000))
    dropped = record(ip / TCP(sport=1001, dport=2000) / b"payload")
    next_flow = record(ip / TCP(sport=1002, dport=2000))
    monkeypatch.setattr(packet_table, "MAX_BYTES", len(first.raw) + len(next_flow.raw))
    model = packet_table.PacketTableModel()
    assert model.append([first, dropped]) == 1
    model.begin_filter(True)
    assert model.append([next_flow]) == 0
    assert [item.stream_id for item in model.records] == [0, 1]

    model.replace([])
    assert model.append([next_flow, first]) == 0
    assert [item.stream_id for item in model.records] == [0, 1]


def test_replacing_with_a_preview_uses_its_stream_index():
    preview = read_capture_preview(SAMPLES / "tcp_http.pcap")
    model = packet_table.PacketTableModel()
    assert model.append(read_capture(SAMPLES / "tls_client_hello.pcap")) == 0
    model.replace(preview.records, streams=preview.streams)
    new = read_capture(SAMPLES / "tls_client_hello.pcap")[0]
    old = preview.records[-1]
    assert model.append([new, old]) == 0
    assert [item.stream_id for item in model.records[-2:]] == [1, 0]
