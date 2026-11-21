from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace

from sniffer.analysis.stats import Counts, StatsSnapshot, conversations, endpoints, io_buckets, protocol_hierarchy
from sniffer.capture.pcap_io import read_capture
from sniffer.gui.packet_table import PacketTableModel
from tools.compare_stats_tshark import _tshark_io

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def test_protocol_hierarchy_counts_complete_wire_lengths():
    records = read_capture(SAMPLES / "tcp_http.pcap")
    nodes = protocol_hierarchy(StatsSnapshot.from_records(records))
    tcp = ("Frame", "Ethernet", "IPv4", "TCP")
    assert nodes[tcp[:1]] == nodes[tcp[:2]] == nodes[tcp[:3]] == nodes[tcp] == Counts(6, 413)
    assert nodes[tcp + ("HTTP",)] == Counts(2, 197)


def test_stats_snapshot_counts_only_visible_frames_with_original_numbers():
    records = read_capture(SAMPLES / "security_demo.pcap")
    model = SimpleNamespace(records=records, _visible=[0, 2], _first_time=records[0].timestamp)
    snapshot, filtered = PacketTableModel.statistics_snapshot(model)
    assert filtered
    assert [number for number, _ in snapshot.frames] == [1, 3]
    assert snapshot.origin == records[0].timestamp
    nodes = protocol_hierarchy(snapshot)
    assert nodes[("Frame",)] == nodes[("Frame", "Ethernet", "ARP")] == Counts(2, 84)


def test_conversations_split_wire_counts_and_keep_stream_number():
    records = read_capture(SAMPLES / "tcp_http.pcap")
    groups = conversations(StatsSnapshot.from_records(records))
    ip, = groups["IPv4"]
    tcp, = groups["TCP"]
    assert (tcp.a, tcp.b, tcp.stream) == (("192.0.2.10", 49152), ("192.0.2.20", 8080), 0)
    assert tcp.forward == ip.forward == Counts(4, 262)
    assert tcp.reverse == ip.reverse == Counts(2, 151)
    assert (tcp.frames, tcp.bytes, tcp.start, tcp.duration) == (6, 413, Decimal(0), Decimal("0.05"))
    assert ip.a == ("192.0.2.10", None) and ip.stream is None


def test_conversations_preserve_origin_on_filtered_reverse_frames():
    records = read_capture(SAMPLES / "tcp_http.pcap")
    snapshot = StatsSnapshot(((2, records[1]), (5, records[4])), records[0].timestamp)
    tcp, = conversations(snapshot)["TCP"]
    assert tcp.a == ("192.0.2.20", 8080)
    assert tcp.stream == 0
    assert tcp.forward == Counts(2, 151) and tcp.reverse == Counts()
    assert tcp.start == Decimal("0.01")


def test_endpoints_split_source_and_destination_counts():
    groups = endpoints(StatsSnapshot.from_records(read_capture(SAMPLES / "dns.pcap")))
    assert not groups["TCP"]
    client, server = groups["UDP"]
    assert client.address[0] == "192.0.2.10" and server.address[1] == 53
    assert client.sent == server.received == Counts(1, 75)
    assert client.received == server.sent == Counts(1, 106)
    assert (client.frames, client.bytes) == (2, 181)
    assert all(row.address[1] is None for row in groups["IPv4"])


def test_io_buckets_use_capture_origin_and_left_closed_boundaries():
    records = read_capture(SAMPLES / "tcp_http.pcap")
    origin = records[0].timestamp
    snapshot = StatsSnapshot((
        (2, replace(records[1], timestamp=origin + Decimal("0.099999"))),
        (3, replace(records[2], timestamp=origin + Decimal("0.1"))),
        (4, replace(records[3], timestamp=origin + Decimal("0.199999"))),
        (6, replace(records[5], timestamp=origin + Decimal("0.3"))),
    ), origin)
    buckets = io_buckets(snapshot, Decimal("0.1"))
    assert [(row.index, row.first_frame, row.counts) for row in buckets] == [
        (0, 2, Counts(1, 54)), (1, 3, Counts(2, 154)), (3, 6, Counts(1, 54)),
    ]
    bucket, = io_buckets(snapshot)
    assert (bucket.index, bucket.first_frame, bucket.counts) == (0, 2, Counts(4, 262))


def test_tshark_io_parser_accepts_integer_and_final_duration_intervals():
    report = "|  0 <> 1  |      4 |   262 |\n|  1 <> Dur|      3 |   251 |"
    assert _tshark_io(report) == {Decimal(0): (4, 262), Decimal(1): (3, 251)}
