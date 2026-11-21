from pathlib import Path
from types import SimpleNamespace

from sniffer.analysis.stats import Counts, StatsSnapshot, protocol_hierarchy
from sniffer.capture.pcap_io import read_capture
from sniffer.gui.packet_table import PacketTableModel

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
