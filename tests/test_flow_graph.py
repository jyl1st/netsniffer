from decimal import Decimal
from pathlib import Path

from scapy.all import TCP

from samples.make_samples import HTTP_REQUEST, HTTP_RESPONSE, dns_packets, tcp_segment
from sniffer.analysis.flow_graph import MAX_GRAPH_PACKETS, FlowPhase, FlowPhaseKind, build_flow_graph
from sniffer.analysis.follow import endpoint_label
from sniffer.analysis.streams import StreamIndex
from sniffer.capture.pcap_io import read_capture
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "tcp_flow_graph.pcap"


def _records(packets):
    streams = StreamIndex()
    result = []
    for packet in packets:
        raw = bytes(packet)
        result.append(PacketRecord.from_bytes(None, raw, LINKTYPE_ETHERNET, len(raw)).with_stream(streams))
    return result


def test_sample_flow_uses_relative_tcp_numbers_and_marks_handshake_and_four_way_close():
    graph = build_flow_graph(read_capture(SAMPLE), 0)
    assert tuple(map(endpoint_label, graph.endpoints)) == ("192.0.2.10:49152", "192.0.2.20:8080")
    assert graph.has_syn
    assert graph.total == 10
    assert graph.phases == (FlowPhase(FlowPhaseKind.HANDSHAKE, 0, 2), FlowPhase(FlowPhaseKind.CLOSE_FOUR, 6, 9))
    assert [(event.flag_text, event.direction, event.seq, event.ack) for event in graph.events[:3]] == [
        ("SYN", 0, 0, None), ("SYN/ACK", 1, 0, 1), ("ACK", 0, 1, 1),
    ]
    assert graph.events[3].length == len(HTTP_REQUEST)
    assert graph.events[4].length == len(HTTP_RESPONSE)
    assert graph.events[4].ack == 1 + len(HTTP_REQUEST)
    last = graph.events[-1]
    assert (last.frame, last.time, last.seq, last.ack) == (
        10, Decimal("0.09"), 2 + len(HTTP_REQUEST), 2 + len(HTTP_RESPONSE),
    )


def test_sample_reset_and_midstream_use_capture_frame_numbers():
    records = read_capture(SAMPLE)
    reset = build_flow_graph(records, 1)
    assert reset.phases == (FlowPhase(FlowPhaseKind.HANDSHAKE, 0, 2), FlowPhase(FlowPhaseKind.RESET, 3, 3))
    assert (reset.events[-1].frame, reset.events[-1].flag_text, reset.events[-1].ack) == (14, "RST", None)

    midstream = build_flow_graph(records, 2)
    assert not midstream.has_syn and not midstream.phases
    assert endpoint_label(midstream.endpoints[0]) == "192.0.2.20:8082"
    assert [(event.frame, event.direction, event.seq, event.ack) for event in midstream.events] == [
        (15, 0, 0, 0), (16, 1, 0, 9),
    ]


def test_wraparound_fin_with_data_and_combined_ack_use_tcp_sequence_space():
    dns, _ = dns_packets()
    records = _records([
        dns,
        tcp_segment(443, "S", 0xffffffff),
        tcp_segment(443, "SA", 0xfffffffe, 0, reply=True),
        tcp_segment(443, "A", 0, 0xffffffff),
        tcp_segment(443, "FPA", 0, 0xffffffff) / b"abc",
        tcp_segment(443, "FA", 0xffffffff, 4, reply=True),
        tcp_segment(443, "A", 4, 0),
    ])
    graph = build_flow_graph(records, 0)
    assert graph.phases == (FlowPhase(FlowPhaseKind.HANDSHAKE, 0, 2), FlowPhase(FlowPhaseKind.CLOSE_THREE, 3, 5))
    assert [(event.frame, event.seq, event.ack) for event in graph.events[-3:]] == [
        (5, 1, 1), (6, 1, 5), (7, 5, 2),
    ]
    assert graph.events[3].flag_text == "FIN/PSH/ACK"
    assert graph.events[3].length == 3


def test_phase_detection_ignores_nonconfirming_acks_and_stops_at_reset():
    records = _records([
        tcp_segment(443, "S", 1000),
        tcp_segment(443, "S", 1000),
        tcp_segment(443, "SA", 2000, 1001, reply=True),
        tcp_segment(443, "A", 1001, 2000),
        tcp_segment(443, "A", 1001, 2001),
        tcp_segment(443, "FA", 1001, 2001),
        tcp_segment(443, "R", 2001, reply=True),
    ])
    assert build_flow_graph(records, 0).phases == (
        FlowPhase(FlowPhaseKind.HANDSHAKE, 0, 4), FlowPhase(FlowPhaseKind.RESET, 6, 6),
    )


def test_single_direction_window_captured_payload_length_and_render_limit():
    packet = tcp_segment(443, "PA", 1234, 99) / b"abcdef"
    packet[TCP].window = 321
    packet[TCP].options = [("MSS", 1460)]
    raw = bytes(packet)
    record = PacketRecord.from_bytes(None, raw[:-2], LINKTYPE_ETHERNET, len(raw)).with_stream(StreamIndex())
    graph = build_flow_graph([record] * (MAX_GRAPH_PACKETS + 1), 0)
    event = graph.events[0]
    assert (event.seq, event.ack, event.length, event.window, event.time) == (0, None, 4, 321, None)
    assert record.summary.tcp.ack == 99
    assert graph.total == MAX_GRAPH_PACKETS + 1
    assert len(graph.events) == graph.events[-1].frame == MAX_GRAPH_PACKETS
    assert build_flow_graph([record], 1).endpoints is None
