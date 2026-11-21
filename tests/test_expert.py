from pathlib import Path

import pytest
from scapy.all import TCP

from samples.make_samples import tcp_handshake, tcp_segment
from sniffer.analysis.expert import ExpertKind, ExpertSeverity, analyze_expert
from sniffer.capture.pcap_io import read_capture
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _records(packets):
    records = []
    for packet in packets:
        raw = bytes(packet)
        records.append(PacketRecord.from_bytes(None, raw, LINKTYPE_ETHERNET, len(raw)))
    return records


def test_retransmission_sample_reports_the_second_copy():
    events = analyze_expert(read_capture(SAMPLES / "tcp_retransmission.pcap"))
    assert [(event.frame, event.severity) for event in events if event.kind == ExpertKind.RETRANSMISSION] == [
        (5, ExpertSeverity.WARNING),
    ]


def test_duplicate_ack_requires_same_direction_ack_and_window():
    packets = [tcp_segment(80, "A", 1001, 2001) for _ in range(5)]
    packets[2] = tcp_segment(80, "A", 2001, 2001, reply=True)
    packets[3][TCP].window = packets[4][TCP].window = 4096
    events = analyze_expert(_records(packets))
    assert [(event.frame, event.kind, event.severity) for event in events] == [
        (2, ExpertKind.DUPLICATE_ACK, ExpertSeverity.NOTE),
        (5, ExpertKind.DUPLICATE_ACK, ExpertSeverity.NOTE),
    ]


def test_zero_window_and_rst_are_warnings_and_rst_does_not_report_zero_window():
    zero = tcp_segment(80, "A", 1001, 2001)
    reset = tcp_segment(80, "RA", 1001, 2001)
    zero[TCP].window = reset[TCP].window = 0
    events = analyze_expert(_records([zero, reset]))
    assert [(event.frame, event.kind, event.severity) for event in events] == [
        (1, ExpertKind.ZERO_WINDOW, ExpertSeverity.WARNING),
        (2, ExpertKind.RESET, ExpertSeverity.WARNING),
    ]


def test_http_sample_has_no_warning():
    assert all(event.severity != ExpertSeverity.WARNING
               for event in analyze_expert(read_capture(SAMPLES / "tcp_http.pcap")))


def test_retransmission_across_wrap_requires_the_whole_range_and_current_connection():
    packets = [
        tcp_segment(80, "S", 0xfffffffc),
        tcp_segment(80, "S", 0xfffffffc),
        tcp_segment(80, "PA", 0xfffffffd) / b"abc",
        tcp_segment(80, "PA", 3) / b"ghi",
        tcp_segment(80, "PA", 1) / b"ef",  # 结束序号低于最高值，但这部分尚未捕获。
        tcp_segment(80, "PA", 0xfffffffe) / b"bcDef",  # 尚未捕获序号 0 的字节。
        tcp_segment(80, "PA", 0xfffffffe) / b"bcDef",
        tcp_segment(80, "FA", 6),
        tcp_segment(80, "FA", 6),
        tcp_segment(80, "S", 0xfffffffd),  # 不同初始 SYN 的新连接。
        tcp_segment(80, "PA", 0xfffffffe) / b"bcDef",
    ]
    events = analyze_expert(_records(packets))
    assert [event.frame for event in events if event.kind == ExpertKind.RETRANSMISSION] == [2, 7, 9]


@pytest.mark.parametrize("probe_data", [b"X", b""])
def test_keep_alive_probes_and_replies_do_not_become_retransmissions_or_duplicate_acks(probe_data):
    packets = [
        *tcp_handshake(80),
        tcp_segment(80, "PA", 1001, 2001) / b"data",
        tcp_segment(80, "A", 2001, 1005, reply=True),
    ]
    for _ in range(3):
        probe = tcp_segment(80, "A", 1004, 2001)
        packets.extend([probe / probe_data if probe_data else probe, tcp_segment(80, "A", 2001, 1005, reply=True)])
    events = analyze_expert(_records(packets))
    assert [(event.frame, event.kind, event.severity) for event in events] == [
        (frame, ExpertKind.KEEP_ALIVE, ExpertSeverity.NOTE) for frame in (6, 8, 10)
    ]


def test_keep_alive_wraps_and_does_not_hide_unrelated_duplicate_ack_or_fin_retransmission():
    packets = [
        tcp_segment(80, "S", 0xfffffffe),
        tcp_segment(80, "SA", 2000, 0xffffffff, reply=True),
        tcp_segment(80, "PA", 0xffffffff, 2001) / b"X",
        tcp_segment(80, "A", 2001, 0, reply=True),
        tcp_segment(80, "A", 0xffffffff, 2001) / b"X",
        tcp_segment(80, "A", 2001, 0, reply=True),
        tcp_segment(80, "FA", 0, 2001),
        tcp_segment(80, "FA", 0, 2001),
        tcp_segment(80, "A", 2001, 0, reply=True),
    ]
    events = analyze_expert(_records(packets))
    assert [(event.frame, event.kind) for event in events] == [
        (5, ExpertKind.KEEP_ALIVE), (8, ExpertKind.RETRANSMISSION), (9, ExpertKind.DUPLICATE_ACK),
    ]
