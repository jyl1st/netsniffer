from base64 import b64encode
from decimal import Decimal
from pathlib import Path

import pytest
from scapy.all import ARP, IP, TCP, Ether

from samples.make_samples import (
    BROADCAST_MAC, CLIENT_MAC, OTHER_MAC, SERVER_IP, SERVER_MAC, tcp_handshake, tcp_segment,
)
from sniffer.analysis.ids import AlertKind, AlertSeverity, analyze_alerts
from sniffer.analysis.streams import StreamIndex
from sniffer.analysis.tcp_application import TcpApplicationTracker
from sniffer.capture.pcap_io import read_capture
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _records(packets, *, interval=Decimal("0.01")):
    index = StreamIndex()
    tracker = TcpApplicationTracker()
    records = []
    for frame, packet in enumerate(packets):
        raw = bytes(packet)
        record = PacketRecord.from_bytes(frame * interval, raw, LINKTYPE_ETHERNET, len(raw))
        records.append(tracker.process(record).with_stream(index))
    return records


def test_arp_reports_both_macs_and_original_frame_numbers():
    alert, = analyze_alerts(read_capture(SAMPLES / "arp_conflict.pcap"))
    assert (alert.kind, alert.severity, alert.first_frame, alert.frames) == (
        AlertKind.ARP_SPOOFING, AlertSeverity.HIGH, 2, (2, 3),
    )
    assert SERVER_MAC in alert.description and OTHER_MAC in alert.description
    assert "帧 2" in alert.description and "帧 3" in alert.description


def test_gratuitous_arp_is_high_and_zero_sender_probes_do_not_create_bindings():
    def arp(sender, mac):
        return Ether(src=mac, dst=BROADCAST_MAC) / ARP(op=1, psrc=sender, hwsrc=mac, pdst=SERVER_IP)

    alert, = analyze_alerts(_records([
        arp("0.0.0.0", CLIENT_MAC), arp("0.0.0.0", OTHER_MAC), arp(SERVER_IP, SERVER_MAC), arp(SERVER_IP, OTHER_MAC),
    ]))
    assert alert.kind == AlertKind.ARP_SPOOFING
    assert alert.severity == AlertSeverity.HIGH
    assert alert.frames == (3, 4)
    assert "免费 ARP" in alert.description
    ordinary = arp(SERVER_IP, OTHER_MAC)
    ordinary[ARP].pdst = "192.0.2.1"
    weaker, = analyze_alerts(_records([arp(SERVER_IP, SERVER_MAC), ordinary]))
    assert weaker.severity == AlertSeverity.WARNING


def test_scan_without_response_counts_all_unique_ports_as_filtered():
    alert, = analyze_alerts(read_capture(SAMPLES / "syn_scan.pcap"))
    assert alert.kind == AlertKind.SYN_SCAN and alert.frames == tuple(range(1, 17))
    assert "开放 0" in alert.description and "过滤（无响应）16" in alert.description


def test_scan_checks_reverse_flow_and_ack_and_reports_open_ports():
    packets = []
    for port in range(8000, 8016):
        packets.append(tcp_segment(port, "S", 1000))
        if port in (8000, 8001):
            packets.extend([tcp_segment(port, "SA", 2000, 1001, reply=True), tcp_segment(port, "R", 1001)])
        elif port == 8002:
            packets.append(tcp_segment(port, "SA", 2000, 1234, reply=True))
        else:
            packets.append(tcp_segment(port, "RA", 0, 1001, reply=True))
    alert, = analyze_alerts(_records(packets))
    assert "开放 2（端口 8000, 8001）" in alert.description
    assert "关闭 13" in alert.description and "过滤（无响应）1" in alert.description
    assert {3, 6, 8}.isdisjoint(alert.frames)


def test_scan_requires_15_distinct_ports_within_ten_seconds():
    probes = [tcp_segment(port, "S", 1000) for port in range(15_000, 15_015)]
    assert not analyze_alerts(_records(probes, interval=Decimal("1")))
    assert not analyze_alerts(_records([*probes[:-1], probes[0]]))
    assert len(analyze_alerts(_records(probes))) == 1


def test_50_complete_connections_to_different_hosts_are_not_a_scan():
    packets = []
    for host in range(1, 51):
        remote = f"198.51.100.{host}"
        for index, packet in enumerate(tcp_handshake(443)):
            if index == 1:
                packet[IP].src = remote
            else:
                packet[IP].dst = remote
            packets.append(packet)
    assert not analyze_alerts(_records(packets))


@pytest.mark.parametrize("filename", ["tcp_http", "dns", "tls_client_hello", "application_protocols"])
def test_normal_sample_has_no_alert(filename):
    assert not analyze_alerts(read_capture(SAMPLES / f"{filename}.pcap"))


def test_basic_from_reassembled_header_and_local_header_never_keeps_password():
    token = b64encode(b"student:sample-basic-secret")
    request = b"GET / HTTP/1.1\r\nHost: example.test\r\nAuthorization: Basic " + token + b"\r\n\r\n"
    split = request.index(token) + 7
    first = tcp_segment(8080, "PA", 1001, 2001) / request[:split]
    second = tcp_segment(8080, "PA", 1001 + split, 2001) / request[split:]
    local = tcp_segment(8082, "PA", 1001, 2001) / request
    records = _records([*tcp_handshake(8080), first, second, second.copy(), local, local.copy()])
    assert records[4].tcp_application.messages[0].parser == "http"
    alerts = analyze_alerts(records)
    assert [alert.frames for alert in alerts] == [(5,), (7,)]
    for alert in alerts:
        assert alert.kind == AlertKind.PLAINTEXT_CREDENTIAL
        assert "student" in alert.description and "s***" in alert.description
        assert "sample-basic-secret" not in repr(alert) and token.decode() not in repr(alert)


def test_form_post_reassembles_observed_body_and_matches_decoded_case_insensitive_keys():
    body = b"name=user&%50aSsWd=%E5%AF%86example&pass=sample-form-secret"
    header = (b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded; charset=utf-8\r\n"
              b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n")
    # 头部分隔符也跨段，后两个 body 片段以乱序到达。
    chunks = [(0, header[:-1]), (len(header) - 1, header[-1:] + body[:8]),
              (len(header) + 28, body[28:]), (len(header) + 8, body[8:28])]
    packets = [*tcp_handshake(8080), *(tcp_segment(8080, "PA", 1001 + offset, 2001) / data
                                       for offset, data in chunks)]
    alert, = analyze_alerts(_records(packets))
    assert "passwd=密***" in alert.description and "pass=s***" in alert.description
    assert alert.frames == (5, 6, 7)
    assert "sample-form-secret" not in repr(alert)


def test_truncated_form_reports_only_material_that_was_captured():
    payload = (b"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n"
               b"Content-Length: 999\r\n\r\nusername=demo%2Dform&password=truncated")
    alert, = analyze_alerts(_records([tcp_segment(80, "PA", 1001) / payload]))
    assert "demo-form" in alert.description and "password=t***" in alert.description
    assert "truncated" not in repr(alert)


def test_ftp_pass_uses_username_and_masks_split_password_once():
    records = _records([
        tcp_segment(21, "S", 1000),
        tcp_segment(21, "PA", 1001) / b"USER demo\r\nPA",
        tcp_segment(21, "PA", 1014) / b"SS sample-ftp-secret\r\n",
        tcp_segment(21, "PA", 1014) / b"SS sample-ftp-secret\r\n",
    ])
    alert, = analyze_alerts(records)
    assert alert.frames == (2, 3) and "demo" in alert.description and "s***" in alert.description
    assert "sample-ftp-secret" not in repr(alert)
