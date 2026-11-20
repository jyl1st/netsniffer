from pathlib import Path

import pytest
from scapy.all import (
    ARP, ICMP, IP, IPv6, TCP, UDP, Ether, ICMPv6EchoRequest, IPv6ExtHdrFragment,
    IPv6ExtHdrHopByHop, rdpcap,
)

from sniffer.capture.pcap_io import read_capture
from sniffer.dissect.frame import dissect_frame
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.mark.parametrize("file,layer,field,attribute", [
    ("tcp_http", Ether, "eth.src", "src"),
    ("tcp_http", IP, "ip.ttl", "ttl"),
    ("tcp_http", TCP, "tcp.seq", "seq"),
    ("dns", UDP, "udp.dstport", "dport"),
    ("arp", ARP, "arp.dst.proto_ipv4", "pdst"),
    ("ipv6", IPv6, "ipv6.src", "src"),
    ("ipv6", ICMPv6EchoRequest, "icmpv6.echo.identifier", "id"),
    ("icmp", ICMP, "icmp.type", "type"),
])
def test_network_fields_crosschecked_with_scapy(file, layer, field, attribute):
    source = SAMPLES / f"{file}.pcap"
    scapy_packet = rdpcap(str(source))[0]
    record = read_capture(source)[0]
    frame = dissect_frame(record)
    fields = {item.name: item for item in frame.walk()}
    item = fields[field]
    assert item.value == getattr(scapy_packet[layer], attribute)
    assert item is frame.at_byte(item.offset) or frame.at_byte(item.offset).offset == item.offset
    assert not any(item.name == "malformed" for item in frame.walk())


def packet_frame(packet):
    raw = bytes(packet)
    return dissect_frame(PacketRecord.from_bytes(None, raw, LINKTYPE_ETHERNET, len(raw)))


def test_tcp_options_capture_lengths_and_checksum():
    packet = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / TCP(
        sport=3211, dport=80, flags="S", options=[("MSS", 1460), ("WScale", 7), ("Timestamp", (21, 34))],
    )
    parsed_by_scapy = Ether(bytes(packet))
    tree = packet_frame(parsed_by_scapy)
    fields = {item.name: item for item in tree.walk()}
    assert fields["tcp.flags.syn"].value is True
    assert fields["tcp.options.mss_val"].value == parsed_by_scapy[TCP].options[0][1]
    assert fields["tcp.options.timestamp.tsecr"].value == 34
    assert fields["tcp.checksum.valid"].value is True
    assert (fields["tcp.srcport"].offset, fields["tcp.srcport"].length) == (34, 2)
    assert int.from_bytes(bytes(packet)[34:36], "big") == 3211

    parsed_by_scapy[TCP].chksum ^= 1
    fields = {item.name: item for item in packet_frame(parsed_by_scapy).walk()}
    assert fields["tcp.checksum.valid"].value is False
    raw = bytes(parsed_by_scapy)
    summary = PacketRecord.from_bytes(None, raw, LINKTYPE_ETHERNET, len(raw)).summary
    assert summary.error and "校验和异常" in summary.info


def test_ipv4_and_ipv6_fragments_do_not_parse_tail_as_a_transport_header():
    fragment = Ether() / IP(src="192.0.2.1", dst="192.0.2.2", flags="MF", frag=2, proto=17) / bytes(24)
    fields = {item.name: item for item in packet_frame(fragment).walk()}
    assert fields["ip.flags.mf"].value is True
    assert fields["ip.frag_offset"].value == 16
    assert "udp" not in fields

    packet = (
        Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2")
        / IPv6ExtHdrHopByHop() / IPv6ExtHdrFragment(id=14)
        / UDP(sport=1234, dport=1111) / b"odd bytes"
    )
    fields = {item.name: item for item in packet_frame(packet).walk()}
    assert fields["ipv6.frag.id"].value == 14
    assert fields["udp.dstport"].offset == 14 + 40 + 8 + 8 + 2
    assert fields["udp.checksum.valid"].value is True


def test_each_truncated_prefix_stays_inside_the_captured_frame():
    complete = read_capture(SAMPLES / "tcp_http.pcap")[3]
    for size in range(len(complete.raw)):
        raw = complete.raw[:size]
        record = PacketRecord.from_bytes(None, raw, LINKTYPE_ETHERNET, complete.wire_length)
        tree = dissect_frame(record)
        assert all(0 <= field.offset <= field.end <= size for field in tree.walk())
