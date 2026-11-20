from pathlib import Path

import pytest
from scapy.all import DHCP, DNS, UDP, rdpcap

from sniffer.capture.pcap_io import read_capture
from sniffer.dissect.frame import dissect_frame

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


@pytest.mark.parametrize("name,index,application,key,value", [
    ("tcp_http", 3, "HTTP", "http.request.uri", "/hello"),
    ("tcp_http", 3, "HTTP", "http.host", "sniffer.example"),
    ("tcp_http", 4, "HTTP", "http.response.code", 200),
    ("tls_client_hello", 3, "TLS", "tls.handshake.extensions_server_name", "sniffer.example"),
    ("application_protocols", 0, "DHCP", "dhcp.option.hostname", "sniffer-lab"),
    ("application_protocols", 1, "mDNS", "dns.qry.name", "实验设备.local"),
    ("application_protocols", 2, "SSDP", "ssdp.request.method", "M-SEARCH"),
    ("application_protocols", 3, "NTP", "ntp.flags.mode", 3),
    ("application_protocols", 4, "TLS", "tls.handshake.extensions_alpn_str", "h2"),
    ("application_protocols", 5, "SSH", "ssh.banner", "SSH-2.0-NetSnifferSample"),
    ("application_protocols", 6, "QUIC", "quic.dcid", "11223344"),
])
def test_application_fields_with_absolute_offsets(name, index, application, key, value):
    record = read_capture(SAMPLES / f"{name}.pcap")[index]
    tree = dissect_frame(record)
    fields = {item.name: item for item in tree.walk()}
    assert all(0 <= item.offset <= item.end <= len(record.raw) for item in tree.walk())
    assert "malformed" not in fields
    assert fields["app"].value == application == record.summary.protocol
    assert fields["app.basis"].value in record.summary.info
    assert fields[key].value == value
    assert fields[key].offset > 34
    if name == "tcp_http":
        assert fields["app.basis"].value == "内容特征"
    if key in ("http.request.uri", "http.host", "tls.handshake.extensions_server_name", "tls.handshake.extensions_alpn_str"):
        assert record.raw[fields[key].offset:fields[key].end] == value.encode()


def test_dns_and_dhcp_crosscheck_against_scapy():
    dns_path = SAMPLES / "dns.pcap"
    answer = rdpcap(str(dns_path))[1][DNS]
    fields = {item.name: item.value for item in dissect_frame(read_capture(dns_path)[1]).walk()}
    assert fields["dns.flags.response"] is True and answer.qr
    assert fields["dns.qry.name"] == answer.qd[0].qname.decode().rstrip(".")
    assert fields["dns.a"] == answer.an[0].rdata

    dhcp_path = SAMPLES / "application_protocols.pcap"
    packet = rdpcap(str(dhcp_path))[0]
    fields = {item.name: item.value for item in dissect_frame(read_capture(dhcp_path)[0]).walk()}
    assert fields["udp.dstport"] == packet[UDP].dport
    assert fields["dhcp.option.hostname"] == dict(option for option in packet[DHCP].options if isinstance(option, tuple))["hostname"].decode()
