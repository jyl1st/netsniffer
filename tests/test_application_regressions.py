from pathlib import Path
from struct import pack

import pytest
from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether

from sniffer.capture.pcap_io import read_capture
from sniffer.dissect.app_detect import identify_application
from sniffer.dissect.frame import dissect_frame
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
HOST = "doh.example"


def record(payload, transport, *, lost=0):
    raw = bytes(
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="192.0.2.53") / transport / payload
    )
    captured = raw[:-lost] if lost else raw
    return PacketRecord.from_bytes(None, captured, LINKTYPE_ETHERNET, len(raw))


def fields(packet):
    return {field.name: field for field in dissect_frame(packet).walk()}


def test_dns_queries_with_every_transaction_id_high_byte():
    question = DNSQR(qname=b"ttnet-doh.example", qtype="AAAA")
    for number in range(256):
        tid = number << 8 | 0xC7
        packet = record(bytes(DNS(id=tid, rd=1, qd=question)), UDP(sport=49152, dport=53))
        assert packet.summary.protocol == "DNS", hex(tid)
        assert f"标准查询 0x{tid:04x} AAAA ttnet-doh.example" in packet.summary.info
        assert "端口（内容已校验）" in packet.summary.info


def test_dns_response_info_and_attempt_to_match_quic_on_known_port():
    message = bytes(DNS(
        id=0x1BC7, qr=1, qd=DNSQR(qname=b"test.example"),
        an=DNSRR(rrname=b"test.example", type="A", rdata="192.0.2.20"),
    ))
    packet = record(message, UDP(sport=53, dport=49152))
    assert "标准应答 0x1bc7" in packet.summary.info and "A 192.0.2.20" in packet.summary.info
    initial = bytes.fromhex((SAMPLES / "quic_initial_rfc9001.hex").read_text(encoding="ascii"))
    for reserved in (53, 5353, 123, 67, 68, 1900):
        packet = record(initial, UDP(sport=443, dport=reserved))
        assert packet.summary.protocol == "UDP" and "内容不符" in packet.summary.info


@pytest.mark.parametrize("payload,port,flags,hint", [
    (b"\0", 443, "A", "TCP Keep-Alive?"),
    (b"\x80\x00\x01\xff\x02\x03", 8080, "PA", "端口 8080 常见于 HTTP，但内容不符"),
    (b"\x16\x03\x03\xff\xff\x01", 443, "PA", "端口 443 常见于 TLS，但内容不符"),
    (b"GET \x00 HTTP/1.1\r\n\r\n", 8080, "PA", "端口 8080 常见于 HTTP，但内容不符"),
    (b"SSH-\x01\x02\n", 22, "PA", "端口 22 常见于 SSH，但内容不符"),
])
def test_tcp_port_guesses_without_valid_content_stay_tcp(payload, port, flags, hint):
    packet = record(payload, TCP(sport=49152, dport=port, flags=flags))
    assert packet.summary.protocol == "TCP" and hint in packet.summary.info
    parsed = fields(packet)
    assert "app" not in parsed
    if port == 8080:
        assert parsed["app.invalid_http"].show == "不是有效的 HTTP 首行"


def test_quic_initial_at_nonstandard_port_and_version_gate():
    packet = read_capture(SAMPLES / "application_protocols.pcap")[-1]
    assert packet.summary.protocol == "QUIC"
    assert "Initial · 版本 0x00000001" in packet.summary.info
    assert fields(packet)["app.basis"].value == "弱特征"
    initial = bytearray.fromhex((SAMPLES / "quic_initial_rfc9001.hex").read_text(encoding="ascii"))
    initial[1:5] = pack("!I", 0x12345678)
    data = bytes(initial)
    assert identify_application(data, 0, len(data), 17, 49152, 4443) is None
    assert identify_application(data, 0, len(data), 17, 49152, 443).protocol == "QUIC"


def _extension(number, data):
    return pack("!HH", number, len(data)) + data


def large_client_hello():
    hostname = HOST.encode("ascii")
    sni = _extension(0, pack("!HBH", 3 + len(hostname), 0, len(hostname)) + hostname)
    group = pack("!HH", 0x11EC, 1216) + bytes([0xAA]) * 1216
    share = _extension(51, pack("!H", len(group)) + group)
    extensions = sni + _extension(43, b"\x02\x03\x04") + share
    fixed = b"\x03\x03" + bytes(range(32)) + b"\x00\x00\x02\x13\x01\x01\x00"
    padding = 1524 - (4 + len(fixed) + 2 + len(extensions) + 4)
    extensions += _extension(21, bytes(padding))
    body = fixed + pack("!H", len(extensions)) + extensions
    return b"\x16\x03\x01" + pack("!H", 1524) + b"\x01" + len(body).to_bytes(3, "big") + body


def test_split_tls_client_hello_keeps_sni_and_distinguishes_snaplen():
    data = large_client_hello()
    first, second = data[:1225], data[1225:]
    assert len(second) == 304
    segment = TCP(sport=49152, dport=443, flags="PA", seq=100)
    packet = record(first, segment)
    parsed = fields(packet)
    sni = parsed["tls.handshake.extensions_server_name"]
    assert sni.value == HOST and packet.raw[sni.offset:sni.end] == HOST.encode()
    assert parsed["tls.handshake.extensions_key_share_key_exchange_length"].value == 1216
    assert "记录跨 TCP 段：本段含 1220 / 1524 字节" in parsed["tls.record"].show
    assert parsed["tls.record.truncated"].show == "其余 304 字节在后续 TCP 段中"
    assert "Client Hello · SNI=doh.example" in packet.summary.info

    truncated = record(first, segment, lost=20)
    parsed = fields(truncated)
    assert parsed["tls.handshake.extensions_server_name"].value == HOST
    assert "记录抓包截断" in parsed["tls.record"].show
    assert "抓包截断" in parsed["tls.record.truncated"].show
    assert "后续 TCP 段" not in parsed["tls.record.truncated"].show

    tail = record(second, TCP(sport=49152, dport=443, flags="PA", seq=100 + len(first)))
    assert tail.summary.protocol == "TCP"
    full = record(data, segment)
    assert "tls.record.truncated" not in fields(full)


def test_http_and_tls_info_and_partial_http_headers():
    request = record(
        b"GET /path HTTP/1.1\r\nHost: local.example\r\nUser-Agent: partial",
        TCP(sport=49152, dport=8080, flags="PA"),
    )
    parsed = fields(request)
    assert request.summary.info.startswith("GET /path HTTP/1.1")
    assert parsed["http.host"].value == "local.example"
    assert parsed["http.user_agent"].value == "partial"
    assert "后续 TCP 段" in parsed["http.headers_incomplete"].show
    response = read_capture(SAMPLES / "tcp_http.pcap")[4]
    assert response.summary.info.startswith("HTTP/1.1 200 OK")
    server = read_capture(SAMPLES / "application_protocols.pcap")[4]
    assert server.summary.info.startswith("Server Hello")
    encrypted = record(b"\x17\x03\x03\x00\x12" + bytes(18), TCP(sport=443, dport=49152, flags="PA"))
    assert encrypted.summary.info.startswith("Application Data")


def test_partial_dns_over_tcp_keeps_first_question():
    message = bytes(DNS(id=9, qr=1, qd=DNSQR(qname=b"local.example"), an=DNSRR(
        rrname=b"local.example", type="A", rdata="192.0.2.11",
    )))
    packet = record(pack("!H", len(message)) + message[:-2], TCP(sport=53, dport=49152, flags="PA"))
    parsed = fields(packet)
    assert packet.summary.protocol == "DNS"
    assert "标准应答 0x0009 A local.example" in packet.summary.info
    assert parsed["dns.qry.name"].value == "local.example"
    assert parsed["dns.resp.name"].value == "local.example"
    assert "其余 2 字节" in parsed["dns.tcp.incomplete"].show
