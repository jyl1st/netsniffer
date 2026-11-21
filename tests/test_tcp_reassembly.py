from ctypes import create_string_buffer
from decimal import Decimal
from struct import pack
from types import SimpleNamespace

from scapy.all import DNS, DNSQR, DNSRR

from samples.make_samples import tcp_segment, tls_client_hello
from sniffer.analysis.tcp import TcpSequenceBuffer, WINDOW_BYTES
from sniffer.capture.engine import CaptureSession, CaptureSettings
from sniffer.capture.pcap_io import read_capture, write_capture
from sniffer.dissect.frame import dissect_frame
from sniffer.filter.evaluator import compile_filter
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord


def test_tcp_sequence_wrap_syn_out_of_order_and_retransmission():
    buffer = TcpSequenceBuffer()
    buffer.add(0xFFFFFFFD, b"", syn=True)
    buffer.add(1, b"DEx")
    assert buffer.contiguous() is None
    buffer.add(1, b"???")
    buffer.add(0xFFFFFFFE, b"ABCDE")
    assert buffer.contiguous() == b"ABCDEx"
    buffer.advance(5)
    buffer.add(0xFFFFFFFE, b"ABCDE?")
    assert buffer.contiguous() == b"x"
    buffer.advance(1)
    assert buffer.contiguous() is None


def test_tcp_uses_only_captured_contiguous_bytes():
    buffer = TcpSequenceBuffer()
    buffer.add(10, b"header")
    buffer.add(21, b"suffix")
    buffer.add(10 + WINDOW_BYTES + 1, b"outside window")
    assert buffer.contiguous() == b"header"
    buffer.add(16, b"-gap-")
    assert buffer.contiguous() == b"header-gap-suffix"


def test_tcp_inserts_earlier_bytes_without_a_captured_syn():
    buffer = TcpSequenceBuffer()
    buffer.add(20, b"tail")
    buffer.add(17, b"pre???")
    assert buffer.contiguous() == b"pretail"


def _segment(port, sequence, data=b"", *, flags="PA", reply=False):
    packet = tcp_segment(port, flags, sequence, reply=reply)
    if data:
        packet = packet / data
    raw = bytes(packet)
    return PacketRecord.from_bytes(Decimal(1), raw, LINKTYPE_ETHERNET, len(raw))


def _import(tmp_path, frames):
    path = tmp_path / "segmented.pcap"
    write_capture(path, frames)
    return read_capture(path)


def _fields(record):
    return {node.name: node for node in dissect_frame(record).walk()}


def _matching_frames(frames, expression):
    program = compile_filter(expression)
    return [index for index, frame in enumerate(frames) if program.matches(dissect_frame(frame))]


def _client_hello():
    # 将 SNI 放在较长的扩展之后，确保主机名落在后续 TCP 段。
    return tls_client_hello(b"split.example", leading_extensions=pack("!HH", 21, 1250) + bytes(1250))


def test_http_recovers_complete_requests_after_a_missing_segment(tmp_path):
    first = b"GET /1 HTTP/1.1\r\nHost: on"
    second = b"GET /2 HTTP/1.1\r\nHost: two.example\r\n\r\n"
    third = b"GET /3 HTTP/1.1\r\nHost: three.example\r\n\r\n"
    second_start = 1001 + len(first) + len(b"e.example\r\n\r\n")
    frames = _import(tmp_path, [
        _segment(80, 1000, flags="S"),
        _segment(80, 1001, first),
        _segment(80, second_start, second),
        _segment(80, second_start + len(second), third),
    ])
    assert _matching_frames(frames, "http.host") == [2, 3]
    partial_host = _fields(frames[1])["http.host"]
    assert frames[1].raw[partial_host.offset:partial_host.end] == b"on"
    for frame, hostname in zip(frames[2:], (b"two.example", b"three.example")):
        host = _fields(frame)["http.host"]
        assert host.value == hostname.decode("ascii")
        assert frame.raw[host.offset:host.end] == hostname
        assert frame.info == frame.summary.info


def test_http_recovers_response_after_head_content_length(tmp_path):
    head = b"HEAD / HTTP/1.1\r\nHost: a\r\n\r\n"
    head_response = b"HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n"
    not_found = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    next_response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    response_start = 2001 + len(head_response)
    frames = _import(tmp_path, [
        _segment(80, 1001, head),
        _segment(80, 2001, head_response, reply=True),
        _segment(80, 1001 + len(head), b"GET /next HTTP/1.1\r\nHost: a\r\n\r\n"),
        _segment(80, response_start, not_found, reply=True),
        _segment(80, response_start + len(not_found), next_response[:8], reply=True),
        _segment(80, response_start + len(not_found) + 8, next_response[8:], reply=True),
    ])
    assert _matching_frames(frames, "http.response.code == 404") == [3]
    code = _fields(frames[3])["http.response.code"]
    assert frames[3].raw[code.offset:code.end] == b"404"
    assert _fields(frames[5])["http.response.code"].value == 200
    assert "tcp.reassembled" in _fields(frames[5])


def test_tls_recovers_complete_alert_after_a_missing_segment(tmp_path):
    data = _client_hello()
    alert = b"\x15\x03\x03\x00\x02\x02\x28"
    frames = _import(tmp_path, [
        _segment(443, 1000, flags="S"),
        _segment(443, 1001, data[:1000]),
        _segment(443, 1001 + len(data), alert),
    ])
    assert _matching_frames(frames, "tls.record.content_type == 21") == [2]
    content_type = _fields(frames[2])["tls.record.content_type"]
    assert frames[2].raw[content_type.offset:content_type.end] == b"\x15"


def test_tls_partial_client_hello_filters_only_on_the_completion_frame(tmp_path):
    data = _client_hello()
    frames = _import(tmp_path, [
        _segment(443, 1000, flags="S"),
        _segment(443, 1001, data[:1000]),
        _segment(443, 2001, data[1000:]),
    ])
    for expression in ("tls", 'app == "TLS"', "tls.handshake.type == 1"):
        assert _matching_frames(frames, expression) == [2]
    handshake = _fields(frames[1])["tls.handshake.type"]
    assert frames[1].raw[handshake.offset:handshake.end] == b"\x01"
    assert dissect_frame(frames[1]).at_byte(handshake.offset) == handshake
    assert _fields(frames[2])["tls.handshake.type"].length == 0


def test_http_partial_post_filters_only_on_the_completion_frame(tmp_path):
    first = b"POST /one HTTP/1.1\r\nHost: split."
    last = b"example\r\nContent-Length: 0\r\n\r\n"
    frames = _import(tmp_path, [
        _segment(80, 1001, first),
        _segment(80, 1001 + len(first), last),
    ])
    for expression in ("http", 'app == "HTTP"', 'http.request.method == "POST"', "http.host"):
        assert _matching_frames(frames, expression) == [1]
    host = _fields(frames[0])["http.host"]
    assert frames[0].raw[host.offset:host.end] == b"split."
    assert dissect_frame(frames[0]).at_byte(host.offset) == host
    assert _fields(frames[1])["http.host"].value == "split.example"


def test_tls_filters_a_complete_record_before_a_partial_record(tmp_path):
    alert = b"\x15\x03\x03\x00\x02\x02\x28"
    data = _client_hello()
    frames = _import(tmp_path, [
        _segment(443, 1001, alert + data[:1000]),
        _segment(443, 1001 + len(alert) + 1000, data[1000:]),
    ])
    assert _matching_frames(frames, "tls.record.content_type == 21") == [0]
    assert _matching_frames(frames, "tls.record.content_type == 22") == [1]
    assert _matching_frames(frames, "tls.handshake.type == 1") == [1]


def test_tls_flow_label_does_not_make_an_incomplete_record_match(tmp_path):
    alert = b"\x15\x03\x03\x00\x02\x02\x28"
    data = _client_hello()
    start = 1001 + len(alert)
    frames = _import(tmp_path, [
        _segment(443, 1001, alert),
        _segment(443, start, data[:3]),
        _segment(443, start + 3, data[3:]),
    ])
    assert frames[1].protocol == "TLS"
    assert _matching_frames(frames, "tls") == [0, 2]


def test_file_reassembles_tls_after_gap_and_keeps_first_segment_offsets(tmp_path):
    data = _client_hello()
    source = [
        _segment(443, 1000, flags="S"),
        _segment(443, 1001, data[:1000]),
        _segment(443, 2301, data[1300:]),
        _segment(443, 1001, data[:1000]),
        _segment(443, 2001, data[1000:1300]),
        _segment(443, 4001, b"\x17\x03\x03\x00", reply=True),
        _segment(443, 5000, flags="S"),
        _segment(443, 5001, b"other application"),
    ]
    frames = _import(tmp_path, source)
    first = _fields(frames[1])
    version = first["tls.handshake.version"]
    assert frames[1].raw[version.offset:version.end] == b"\x03\x03"
    assert "tls.record.truncated" in first
    expected = compile_filter('tls.handshake.extensions_server_name == "split.example"')
    assert [index for index, frame in enumerate(frames) if expected.matches(dissect_frame(frame))] == [4]
    result = _fields(frames[4])
    assert result["tls.handshake.extensions_server_name"].length == 0
    assert "tcp.reassembled" in result
    assert "SNI=split.example" in frames[4].info
    assert frames[5].protocol == "TLS"
    assert _fields(frames[5])["app.basis"].value == "TCP 流"
    assert frames[7].protocol == "TCP"
    assert "tls" not in _fields(frames[7])
    assert [item.raw for item in frames] == [item.raw for item in source]


def test_http_reassembles_headers_and_skips_fixed_length_body(tmp_path):
    body = b"GET /body HTTP/1.1\r\nHost: body.example\r\n\r\n"
    first = b"POST /one HTTP/1.1\r\nContent-Length: " + str(len(body)).encode() + b"\r\nHost: split."
    final = b"example\r\n\r\n"
    next_start = 1001 + len(first) + len(final) + len(body)
    frames = _import(tmp_path, [
        _segment(8080, 1001, first),
        _segment(8080, 1001 + len(first), final),
        _segment(8080, next_start - len(body), body),
        _segment(8080, next_start, b"GET /two HTTP/1.1\r\nHost: two"),
        _segment(8080, next_start + len(b"GET /two HTTP/1.1\r\nHost: two"), b".example\r\n\r\n"),
    ])
    assert _fields(frames[0])["http.host"].length == len(b"split.")
    assert _fields(frames[1])["http.host"].value == "split.example"
    assert frames[2].protocol == "HTTP"
    assert "http.host" not in _fields(frames[2])
    assert _fields(frames[4])["http.host"].value == "two.example"


def test_file_reassembles_dns_tcp_length_and_response(tmp_path):
    question = DNSQR(qname="dns.example")
    query = bytes(DNS(id=7, qd=question))
    response = bytes(DNS(id=7, qr=1, qd=question, an=DNSRR(rrname="dns.example", rdata="192.0.2.5")))
    query = pack("!H", len(query)) + query
    response = pack("!H", len(response)) + response
    frames = _import(tmp_path, [
        _segment(53, 1001, query[:1]),
        _segment(53, 1002, query[1:]),
        _segment(53, 2001, response[:-2], reply=True),
        _segment(53, 2001 + len(response) - 2, response[-2:], reply=True),
    ])
    assert _fields(frames[1])["dns.qry.name"].value == "dns.example"
    assert _fields(frames[2])["dns.qry.name"].length > 0
    assert _fields(frames[3])["dns.a"].value == "192.0.2.5"
    assert _fields(frames[3])["dns.a"].length == 0
    assert _matching_frames(frames, "dns.qry.name") == [1, 3]


def test_live_queue_reassembles_tls_record_header_split_across_packets():
    data = _client_hello()
    session = CaptureSession(CaptureSettings("test"))
    for frame in [_segment(443, 1001, data[:3]), _segment(443, 1004, data[3:])]:
        header = SimpleNamespace(caplen=len(frame.raw), len=frame.wire_length, ts=SimpleNamespace(tv_sec=1, tv_usec=0))
        session._receive(header, create_string_buffer(frame.raw), frame.linktype)
    first, last = session.drain()
    assert first.protocol == "TCP"
    assert last.protocol == "TLS"
    assert _fields(last)["tls.handshake.extensions_server_name"].value == "split.example"


def test_tls_hello_spans_both_records_and_tcp_segments(tmp_path):
    hello = _client_hello()[5:]
    first = b"\x16\x03\x03" + pack("!H", 3) + hello[:3]
    second = b"\x16\x03\x03" + pack("!H", len(hello) - 3) + hello[3:]
    split = 1200
    frames = _import(tmp_path, [
        _segment(443, 1001, first),
        _segment(443, 1001 + len(first), second[:split]),
        _segment(443, 1001 + len(first) + split, second[split:]),
    ])
    assert "tls.handshake.extensions_server_name" not in _fields(frames[0])
    assert "tls.handshake.extensions_server_name" not in _fields(frames[1])
    assert _fields(frames[2])["tls.handshake.extensions_server_name"].value == "split.example"
    assert "SNI=split.example" in frames[2].info
