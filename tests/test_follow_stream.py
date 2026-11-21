from pathlib import Path

from scapy.all import DNS

from samples.make_samples import HTTP_REQUEST, HTTP_RESPONSE, dns_packets, tcp_segment
from sniffer.analysis.follow import StreamChunk, assemble_stream, endpoint_label
from sniffer.analysis.streams import StreamIndex
from sniffer.capture.pcap_io import read_capture
from sniffer.gui.dialogs.follow_stream import _format_chunk, _save_stream
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _records(packets):
    index = StreamIndex()
    records = []
    for packet in packets:
        raw = bytes(packet)
        records.append(PacketRecord.from_bytes(None, raw, LINKTYPE_ETHERNET, len(raw)).with_stream(index))
    return records


def test_follow_tcp_restores_http_in_both_directions_without_the_retransmission():
    records = read_capture(SAMPLES / "tcp_retransmission.pcap")
    stream = assemble_stream(records, "tcp", 0)
    assert [endpoint_label(endpoint) for endpoint in stream.endpoints] == [
        "192.0.2.10:49152", "192.0.2.20:8080",
    ]
    assert [(chunk.direction, bytes(chunk.data)) for chunk in stream.chunks] == [
        (0, HTTP_REQUEST), (1, HTTP_RESPONSE),
    ]


def test_follow_tcp_orders_wrapped_sequences_and_preserves_first_overlap_and_gap():
    frames = _records([
        tcp_segment(8080, "S", 0xfffffffc),
        tcp_segment(8080, "PA", 0) / b"DEF",
        tcp_segment(8080, "PA", 2001, reply=True) / b"reply",
        tcp_segment(8080, "PA", 0xfffffffd) / b"abcXX",
        tcp_segment(8080, "PA", 5) / b"end",
    ])
    chunks = assemble_stream(frames, "tcp", 0).chunks
    assert [chunk.direction for chunk in chunks] == [1, 0, 0, 0, 0]
    assert [bytes(chunk.data) for chunk in chunks] == [b"reply", b"abc", b"DEF", b"", b"end"]
    assert [(chunk.offset, chunk.missing) for chunk in chunks if chunk.missing] == [(6, 2)]


def test_follow_tcp_handles_four_tuple_reuse_without_merging_sequence_spaces():
    frames = _records([
        tcp_segment(8080, "S", 1000),
        tcp_segment(8080, "PA", 1001) / b"first",
        tcp_segment(8443, "PA", 1001) / b"different stream",
        tcp_segment(8080, "S", 100000),
        tcp_segment(8080, "PA", 100001) / b"next",
    ])
    chunks = assemble_stream(frames, "tcp", 0).chunks
    assert [(bytes(chunk.data), chunk.offset, chunk.missing) for chunk in chunks] == [
        (b"first", 0, 0), (b"next", 0, 0),
    ]
    assert [bytes(chunk.data) for chunk in assemble_stream(frames, "tcp", 1).chunks] == [b"different stream"]


def test_follow_udp_keeps_datagrams_and_selects_protocol_as_well_as_stream_number():
    query, response = dns_packets()
    frames = _records([query, tcp_segment(8080, "PA", 1001) / HTTP_REQUEST, query, response])
    stream = assemble_stream(frames, "udp", 0)
    assert [chunk.direction for chunk in stream.chunks] == [0, 0, 1]
    assert [bytes(chunk.data) for chunk in stream.chunks] == [
        bytes(query[DNS]), bytes(query[DNS]), bytes(response[DNS]),
    ]


def test_follow_raw_save_preserves_bytes_and_text_formats_show_gaps(tmp_path):
    outgoing = StreamChunk(0, 0, memoryview(b"A\r\n\x00\xff"))
    gap = StreamChunk(0, 5, memoryview(b""), 20)
    incoming = StreamChunk(1, 0, memoryview(b"B\x01"))
    assert _format_chunk(outgoing, "ascii") == "A\r\n.."
    assert _format_chunk(outgoing, "raw") == r"A\r\n\x00\xff"
    assert _format_chunk(outgoing, "hex").startswith("00000000  41 0D 0A 00 FF")

    labels = ("A to B", "B to A")
    raw = tmp_path / "stream.bin"
    _save_stream(raw, (outgoing, gap, incoming), labels, "raw")
    assert raw.read_bytes() == b"A\r\n\x00\xffB\x01"
    _save_stream(raw, (incoming,), labels, "raw")
    assert raw.read_bytes() == b"B\x01"

    text = tmp_path / "stream.txt"
    _save_stream(text, (outgoing, gap, incoming), labels, "hex")
    contents = text.read_text(encoding="utf-8")
    assert contents.index("[A to B]") < contents.index("缺少 20 字节") < contents.index("[B to A]")
    assert "41 0D 0A 00 FF" in contents and "42 01" in contents
