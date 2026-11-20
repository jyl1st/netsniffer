from pathlib import Path

import pytest

from sniffer.capture import pcap_io
from sniffer.capture.pcap_io import read_capture, write_capture
from sniffer.model.packet import LINKTYPE_NULL, PacketRecord

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "tcp_http.pcap"


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_round_trip_preserves_frames_timing_and_summary(tmp_path, suffix):
    records = read_capture(SAMPLE)
    assert len(records) == 6
    assert records[0].summary.protocol == "TCP"
    assert records[0].summary.source == "192.0.2.10"
    assert "[SYN]" in records[0].summary.info

    target = tmp_path / f"测试抓包{suffix}"
    write_capture(target, records)
    assert read_capture(target) == records


def test_pcapng_preserves_mixed_link_types(tmp_path):
    ethernet = read_capture(SAMPLE)[0]
    loopback = PacketRecord.from_bytes(
        ethernet.timestamp, b"\x02\x00\x00\x00" + ethernet.raw[14:],
        LINKTYPE_NULL, ethernet.wire_length - 10,
    )
    records = [loopback, ethernet, loopback]
    target = tmp_path / "mixed.pcapng"
    write_capture(target, records)
    assert read_capture(target) == records

    pcap = tmp_path / "mixed.pcap"
    pcap.write_bytes(b"existing file")
    with pytest.raises(ValueError, match="多种链路类型"):
        write_capture(pcap, records)
    assert pcap.read_bytes() == b"existing file"


@pytest.mark.parametrize("suffix", [".pcap", ".pcapng"])
def test_capture_preview_stops_at_the_first_frame_beyond_the_limit(tmp_path, monkeypatch, suffix):
    records = read_capture(SAMPLE)
    target = tmp_path / f"preview{suffix}"
    write_capture(target, records)

    monkeypatch.setattr(pcap_io, "MAX_PACKETS", len(records))
    exact = pcap_io.read_capture_preview(target)
    assert exact.records == records
    assert not exact.truncated

    monkeypatch.setattr(pcap_io, "MAX_PACKETS", 3)
    preview = pcap_io.read_capture_preview(target)
    assert preview.records == records[:3]
    assert preview.truncated

    monkeypatch.setattr(pcap_io, "MAX_PACKETS", len(records))
    monkeypatch.setattr(pcap_io, "MAX_BYTES", sum(len(record.raw) for record in records[:2]))
    preview = pcap_io.read_capture_preview(target)
    assert preview.records == records[:2]
    assert preview.truncated
