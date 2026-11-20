from collections.abc import Sequence
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from tempfile import NamedTemporaryFile

from scapy.utils import RawPcapNgReader, RawPcapNgWriter, RawPcapReader, RawPcapWriter

from sniffer.model.packet import MAX_BYTES, MAX_PACKETS, PacketRecord

NANOSECONDS = 10**9
MAX_FRAME_BYTES = 262_144


@dataclass(frozen=True, slots=True)
class CapturePreview:
    records: list[PacketRecord]
    truncated: bool


def read_capture(path: Path) -> list[PacketRecord]:
    return read_capture_preview(path).records


def read_capture_preview(path: Path) -> CapturePreview:
    records = []
    stored_bytes = 0
    with RawPcapReader(str(path)) as reader:
        is_pcapng = isinstance(reader, RawPcapNgReader)
        while True:
            try:
                data, metadata = reader._read_packet(size=MAX_FRAME_BYTES)
            except EOFError:
                break
            stored_bytes += len(data)
            if len(records) >= MAX_PACKETS or stored_bytes > MAX_BYTES:
                return CapturePreview(records, truncated=True)
            if is_pcapng:
                linktype = metadata.linktype
                ticks = metadata.tshigh << 32 | metadata.tslow if metadata.tshigh is not None else None
                timestamp = Decimal(ticks) / metadata.tsresol if ticks is not None else None
            else:
                if metadata.caplen != len(data):
                    raise ValueError("文件中的帧已截断，或超过受支持的捕获长度。")
                linktype = reader.linktype
                resolution = NANOSECONDS if reader.nano else 10**6
                timestamp = Decimal(metadata.sec) + Decimal(metadata.usec) / resolution
            records.append(PacketRecord.from_bytes(timestamp, data, linktype, metadata.wirelen))
    return CapturePreview(records, truncated=False)


def write_capture(path: Path, records: Sequence[PacketRecord]) -> None:
    if not records:
        raise ValueError("没有可保存的包。")
    suffix = path.suffix.casefold()
    linktype = records[0].linktype
    if suffix == ".pcap":
        if any(record.linktype != linktype for record in records):
            raise ValueError("这份抓包含多种链路类型，请保存为 pcapng。")
        write_file = _write_pcap
    elif suffix == ".pcapng":
        write_file = _write_pcapng
    else:
        raise ValueError("请选择 .pcap 或 .pcapng 文件。")

    # 先写同目录临时文件，成功后再替换目标。写入失败时保留原文件。
    with NamedTemporaryFile(dir=path.parent, prefix=".netsniffer-", delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        write_file(temporary_path, records, linktype)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _write_pcap(path: Path, records: Sequence[PacketRecord], linktype: int) -> None:
    with RawPcapWriter(str(path), linktype=linktype, nano=True, snaplen=MAX_FRAME_BYTES) as writer:
        writer.linktype = linktype
        writer.write_header(records[0].raw)
        for record in records:
            seconds, nanoseconds = divmod(int((record.timestamp or 0) * NANOSECONDS), NANOSECONDS)
            writer.write_packet(
                record.raw, sec=seconds, usec=nanoseconds, wirelen=record.wire_length
            )


def _write_pcapng(path: Path, records: Sequence[PacketRecord], linktype: int) -> None:
    with RawPcapNgWriter(str(path)) as writer:
        writer.linktype = linktype
        writer.write_header(records[0].raw)
        for record in records:
            # Scapy 按接口名分配 IDB，给不同的链路类型分配单独的逻辑接口。
            ifname = None if record.linktype == linktype else f"Link type {record.linktype}".encode()
            writer._write_packet(
                record.raw, record.linktype, sec=record.timestamp or 0,
                wirelen=record.wire_length, ifname=ifname,
            )
