from dataclasses import dataclass

from sniffer.dissect.field import Field, ParseError, Span
from sniffer.dissect.registry import Registry

HTTP_PREFIXES = (
    b"HTTP/1.", b"GET ", b"POST ", b"HEAD ", b"PUT ", b"PATCH ", b"DELETE ",
    b"OPTIONS ", b"CONNECT ", b"TRACE ",
)
TCP_PORTS = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "TLS", 8000: "HTTP", 8080: "HTTP", 8443: "TLS"}
UDP_PORTS = {53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 443: "QUIC", 1900: "SSDP", 5353: "mDNS"}


@dataclass(frozen=True, slots=True)
class Application:
    protocol: str
    basis: str


def identify_application(
    raw: bytes, start: int, end: int, transport: int, source: int, destination: int,
) -> Application | None:
    if start >= end:
        return None
    first = raw[start]
    if transport == 6:
        if first in b"HGPDOCT" and raw.startswith(HTTP_PREFIXES, start, end):
            return Application("HTTP", "内容特征")
        if first in (20, 21, 22, 23, 24) and end - start >= 5 and raw[start + 1] == 3 and raw[start + 2] <= 4:
            return Application("TLS", "内容特征")
        if first == 83 and raw.startswith(b"SSH-", start, end):
            return Application("SSH", "内容特征")
        known_ports = TCP_PORTS
    else:
        if first in (77, 78) and raw.startswith((b"M-SEARCH ", b"NOTIFY "), start, end):
            return Application("SSDP", "内容特征")
        if end - start >= 240 and raw.startswith(b"\x63\x82\x53\x63", start + 236, end):
            return Application("DHCP", "内容特征")
        if first & 0xC0 == 0xC0 and _quic_long_header(raw, start, end):
            return Application("QUIC", "内容特征")
        known_ports = UDP_PORTS
    protocol = known_ports.get(destination) or known_ports.get(source)
    return Application(protocol, "端口") if protocol else None


def _quic_long_header(raw: bytes, start: int, end: int) -> bool:
    if end - start < 7 or raw[start + 1:start + 5] == b"\0" * 4:
        return False
    destination_length = raw[start + 5]
    source_length_at = start + 6 + destination_length
    if destination_length > 20 or source_length_at >= end:
        return False
    source_length = raw[source_length_at]
    return source_length <= 20 and source_length_at + 1 + source_length < end


def dissect_application(
    span: Span, registry: Registry, transport: int, source: int, destination: int,
) -> Field:
    identified = identify_application(span.raw, span.start, span.end, transport, source, destination)
    if identified is None:
        return span.payload(name="tcp.payload" if transport == 6 else "udp.payload")

    name, basis = identified.protocol, identified.basis
    key = "dns_tcp" if name == "DNS" and transport == 6 else name.casefold()
    fields = [
        span.field("app", "应用协议", name, 0, 0),
        span.field("app.basis", "识别依据", basis, 0, 0),
        registry.dispatch("app", key, span),
    ]
    return span.layer("application", f"应用识别 · {name}（{basis}）", fields)


def parse_ssh(span: Span, _registry, _network) -> Field:
    if not span.raw.startswith(b"SSH-", span.start, span.end):
        return span.layer("ssh", "SSH 数据", [span.payload()])
    end = span.raw.find(b"\n", span.start, min(span.start + 255, span.end))
    size = end - span.start + 1 if end >= 0 else min(len(span), 255)
    banner = span.bytes(0, size).decode("ascii", "replace").rstrip("\r\n")
    return span.layer("ssh", "SSH 标识", [span.field("ssh.banner", "版本横幅", banner, 0, size)])


def parse_quic(span: Span, _registry, _network) -> Field:
    flags = span.uint(0)
    fields = [span.number("quic.flags", "首字节", 0, hexadecimal=True)]
    if flags & 0x80:
        fields.append(span.number("quic.version", "版本", 1, 4, hexadecimal=True))
        size = span.uint(5)
        if size > 20:
            raise ParseError("QUIC 连接标识长度超过 20")
        fields.append(span.field("quic.dcid", "目标连接标识", span.bytes(6, size).hex(), 6, size))
        cursor = 6 + size
        size = span.uint(cursor)
        if size > 20:
            raise ParseError("QUIC 连接标识长度超过 20")
        fields.append(span.field("quic.scid", "源连接标识", span.bytes(cursor + 1, size).hex(), cursor + 1, size))
        cursor += 1 + size
    else:
        cursor = 1
    if cursor < len(span):
        fields.append(span.payload(cursor, label="QUIC 剩余数据"))
    return span.layer("quic", "QUIC 长报头" if flags & 0x80 else "QUIC 短报头", fields)
