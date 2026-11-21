import re
from dataclasses import dataclass

from sniffer.dissect.dhcp import dhcp_info
from sniffer.dissect.dns import dns_info
from sniffer.dissect.field import Field, ParseError, Span
from sniffer.dissect.http import http_info
from sniffer.dissect.ntp import ntp_info
from sniffer.dissect.quic import quic_long_header
from sniffer.dissect.registry import Registry
from sniffer.dissect.tls import tls_info, tls_record_header

TCP_PORTS = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "TLS", 8000: "HTTP", 8080: "HTTP", 8443: "TLS"}
UDP_PORTS = {53: "DNS", 67: "DHCP", 68: "DHCP", 123: "NTP", 1900: "SSDP", 5353: "mDNS"}
SSH_BANNER = re.compile(rb"SSH-(?:2\.0|1\.(?:99|5))-[!-~]+(?: [ -~]*)?\r?")


@dataclass(frozen=True, slots=True)
class Application:
    protocol: str | None
    basis: str
    info: str
    hinted_protocol: str | None = None


def identify_application(
    raw: bytes, start: int, end: int, transport: int, source: int, destination: int,
) -> Application | None:
    if start >= end:
        return None

    first = raw[start]
    if transport == 6:
        # 强特征不依赖端口。HTTP 要通过首行语法，TLS 要通过整个记录头的检查。
        if 65 <= first <= 90:
            summary = http_info(raw, start, end)
            if summary:
                return Application("HTTP", "内容特征", summary)
        if 20 <= first <= 24:
            header = tls_record_header(raw, start, end)
            if header is not None:
                kind, _, length = header
                return Application("TLS", "内容特征", tls_info(raw, start, end, kind, length))
        if first == 83:
            banner = _ssh_banner(raw, start, end)
            if banner:
                return Application("SSH", "内容特征", banner)
        port_table = TCP_PORTS
    else:
        port_table = UDP_PORTS

    destination_hint = port_table.get(destination)
    source_hint = port_table.get(source)
    if destination_hint or source_hint:
        span = Span(raw, start, end)
        for hint in (destination_hint, source_hint if source_hint != destination_hint else None):
            if hint is not None:
                summary = _validated_summary(span, hint, tcp=transport == 6)
                if summary is not None:
                    return Application(hint, "端口（内容已校验）", summary)
        port, hint = (destination, destination_hint) if destination_hint else (source, source_hint)
        # 这些 UDP 服务端口无论内容检查结果如何，都不参与弱 QUIC 检测。
        return _rejected(port, hint)

    if transport == 17 and (first & 0x80 or source == 443 or destination == 443):
        on_443 = source == 443 or destination == 443
        quic = quic_long_header(raw, start, end, on_443=on_443)
        if quic is not None:
            return Application("QUIC", "弱特征", f"{quic.kind} · 版本 0x{quic.version:08x}")
        if on_443:
            return _rejected(443, "QUIC")
    return None


def _validated_summary(span: Span, protocol: str, *, tcp: bool) -> str | None:
    if protocol in ("DNS", "mDNS"):
        return dns_info(span, tcp=tcp)
    if protocol == "SSDP":
        return http_info(span.raw, span.start, span.end, ssdp=True)
    if protocol == "DHCP":
        return dhcp_info(span)
    if protocol == "NTP":
        return ntp_info(span)
    # TCP 端口表中的 HTTP/TLS/SSH 与上方强特征使用相同的最小必要语法。
    return None


def _rejected(port: int, protocol: str) -> Application:
    return Application(None, "", f"端口 {port} 常见于 {protocol}，但内容不符", protocol)


def _ssh_banner(raw: bytes, start: int, end: int) -> str | None:
    if not raw.startswith(b"SSH-", start, end):
        return None
    line_end = raw.find(b"\n", start, min(start + 255, end))
    if line_end < 0 or SSH_BANNER.fullmatch(raw, start, line_end) is None:
        return None
    return raw[start:line_end].decode("ascii").rstrip("\r")


def dissect_application(
    span: Span, registry: Registry, transport: int, source: int, destination: int,
) -> Field:
    identified = identify_application(span.raw, span.start, span.end, transport, source, destination)
    if identified is None:
        return span.payload(name="tcp.payload" if transport == 6 else "udp.payload")
    if identified.protocol is None:
        return _unconfirmed(span, registry, transport, identified)
    name, basis = identified.protocol, identified.basis
    key = "dns_tcp" if name == "DNS" and transport == 6 else name.casefold()
    details = registry.dispatch("app", key, span)
    fields = [
        span.field("app", "应用协议", name, 0, 0),
        span.field("app.basis", "识别依据", basis, 0, 0),
        details,
    ]
    return span.layer("application", f"应用识别 · {name}（{basis}）", fields, filterable=details.filterable)


def _unconfirmed(span: Span, registry: Registry, transport: int, result: Application) -> Field:
    fields = [span.payload()]
    if result.hinted_protocol == "HTTP":
        fields.insert(0, span.field("app.invalid_http", "不是有效的 HTTP 首行", None, 0, 0))
    if (transport == 6 and result.hinted_protocol == "DNS" and len(span) >= 2
            and span.uint(0, 2) >= 12 and span.uint(0, 2) > len(span) - 2):
        fields = [registry.dispatch("app", "dns_tcp", span)]
    if span.capture_truncated and transport == 17 and result.hinted_protocol in ("DNS", "mDNS", "DHCP", "NTP"):
        fields = [registry.dispatch("app", result.hinted_protocol.casefold(), span)]
    return span.layer("app.port_hint", result.info, fields)


def parse_ssh(span: Span, _registry, _network) -> Field:
    banner = _ssh_banner(span.raw, span.start, span.end)
    if banner is None:
        raise ParseError("不是有效的 SSH 版本横幅")
    return span.layer("ssh", "SSH 标识", [span.field("ssh.banner", "版本横幅", banner, 0, len(banner))])
