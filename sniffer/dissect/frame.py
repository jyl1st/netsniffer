from dataclasses import replace
from decimal import Decimal

from sniffer.analysis.tcp import TcpApplication
from sniffer.dissect.app_detect import parse_ssh
from sniffer.dissect.dhcp import parse_dhcp
from sniffer.dissect.dns import parse_dns, parse_dns_tcp, parse_mdns
from sniffer.dissect.ethernet import parse_arp, parse_ethernet, parse_loopback, parse_raw_ip
from sniffer.dissect.field import Field, Span
from sniffer.dissect.http import parse_http, parse_ssdp
from sniffer.dissect.ip import parse_ipv4, parse_ipv6
from sniffer.dissect.ntp import parse_ntp
from sniffer.dissect.quic import parse_quic
from sniffer.dissect.registry import Registry
from sniffer.dissect.tls import parse_tls, parse_tls_handshake
from sniffer.dissect.transport import parse_icmp, parse_icmpv6, parse_tcp, parse_udp
from sniffer.model.packet import (
    LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_LOOP, LINKTYPE_NULL, LINKTYPE_RAW,
    PacketRecord,
)


def _build_registry() -> Registry:
    registry = Registry()
    for key, parser in (
        (LINKTYPE_ETHERNET, parse_ethernet), (LINKTYPE_NULL, parse_loopback),
        (LINKTYPE_LOOP, parse_loopback), (LINKTYPE_RAW, parse_raw_ip),
        (LINKTYPE_IPV4, parse_ipv4), (LINKTYPE_IPV6, parse_ipv6),
    ):
        registry.register("link", key, parser)
    for key, parser in ((0x0800, parse_ipv4), (0x0806, parse_arp), (0x86DD, parse_ipv6)):
        registry.register("ether", key, parser)
    for key, parser in ((1, parse_icmp), (6, parse_tcp), (17, parse_udp), (58, parse_icmpv6)):
        registry.register("ip", key, parser)
    for key, parser in (
        ("dns", parse_dns), ("dns_tcp", parse_dns_tcp), ("mdns", parse_mdns),
        ("http", parse_http), ("tls", parse_tls), ("tls_handshake", parse_tls_handshake), ("dhcp", parse_dhcp),
        ("ssdp", parse_ssdp), ("ntp", parse_ntp), ("ssh", parse_ssh), ("quic", parse_quic),
    ):
        registry.register("app", key, parser)
    return registry


REGISTRY = _build_registry()


def dissect_frame(
    record: PacketRecord, number: int = 1, previous_time: Decimal | None = None,
    *, registry: Registry = REGISTRY,
) -> Field:
    span = Span(record.raw, 0, len(record.raw), len(record.raw) < record.wire_length)
    children = [
        span.field("frame.number", "编号", number, 0, 0),
        span.field("frame.len", "线上长度", record.wire_length, 0, 0),
        span.field("frame.cap_len", "捕获长度", len(span), 0, 0),
    ]
    if record.timestamp is not None:
        children.append(span.field("frame.time", "捕获时刻（Unix 秒）", record.timestamp, 0, 0))
        if previous_time is not None:
            children.append(span.field("frame.time_delta", "距上一包（秒）", record.timestamp - previous_time, 0, 0))
    if record.stream_id is not None and record.summary.flow is not None:
        protocol = record.summary.flow.protocol
        children.append(span.field(f"{protocol}.stream", f"{protocol.upper()} 流编号", record.stream_id, 0, 0))
    for owner in record.process_owners:
        fields = [span.field("proc.pid", "PID", owner.pid, 0, 0)]
        if owner.name is not None:
            fields.append(span.field("proc.name", "进程名", owner.name, 0, 0))
        children.append(Field("proc", f"进程 · {owner.label}", None, 0, 0, tuple(fields)))
    link = registry.dispatch("link", record.linktype, span)
    application = record.tcp_application
    if application is not None:
        if not application.keep_local_fields:
            link = _tcp_payload_only(link)
        children.append(_tcp_application(application, registry))
    children.append(link)
    return span.layer("frame", f"帧 {number} · 捕获 {len(span)} 字节", children)


def _tcp_payload_only(field: Field) -> Field:
    # 传输层是链路与 IP 字段树的最后一个子节点。
    if not field.children:
        return field
    last = field.children[-1]
    if field.name == "tcp" and last.name in ("application", "app.port_hint"):
        payload = Field("tcp.payload", f"TCP 负载（{last.length} 字节）", None, last.offset, last.length)
        return replace(field, children=(*field.children[:-1], payload))
    if field.name in ("eth", "null", "ip", "ipv6"):
        updated = _tcp_payload_only(last)
        if updated is not last:
            return replace(field, children=(*field.children[:-1], updated))
    return field


def _tcp_application(application: TcpApplication, registry: Registry) -> Field:
    protocol = application.protocol.casefold()
    basis = "TCP 重组" if application.messages else "TCP 流"
    fields = [
        Field("app", f"应用协议: {application.protocol}", application.protocol, 0, 0),
        Field("app.basis", f"识别依据: {basis}", basis, 0, 0),
    ]
    if application.messages:
        for message in application.messages:
            tree = registry.dispatch("app", message.parser, Span(message.data, 0, len(message.data)))
            fields.append(_generated(tree))
        return Field("tcp.reassembled", f"TCP 重组 · {application.protocol}", None, 0, 0, tuple(fields))
    fields.append(Field(protocol, application.protocol, None, 0, 0))
    return Field(
        "application", f"应用识别 · {application.protocol}（{basis}）", None, 0, 0, tuple(fields),
        filterable=protocol not in ("dns", "http", "tls"),
    )


def _generated(field: Field) -> Field:
    # 重组字段可能横跨任意多帧，当前帧没有可高亮的连续字节范围。
    return replace(field, offset=0, length=0, children=tuple(_generated(child) for child in field.children))
