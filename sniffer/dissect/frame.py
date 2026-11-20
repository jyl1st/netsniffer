from decimal import Decimal

from sniffer.dissect.app_detect import parse_quic, parse_ssh
from sniffer.dissect.dhcp import parse_dhcp
from sniffer.dissect.dns import parse_dns, parse_dns_tcp, parse_mdns
from sniffer.dissect.ethernet import parse_arp, parse_ethernet, parse_loopback, parse_raw_ip
from sniffer.dissect.field import Field, Span
from sniffer.dissect.http import parse_http, parse_ssdp
from sniffer.dissect.ip import parse_ipv4, parse_ipv6
from sniffer.dissect.ntp import parse_ntp
from sniffer.dissect.registry import Registry
from sniffer.dissect.tls import parse_tls
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
        ("http", parse_http), ("tls", parse_tls), ("dhcp", parse_dhcp),
        ("ssdp", parse_ssdp), ("ntp", parse_ntp), ("ssh", parse_ssh), ("quic", parse_quic),
    ):
        registry.register("app", key, parser)
    return registry


REGISTRY = _build_registry()


def dissect_frame(
    record: PacketRecord, number: int = 1, previous_time: Decimal | None = None,
    *, registry: Registry = REGISTRY,
) -> Field:
    span = Span(record.raw, 0, len(record.raw))
    children = [
        span.field("frame.number", "编号", number, 0, 0),
        span.field("frame.len", "线上长度", record.wire_length, 0, 0),
        span.field("frame.cap_len", "捕获长度", len(span), 0, 0),
    ]
    if record.timestamp is not None:
        children.append(span.field("frame.time", "捕获时刻（Unix 秒）", record.timestamp, 0, 0))
        if previous_time is not None:
            children.append(span.field("frame.time_delta", "距上一包（秒）", record.timestamp - previous_time, 0, 0))
    children.append(registry.dispatch("link", record.linktype, span))
    return span.layer("frame", f"帧 {number} · 捕获 {len(span)} 字节", children)
