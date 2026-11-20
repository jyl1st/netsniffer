from ipaddress import ip_address

from sniffer.dissect.field import Field, Span, partial_header
from sniffer.dissect.registry import Registry

VLAN_TYPES = {0x8100, 0x88A8, 0x9100}


def parse_ethernet(span: Span, registry: Registry, _network) -> Field:
    if len(span) < 14:
        return partial_header(span, "eth", "Ethernet II", 14, (
            ("eth.dst", "目标 MAC", 0, 6, "mac"),
            ("eth.src", "源 MAC", 6, 6, "mac"),
        ))
    destination = span.bytes(0, 6).hex(":")
    source = span.bytes(6, 6).hex(":")
    ether_type = span.uint(12, 2)
    fields = [
        span.field("eth.dst", "目标 MAC", destination, 0, 6),
        span.field("eth.src", "源 MAC", source, 6, 6),
        span.number("eth.type", "以太类型", 12, 2, hexadecimal=True),
    ]
    cursor = 14
    # 每个 VLAN 标签包含 TCI 和内层 EtherType，之后还能继续套标签。
    while ether_type in VLAN_TYPES and cursor < 46:
        if len(span) - cursor < 4:
            fields.append(span.missing("vlan.incomplete", cursor + 4 - len(span)))
            return span.layer("eth", f"Ethernet II · {source} → {destination}", fields)
        tag = span.sub(cursor, 4)
        tci = tag.uint(0, 2)
        ether_type = tag.uint(2, 2)
        fields.append(tag.layer("vlan", "802.1Q VLAN", [
            tag.field("vlan.priority", "优先级", tci >> 13, 0, 2),
            tag.field("vlan.dei", "丢弃优先", bool(tci & 0x1000), 0, 2),
            tag.field("vlan.id", "VLAN ID", tci & 0x0FFF, 0, 2),
            tag.number("vlan.etype", "封装类型", 2, 2, hexadecimal=True),
        ]))
        cursor += 4
    if cursor < len(span) or ether_type in (0x0800, 0x0806, 0x86DD):
        fields.append(registry.dispatch("ether", ether_type, span.sub(cursor)))
    return span.layer("eth", f"Ethernet II · {source} → {destination}", fields)


def parse_arp(span: Span, _registry, _network) -> Field:
    if len(span) < 8:
        return partial_header(span, "arp", "ARP", 8, (
            ("arp.hw.type", "硬件类型", 0, 2),
            ("arp.proto.type", "协议类型", 2, 2, "hex"),
            ("arp.hw.size", "硬件地址长度", 4, 1),
            ("arp.proto.size", "协议地址长度", 5, 1),
        ))
    _, protocol, hardware_size, protocol_size, operation = span.unpack("!HHBBH", 0)
    size = 8 + 2 * (hardware_size + protocol_size)
    section = span.sub(0, min(size, len(span)))
    fields = [
        span.number("arp.hw.type", "硬件类型", 0, 2),
        span.number("arp.proto.type", "协议类型", 2, 2, hexadecimal=True),
        span.number("arp.hw.size", "硬件地址长度", 4),
        span.number("arp.proto.size", "协议地址长度", 5),
        span.number("arp.opcode", "操作码", 6, 2),
    ]
    cursor = 8
    for direction, label in (("src", "发送方"), ("dst", "目标")):
        if cursor + hardware_size > len(section):
            break
        address = span.bytes(cursor, hardware_size).hex(":")
        fields.append(span.field(f"arp.{direction}.hw_mac", f"{label}硬件地址", address, cursor, hardware_size))
        cursor += hardware_size
        if cursor + protocol_size > len(section):
            break
        raw = span.bytes(cursor, protocol_size)
        is_ipv4 = protocol == 0x0800 and protocol_size == 4
        value = str(ip_address(raw)) if is_ipv4 else raw.hex(":")
        suffix = "proto_ipv4" if is_ipv4 else "proto"
        fields.append(span.field(f"arp.{direction}.{suffix}", f"{label}协议地址", value, cursor, protocol_size))
        cursor += protocol_size
    if len(section) < size:
        fields.append(section.missing("arp.incomplete", size - len(section)))
    description = {1: "请求", 2: "应答"}.get(operation, str(operation))
    return section.layer("arp", f"ARP · {description}", fields)


def parse_raw_ip(span: Span, registry: Registry, _network) -> Field:
    version = span.uint(0) >> 4
    if version in (4, 6):
        return registry.dispatch("ether", 0x0800 if version == 4 else 0x86DD, span)
    return span.payload(label=f"未知 IP 版本 {version}")


def parse_loopback(span: Span, registry: Registry, network) -> Field:
    if len(span) < 4:
        return partial_header(span, "null", "回环链路", 4, ())
    encoded = span.bytes(0, 4)
    # Npcap 的 DLT_NULL 使用主机字节序，DLT_LOOP 使用网络字节序。
    little = int.from_bytes(encoded, "little")
    big = int.from_bytes(encoded, "big")
    family = little if little < big else big
    fields = [span.field("null.family", "地址族", family, 0, 4)]
    if len(span) > 4:
        fields.append(parse_raw_ip(span.sub(4), registry, network))
    else:
        fields.append(span.missing("null.incomplete", 1))
    return span.layer("null", "回环链路", fields)
