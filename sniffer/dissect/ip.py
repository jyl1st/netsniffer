from ipaddress import ip_address

from sniffer.dissect.checksum import checksum_field, checksum_valid
from sniffer.dissect.field import Field, ParseError, Span, partial_header
from sniffer.dissect.registry import IPContext, Registry

IPV6_EXTENSIONS = {
    0: "逐跳选项", 43: "路由", 44: "分片", 51: "认证", 60: "目的选项",
}


def parse_ipv4(span: Span, registry: Registry, _network) -> Field:
    if len(span) < 20:
        return partial_header(span, "ip", "IPv4", 20, (
            ("ip.len", "总长度", 2, 2), ("ip.id", "标识", 4, 2, "hex"),
            ("ip.ttl", "生存时间", 8, 1), ("ip.proto", "协议号", 9, 1),
            ("ip.checksum", "校验和", 10, 2, "hex"), ("ip.src", "源地址", 12, 4, "ip"),
        ))
    version_and_length, dscp, total_length, _, fragment, _, proto = span.unpack("!BBHHHBB", 0)
    header_length = (version_and_length & 15) * 4
    if version_and_length >> 4 != 4 or header_length < 20 or total_length < header_length:
        raise ParseError("IPv4 版本或长度字段异常")
    section = span.sub(0, min(total_length, len(span)))
    source, destination = span.bytes(12, 4), span.bytes(16, 4)
    src, dst = str(ip_address(source)), str(ip_address(destination))
    fields = [
        span.field("ip.version", "版本", 4, 0, 1),
        span.field("ip.hdr_len", "报头长度", header_length, 0, 1),
        span.field("ip.dsfield.dscp", "DSCP", dscp >> 2, 1, 1),
        span.field("ip.dsfield.ecn", "ECN", dscp & 3, 1, 1),
        span.number("ip.len", "总长度", 2, 2),
        span.number("ip.id", "标识", 4, 2, hexadecimal=True),
        span.field("ip.flags.rb", "保留位", bool(fragment & 0x8000), 6, 2),
        span.field("ip.flags.df", "禁止分片", bool(fragment & 0x4000), 6, 2),
        span.field("ip.flags.mf", "还有分片", bool(fragment & 0x2000), 6, 2),
        span.field("ip.frag_offset", "分片偏移（字节）", (fragment & 0x1FFF) * 8, 6, 2),
        span.number("ip.ttl", "生存时间", 8),
        span.number("ip.proto", "协议号", 9),
        checksum_field(span, "ip.checksum", 10, checksum_valid(span.bytes(0, header_length)) if header_length <= len(span) else None),
        span.field("ip.src", "源地址", src, 12, 4),
        span.field("ip.dst", "目标地址", dst, 16, 4),
    ]
    fields.extend(_ipv4_options(section.sub(20, min(header_length, len(section)) - 20)))
    if total_length > len(span):
        fields.append(span.missing("ip.truncated", total_length - len(span)))
    if header_length > len(section):
        return section.layer("ip", f"IPv4 · {src} → {dst}", fields)
    payload = section.sub(header_length)
    if fragment & 0x1FFF:
        fields.append(payload.payload(label="IPv4 后续分片"))
    elif len(payload):
        complete = not (fragment & 0x2000) and total_length <= len(span)
        fields.append(registry.dispatch("ip", proto, payload, IPContext(4, source, destination, complete)))
    return section.layer("ip", f"IPv4 · {src} → {dst}", fields)


def _ipv4_options(options: Span) -> list[Field]:
    fields = []
    cursor = 0
    while cursor < len(options):
        kind = options.uint(cursor)
        if kind not in (0, 1) and len(options) - cursor < 2:
            fields.append(options.missing("ip.option.incomplete", cursor + 2 - len(options)))
            break
        length = 1 if kind in (0, 1) else options.uint(cursor + 1)
        if kind not in (0, 1) and length < 2:
            fields.append(options.payload(cursor, label="IPv4 选项长度小于 2"))
            break
        if cursor + length > len(options):
            fields.append(options.missing("ip.option.incomplete", cursor + length - len(options)))
            break
        option = options.sub(cursor, length)
        fields.append(option.layer("ip.option", f"IPv4 选项 {kind}", [
            option.number("ip.option.type", "类型", 0),
            *([option.payload(2, label="选项数据")] if length > 2 else []),
        ], kind))
        if kind == 0:
            break
        cursor += length
    return fields


def parse_ipv6(span: Span, registry: Registry, _network) -> Field:
    if len(span) < 40:
        return partial_header(span, "ipv6", "IPv6", 40, (
            ("ipv6.plen", "负载长度", 4, 2), ("ipv6.nxt", "下一个报头", 6, 1),
            ("ipv6.hlim", "跳数限制", 7, 1), ("ipv6.src", "源地址", 8, 16, "ip"),
        ))
    first_word, payload_length, next_header, _ = span.unpack("!IHBB", 0)
    if first_word >> 28 != 6:
        raise ParseError("IPv6 版本字段异常")
    source, destination = span.bytes(8, 16), span.bytes(24, 16)
    src, dst = str(ip_address(source)), str(ip_address(destination))
    section = span.sub(0, min(40 + payload_length, len(span)))
    fields = [
        span.field("ipv6.version", "版本", 6, 0, 1),
        span.field("ipv6.tclass", "流量类别", (first_word >> 20) & 0xFF, 0, 2),
        span.field("ipv6.flow", "流标签", first_word & 0xFFFFF, 1, 3),
        span.number("ipv6.plen", "负载长度", 4, 2),
        span.number("ipv6.nxt", "下一个报头", 6),
        span.number("ipv6.hlim", "跳数限制", 7),
        span.field("ipv6.src", "源地址", src, 8, 16),
        span.field("ipv6.dst", "目标地址", dst, 24, 16),
    ]
    complete = 40 + payload_length <= len(span)
    if not complete:
        fields.append(span.missing("ipv6.truncated", 40 + payload_length - len(span)))

    cursor = 40
    for _ in range(16):
        if next_header not in IPV6_EXTENSIONS:
            break
        previous = next_header
        try:
            size = ipv6_extension_size(section, cursor, previous)
            extension = section.sub(cursor, size)
            fields.append(_extension_fields(extension, previous))
        except ParseError as error:
            if error.missing:
                available = section.sub(cursor)
                prefix = []
                if len(available):
                    prefix.append(available.number("ipv6.ext.nxt", "下一个报头", 0))
                if previous != 44 and len(available) >= 2:
                    prefix.append(available.number("ipv6.ext.len", "长度字段", 1))
                prefix.append(available.missing("ipv6.ext.incomplete", error.missing))
                fields.append(available.layer("ipv6.ext", f"扩展报头不完整 · {IPV6_EXTENSIONS[previous]}", prefix, previous))
            else:
                fields.append(section.payload(cursor, label=f"IPv6 扩展报头异常 · {error}"))
            break
        next_header = extension.uint(0)
        cursor += len(extension)
        if previous == 44:
            offset_and_flags = extension.uint(2, 2)
            if offset_and_flags >> 3:
                fields.append(section.payload(cursor, label="IPv6 后续分片"))
                return section.layer("ipv6", f"IPv6 · {src} → {dst}", fields)
            complete &= not bool(offset_and_flags & 1)
        if previous == 43 and extension.uint(3):
            complete = False  # 存在尚未遍历的路由段，伪首部目标地址不能直接取 IPv6 报头。
    if next_header != 59 and next_header not in IPV6_EXTENSIONS and cursor < len(section):
        fields.append(registry.dispatch("ip", next_header, section.sub(cursor), IPContext(6, source, destination, complete)))
    return section.layer("ipv6", f"IPv6 · {src} → {dst}", fields)


def ipv6_extension_size(span: Span, offset: int, kind: int) -> int:
    if kind == 44:
        return 8
    length = span.uint(offset + 1)
    return (length + 2) * 4 if kind == 51 else (length + 1) * 8


def _extension_fields(span: Span, kind: int) -> Field:
    fields = [span.number("ipv6.ext.nxt", "下一个报头", 0)]
    if kind == 44:
        fragment = span.uint(2, 2)
        fields.extend([
            span.field("ipv6.frag.offset", "分片偏移（字节）", (fragment >> 3) * 8, 2, 2),
            span.field("ipv6.frag.more", "还有分片", bool(fragment & 1), 2, 2),
            span.number("ipv6.frag.id", "标识", 4, 4, hexadecimal=True),
        ])
    else:
        fields.append(span.number("ipv6.ext.len", "长度字段", 1))
        if kind == 43:
            fields.extend([
                span.number("ipv6.routing.type", "路由类型", 2),
                span.number("ipv6.routing.segments_left", "剩余段数", 3),
                span.payload(4, label="路由数据"),
            ])
        elif kind == 51:
            fields.extend([
                span.number("ipv6.ah.spi", "安全参数索引", 4, 4, hexadecimal=True),
                span.number("ipv6.ah.seq", "序号", 8, 4),
                span.payload(12, label="完整性校验值"),
            ])
        else:
            cursor = 2
            while cursor < len(span):
                option_type = span.uint(cursor)
                if option_type and len(span) - cursor < 2:
                    fields.append(span.missing("ipv6.opt.incomplete", cursor + 2 - len(span)))
                    break
                size = 1 if not option_type else span.uint(cursor + 1) + 2
                if cursor + size > len(span):
                    fields.append(span.missing("ipv6.opt.incomplete", cursor + size - len(span)))
                    break
                option = span.sub(cursor, size)
                fields.append(option.layer("ipv6.opt", f"IPv6 选项 {option_type}", [
                    option.number("ipv6.opt.type", "类型", 0),
                    *([option.payload(2, label="选项数据")] if size > 2 else []),
                ], option_type))
                cursor += size
    return span.layer("ipv6.ext", f"扩展报头 · {IPV6_EXTENSIONS[kind]}", fields, kind)
