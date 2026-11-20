from ipaddress import ip_address

from sniffer.dissect.app_detect import dissect_application
from sniffer.dissect.checksum import checksum_field, checksum_valid, transport_checksum
from sniffer.dissect.field import Field, ParseError, Span, partial_header
from sniffer.dissect.registry import IPContext, Registry

TCP_FLAGS = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")
TCP_OPTIONS = {0: "结束", 1: "NOP", 2: "MSS", 3: "窗口扩大", 4: "允许 SACK", 5: "SACK", 8: "时间戳"}


def parse_tcp(span: Span, registry: Registry, network: IPContext | None) -> Field:
    if len(span) < 20:
        return partial_header(span, "tcp", "TCP", 20, (
            ("tcp.srcport", "源端口", 0, 2), ("tcp.dstport", "目标端口", 2, 2),
            ("tcp.seq", "序号", 4, 4), ("tcp.ack", "确认号", 8, 4),
            ("tcp.flags", "标志位", 13, 1, "hex"), ("tcp.window_size", "窗口大小", 14, 2),
            ("tcp.checksum", "校验和", 16, 2, "hex"),
        ))
    source, destination, _, _, control = span.unpack("!HHIIH", 0)
    header_length = (control >> 12) * 4
    if header_length < 20:
        raise ParseError("TCP 报头长度小于 20 字节")
    header = span.sub(0, min(len(span), header_length))
    flag_fields = [
        header.field(f"tcp.flags.{name.lower()}", name, bool(control & (1 << index)), 13, 1)
        for index, name in enumerate(TCP_FLAGS)
    ]
    fields = [
        span.number("tcp.srcport", "源端口", 0, 2),
        span.number("tcp.dstport", "目标端口", 2, 2),
        span.number("tcp.seq", "序号", 4, 4),
        span.number("tcp.ack", "确认号", 8, 4),
        span.field("tcp.hdr_len", "报头长度", header_length, 12, 1),
        span.sub(13, 1).layer("tcp.flags", f"标志位: 0x{control & 255:02x}", flag_fields, control & 255),
        span.number("tcp.window_size", "窗口大小", 14, 2),
        checksum_field(span, "tcp.checksum", 16, transport_checksum(span, network, 6) if len(span) >= header_length else None),
        span.number("tcp.urgent_pointer", "紧急指针", 18, 2),
        span.field("tcp.len", "已捕获负载长度", max(0, len(span) - header_length), 0, 0),
    ]
    if header_length > 20:
        options = header.sub(20)
        fields.append(options.layer("tcp.options", "TCP 选项", _tcp_options(options)))
    if len(span) < header_length:
        fields.append(span.missing("tcp.options.incomplete", header_length - len(span)))
    if header_length < len(span):
        fields.append(dissect_application(span.sub(header_length), registry, 6, source, destination))
    return span.layer("tcp", f"TCP · {source} → {destination}", fields)


def _tcp_options(span: Span) -> list[Field]:
    fields = []
    cursor = 0
    while cursor < len(span):
        kind = span.uint(cursor)
        if kind not in (0, 1) and len(span) - cursor < 2:
            fields.append(span.missing("tcp.option.incomplete", cursor + 2 - len(span)))
            break
        size = 1 if kind in (0, 1) else span.uint(cursor + 1)
        if kind not in (0, 1) and size < 2:
            fields.append(span.payload(cursor, label="TCP 选项长度小于 2"))
            break
        if cursor + size > len(span):
            fields.append(span.missing("tcp.option.incomplete", cursor + size - len(span)))
            break
        option = span.sub(cursor, size)
        details = [option.number("tcp.option.kind", "类型", 0)]
        if kind not in (0, 1):
            details.append(option.number("tcp.option.length", "长度", 1))
        if kind == 2 and size == 4:
            details.append(option.number("tcp.options.mss_val", "最大段长度", 2, 2))
        elif kind == 3 and size == 3:
            details.append(option.number("tcp.options.wscale.shift", "窗口扩大位移", 2))
        elif kind == 5 and (size - 2) % 8 == 0:
            for offset in range(2, size, 8):
                details.extend([
                    option.number("tcp.options.sack_le", "SACK 左边界", offset, 4),
                    option.number("tcp.options.sack_re", "SACK 右边界", offset + 4, 4),
                ])
        elif kind == 8 and size == 10:
            details.extend([
                option.number("tcp.options.timestamp.tsval", "TSval", 2, 4),
                option.number("tcp.options.timestamp.tsecr", "TSecr", 6, 4),
            ])
        elif size > 2:
            details.append(option.payload(2, label="选项数据"))
        fields.append(option.layer("tcp.option", TCP_OPTIONS.get(kind, f"TCP 选项 {kind}"), details, kind))
        if kind == 0:
            break
        cursor += size
    return fields


def parse_udp(span: Span, registry: Registry, network: IPContext | None) -> Field:
    if len(span) < 8:
        return partial_header(span, "udp", "UDP", 8, (
            ("udp.srcport", "源端口", 0, 2), ("udp.dstport", "目标端口", 2, 2),
            ("udp.length", "长度", 4, 2),
        ))
    source, destination, length, checksum = span.unpack("!HHHH", 0)
    if length < 8:
        raise ParseError("UDP 长度小于 8 字节")
    section = span.sub(0, min(length, len(span)))
    valid = None
    if length <= len(span) and network is not None:
        if checksum or network.version == 6:
            valid = transport_checksum(section, network, 17)
    fields = [
        section.number("udp.srcport", "源端口", 0, 2),
        section.number("udp.dstport", "目标端口", 2, 2),
        section.number("udp.length", "长度", 4, 2),
        checksum_field(section, "udp.checksum", 6, valid),
    ]
    if length > len(span):
        fields.append(section.missing("udp.truncated", length - len(span)))
    if len(section) > 8:
        fields.append(dissect_application(section.sub(8), registry, 17, source, destination))
    return section.layer("udp", f"UDP · {source} → {destination}", fields)


ICMP_TYPES = {0: "回显应答", 3: "目标不可达", 5: "重定向", 8: "回显请求", 11: "超时", 12: "参数错误", 13: "时间戳请求", 14: "时间戳应答"}
ICMPV6_TYPES = {
    1: "目标不可达", 2: "数据包过大", 3: "超时", 4: "参数错误",
    128: "回显请求", 129: "回显应答", 133: "路由器请求", 134: "路由器通告",
    135: "邻居请求", 136: "邻居通告", 137: "重定向",
}


def parse_icmp(span: Span, _registry, network: IPContext | None) -> Field:
    if len(span) < 4:
        return partial_header(span, "icmp", "ICMP", 4, (("icmp.type", "类型", 0, 1), ("icmp.code", "代码", 1, 1)))
    kind, code = span.unpack("!BB", 0)
    valid = checksum_valid(memoryview(span.raw)[span.start:span.end]) if network and network.complete else None
    fields = [
        span.number("icmp.type", "类型", 0),
        span.number("icmp.code", "代码", 1),
        checksum_field(span, "icmp.checksum", 2, valid),
    ]
    cursor = 4
    if kind in (0, 8, 13, 14):
        cursor = _icmp_numbers(span, fields, "icmp.incomplete", 8, (
            ("icmp.ident", "标识", 4, 2), ("icmp.seq", "序号", 6, 2),
        ))
    if kind in (13, 14):
        if len(span) >= 8:
            cursor = _icmp_numbers(span, fields, "icmp.incomplete", 20, (
                ("icmp.timestamp.originate", "起始", 8, 4),
                ("icmp.timestamp.receive", "接收", 12, 4),
                ("icmp.timestamp.transmit", "发送", 16, 4),
            ))
    if kind == 3 and code == 4:
        cursor = _icmp_numbers(span, fields, "icmp.incomplete", 8, (("icmp.mtu", "下一跳 MTU", 6, 2),))
    elif kind == 5:
        if len(span) >= 8:
            gateway = str(ip_address(span.bytes(4, 4)))
            fields.append(span.field("icmp.redir_gw", "重定向网关", gateway, 4, 4))
        else:
            fields.append(span.missing("icmp.incomplete", 8 - len(span)))
        cursor = 8
    elif kind == 12:
        cursor = _icmp_numbers(span, fields, "icmp.incomplete", 8, (("icmp.pointer", "错误位置", 4, 1),))
    if cursor < len(span):
        fields.append(span.payload(cursor, "icmp.data"))
    return span.layer("icmp", f"ICMP · {ICMP_TYPES.get(kind, kind)}", fields)


def parse_icmpv6(span: Span, _registry, network: IPContext | None) -> Field:
    if len(span) < 4:
        return partial_header(span, "icmpv6", "ICMPv6", 4, (
            ("icmpv6.type", "类型", 0, 1), ("icmpv6.code", "代码", 1, 1),
        ))
    kind = span.uint(0)
    fields = [
        span.number("icmpv6.type", "类型", 0),
        span.number("icmpv6.code", "代码", 1),
        checksum_field(span, "icmpv6.checksum", 2, transport_checksum(span, network, 58)),
    ]
    cursor = 4
    if kind in (128, 129):
        cursor = _icmp_numbers(span, fields, "icmpv6.incomplete", 8, (
            ("icmpv6.echo.identifier", "标识", 4, 2), ("icmpv6.echo.sequence_number", "序号", 6, 2),
        ))
    elif kind in (2, 4):
        name, title = ("mtu", "MTU") if kind == 2 else ("pointer", "错误位置")
        cursor = _icmp_numbers(span, fields, "icmpv6.incomplete", 8, ((f"icmpv6.{name}", title, 4, 4),))
    elif kind == 133:
        cursor = _icmp_numbers(span, fields, "icmpv6.incomplete", 8, ())
    elif kind == 134:
        cursor = _icmp_numbers(span, fields, "icmpv6.incomplete", 16, (
            ("icmpv6.nd.ra.cur_hop_limit", "当前跳数限制", 4, 1),
            ("icmpv6.nd.ra.flags", "通告标志", 5, 1),
            ("icmpv6.nd.ra.router_lifetime", "路由器寿命", 6, 2),
            ("icmpv6.nd.ra.reachable_time", "可达时间", 8, 4),
            ("icmpv6.nd.ra.retrans_timer", "重传计时", 12, 4),
        ))
    elif kind in (135, 136, 137):
        cursor = 40 if kind == 137 else 24
        if kind == 136 and len(span) >= 8:
            fields.append(span.number("icmpv6.nd.na.flags", "通告标志", 4, 4, hexadecimal=True))
        if len(span) >= 24:
            fields.append(span.field("icmpv6.nd.target", "目标地址", str(ip_address(span.bytes(8, 16))), 8, 16))
        if kind == 137 and len(span) >= 40:
            fields.append(span.field("icmpv6.nd.destination", "重定向目的地址", str(ip_address(span.bytes(24, 16))), 24, 16))
        if len(span) < cursor:
            fields.append(span.missing("icmpv6.incomplete", cursor - len(span)))
    if cursor < len(span):
        if kind in (133, 134, 135, 136, 137):
            fields.extend(_neighbor_options(span.sub(cursor)))
        else:
            fields.append(span.payload(cursor, "icmpv6.data"))
    return span.layer("icmpv6", f"ICMPv6 · {ICMPV6_TYPES.get(kind, kind)}", fields)


def _icmp_numbers(span: Span, fields: list[Field], missing_name: str, required: int, parts: tuple) -> int:
    for name, label, offset, size in parts:
        if offset + size <= len(span):
            fields.append(span.number(name, label, offset, size))
    if len(span) < required:
        fields.append(span.missing(missing_name, required - len(span)))
    return required


def _neighbor_options(span: Span) -> list[Field]:
    result = []
    cursor = 0
    while cursor < len(span):
        if len(span) - cursor < 2:
            result.append(span.missing("icmpv6.opt.incomplete", cursor + 2 - len(span)))
            break
        kind, blocks = span.unpack("!BB", cursor)
        if blocks == 0:
            result.append(span.payload(cursor, label="ICMPv6 邻居发现选项长度为零"))
            break
        if cursor + blocks * 8 > len(span):
            result.append(span.missing("icmpv6.opt.incomplete", cursor + blocks * 8 - len(span)))
            break
        option = span.sub(cursor, blocks * 8)
        fields = [option.number("icmpv6.opt.type", "类型", 0), option.number("icmpv6.opt.length", "长度字段", 1)]
        if kind in (1, 2) and blocks == 1:
            fields.append(option.field("icmpv6.opt.linkaddr", "链路层地址", option.bytes(2, 6).hex(":"), 2, 6))
        elif kind == 3 and blocks == 4:
            fields.extend([
                option.number("icmpv6.opt.prefix_len", "前缀长度", 2),
                option.number("icmpv6.opt.prefix.valid_lifetime", "有效寿命", 4, 4),
                option.field("icmpv6.opt.prefix", "前缀", str(ip_address(option.bytes(16, 16))), 16, 16),
            ])
        else:
            fields.append(option.payload(2, label="选项数据"))
        result.append(option.layer("icmpv6.opt", f"邻居发现选项 {kind}", fields, kind))
        cursor += len(option)
    return result
