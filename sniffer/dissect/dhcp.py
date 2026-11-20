from ipaddress import ip_address

from sniffer.dissect.field import Field, ParseError, Span, partial_header

COOKIE = b"\x63\x82\x53\x63"
MESSAGE_TYPES = {1: "Discover", 2: "Offer", 3: "Request", 4: "Decline", 5: "ACK", 6: "NAK", 7: "Release", 8: "Inform"}
OPTION_NAMES = {
    1: "subnet_mask", 3: "router", 6: "dns_server", 12: "hostname", 15: "domain_name",
    28: "broadcast", 50: "requested_ip", 51: "lease_time", 53: "message_type",
    54: "server_id", 55: "parameter_request", 58: "renewal_time", 59: "rebinding_time",
    60: "vendor_class", 61: "client_id",
}


def dhcp_info(span: Span) -> str | None:
    if len(span) < 240 or span.bytes(236, 4) != COOKIE:
        return None
    if span.uint(0) not in (1, 2) or not 1 <= span.uint(2) <= 16:
        return None
    choice = None
    cursor = 240
    options = 0
    try:
        while cursor < len(span) and cursor - 240 < 4096 and options < 256:
            code = span.uint(cursor)
            if code == 255:
                return f"DHCP {MESSAGE_TYPES.get(choice, choice)}" if choice is not None else None
            if not code:
                cursor += 1
                continue
            size = span.uint(cursor + 1)
            span.require(cursor + 2, size)
            if code == 53:
                if size != 1 or choice is not None:
                    return None
                choice = span.uint(cursor + 2)
                if choice not in MESSAGE_TYPES:
                    return None
            cursor += 2 + size
            options += 1
    except ParseError:
        pass
    return None


def parse_dhcp(span: Span, _registry, _network) -> Field:
    if len(span) < 240:
        return partial_header(span, "dhcp", "DHCP / BOOTP", 240, (
            ("dhcp.op", "操作码", 0, 1), ("dhcp.hw.type", "硬件类型", 1, 1),
            ("dhcp.hw.len", "硬件地址长度", 2, 1), ("dhcp.hops", "跳数", 3, 1),
            ("dhcp.id", "事务 ID", 4, 4, "hex"), ("dhcp.secs", "已用秒数", 8, 2),
            ("dhcp.flags", "标志", 10, 2, "hex"), ("dhcp.ip.ciaddr", "客户端 IP", 12, 4, "ip"),
            ("dhcp.ip.yiaddr", "分配的 IP", 16, 4, "ip"), ("dhcp.ip.siaddr", "服务器 IP", 20, 4, "ip"),
            ("dhcp.ip.giaddr", "中继 IP", 24, 4, "ip"),
        ))
    if span.bytes(236, 4) != COOKIE:
        raise ParseError("DHCP 魔数无效")
    hlen = span.uint(2)
    if hlen > 16:
        raise ParseError("DHCP 客户端硬件地址长度超过 16")
    fields = [
        span.number("dhcp.op", "操作码", 0),
        span.number("dhcp.hw.type", "硬件类型", 1),
        span.number("dhcp.hw.len", "硬件地址长度", 2),
        span.number("dhcp.hops", "跳数", 3),
        span.number("dhcp.id", "事务 ID", 4, 4, hexadecimal=True),
        span.number("dhcp.secs", "已用秒数", 8, 2),
        span.number("dhcp.flags", "标志", 10, 2, hexadecimal=True),
        span.field("dhcp.hw.mac_addr", "客户端硬件地址", span.bytes(28, hlen).hex(":"), 28, hlen),
        span.number("dhcp.cookie", "魔数", 236, 4, hexadecimal=True),
    ]
    for offset, name, label in (
        (12, "ciaddr", "客户端 IP"), (16, "yiaddr", "分配的 IP"),
        (20, "siaddr", "服务器 IP"), (24, "giaddr", "中继 IP"),
    ):
        fields.append(span.field(f"dhcp.ip.{name}", label, str(ip_address(span.bytes(offset, 4))), offset, 4))
    options = span.sub(240)
    message_type, items = _options(options)
    fields.append(options.layer("dhcp.options", "DHCP 选项", items))
    title = MESSAGE_TYPES.get(message_type, str(message_type)) if message_type is not None else "消息"
    return span.layer("dhcp", f"DHCP · {title}", fields)


def _options(span: Span) -> tuple[int | None, list[Field]]:
    result = []
    message_type = None
    cursor = 0
    while cursor < len(span) and len(result) < 256:
        code = span.uint(cursor)
        if code == 255:
            result.append(span.number("dhcp.option.end", "结束", cursor))
            break
        if code == 0:
            cursor += 1
            continue
        if len(span) - cursor < 2:
            result.append(span.missing("dhcp.option.incomplete", cursor + 2 - len(span)))
            break
        size = span.uint(cursor + 1)
        if cursor + size + 2 > len(span):
            result.append(span.missing("dhcp.option.incomplete", cursor + size + 2 - len(span)))
            break
        option = span.sub(cursor, size + 2)
        label = OPTION_NAMES.get(code, f"未知选项 {code}")
        fields = [
            option.number("dhcp.option.type", "类型", 0),
            option.number("dhcp.option.length", "长度", 1),
        ]
        name = f"dhcp.option.{label}"
        if code in (12, 15, 60):
            value = option.bytes(2, size).decode("utf-8", "replace")
            fields.append(option.field(name, label, value, 2, size))
        elif code == 53 and size == 1:
            message_type = option.uint(2)
            fields.append(option.field(name, "消息类型", message_type, 2, 1, text=MESSAGE_TYPES.get(message_type, str(message_type))))
        elif code in (1, 3, 6, 28, 50, 54) and size % 4 == 0:
            for offset in range(2, len(option), 4):
                fields.append(option.field(name, label, str(ip_address(option.bytes(offset, 4))), offset, 4))
        elif code in (51, 58, 59) and size == 4:
            fields.append(option.number(name, "秒数", 2, 4))
        elif size:
            fields.append(option.payload(2, label="选项数据"))
        result.append(option.layer("dhcp.option", f"选项 {code} · {label}", fields, code))
        cursor += size + 2
    return message_type, result
