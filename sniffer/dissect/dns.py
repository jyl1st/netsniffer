from ipaddress import ip_address

from sniffer.dissect.field import Field, ParseError, Span

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}
MAX_DNS_ENTRIES = 256


def _domain_name(message: Span, offset: int) -> tuple[str, int]:
    labels = []
    cursor = offset
    traversed = 0
    consumed = None
    label_bytes = 0
    # 指针指向 DNS 消息内先前的标签。返回的长度只计算当前位置实际占用的字节。
    while traversed < 128:
        traversed += 1
        length = message.uint(cursor)
        if length & 0xC0 == 0xC0:
            pointer = message.uint(cursor, 2) & 0x3FFF
            if not 12 <= pointer < cursor:
                raise ParseError("DNS 压缩指针未指向先前的名称标签")
            if consumed is None:
                consumed = cursor + 2 - offset
            cursor = pointer
        elif length == 0:
            return ".".join(labels) or ".", cursor + 1 - offset if consumed is None else consumed
        elif length & 0xC0:
            raise ParseError("DNS 标签类型无效")
        else:
            label_bytes += length + 1
            if label_bytes >= 255:
                raise ParseError("DNS 名称超过 255 字节")
            labels.append(message.bytes(cursor + 1, length).decode("utf-8", "replace"))
            cursor += 1 + length
    raise ParseError("DNS 压缩链过长")


def parse_dns(span: Span, _registry, _network) -> Field:
    return _parse_message(span, mdns=False)


def parse_mdns(span: Span, _registry, _network) -> Field:
    return span.layer("mdns", "多播 DNS", [_parse_message(span, mdns=True)])


def parse_dns_tcp(span: Span, _registry, _network) -> Field:
    records = []
    cursor = 0
    while cursor < len(span) and len(records) < 16:
        size = span.uint(cursor, 2)
        if size > len(span) - cursor - 2:
            records.append(span.payload(cursor, label="TCP DNS 消息未完整捕获"))
            break
        block = span.sub(cursor, size + 2)
        records.append(block.layer("dns.tcp.message", "TCP DNS 消息", [
            block.number("dns.tcp.length", "消息长度", 0, 2),
            _parse_message(block.sub(2), mdns=False),
        ]))
        cursor += size + 2
    return span.layer("dns.tcp", "TCP DNS", records)


def _parse_message(span: Span, *, mdns: bool) -> Field:
    transaction, flags, questions, answers, authority, additional = span.unpack("!HHHHHH", 0)
    is_response = bool(flags & 0x8000)
    fields = [
        span.number("dns.id", "事务 ID", 0, 2, hexadecimal=True),
        span.sub(2, 2).layer("dns.flags", f"标志: 0x{flags:04x}", [
            span.field("dns.flags.response", "应答", is_response, 2, 2),
            span.field("dns.flags.opcode", "操作码", (flags >> 11) & 15, 2, 2),
            span.field("dns.flags.authoritative", "权威应答", bool(flags & 0x400), 2, 2),
            span.field("dns.flags.truncated", "截断", bool(flags & 0x200), 2, 2),
            span.field("dns.flags.recdesired", "期望递归", bool(flags & 0x100), 2, 2),
            span.field("dns.flags.recavail", "支持递归", bool(flags & 0x80), 2, 2),
            span.field("dns.flags.rcode", "应答码", flags & 15, 2, 2),
        ], flags),
        span.number("dns.count.queries", "查询数", 4, 2),
        span.number("dns.count.answers", "应答数", 6, 2),
        span.number("dns.count.auth_rr", "授权记录数", 8, 2),
        span.number("dns.count.add_rr", "附加记录数", 10, 2),
    ]
    cursor = 12
    budget = MAX_DNS_ENTRIES
    for kind, title, count in (
        ("qry", "查询", questions), ("answer", "应答", answers),
        ("authority", "授权记录", authority), ("additional", "附加记录", additional),
    ):
        start = cursor
        entries = []
        for _ in range(min(count, budget)):
            if kind == "qry":
                item, cursor = _question(span, cursor, mdns)
            else:
                item, cursor = _record(span, cursor, mdns)
            entries.append(item)
        budget -= len(entries)
        if entries:
            fields.append(span.sub(start, cursor - start).layer(f"dns.section.{kind}", title, entries))
        if count > len(entries):
            fields.append(span.payload(cursor, label="超出单条 DNS 消息的展示上限"))
            break
    label = "应答" if is_response else "查询"
    return span.layer("dns", f"DNS {label} · 事务 0x{transaction:04x}", fields)


def _question(span: Span, start: int, mdns: bool) -> tuple[Field, int]:
    name, length = _domain_name(span, start)
    type_at = start + length
    kind, qclass = span.unpack("!HH", type_at)
    fields = [
        span.field("dns.qry.name", "名称", name, start, length),
        span.field("dns.qry.type", "类型", kind, type_at, 2, text=TYPES.get(kind, str(kind))),
        span.field("dns.qry.class", "类别", qclass & 0x7FFF if mdns else qclass, type_at + 2, 2),
    ]
    if mdns:
        fields.append(span.field("dns.qry.qu", "期望单播应答", bool(qclass & 0x8000), type_at + 2, 2))
    return span.sub(start, length + 4).layer("dns.question", f"{name} · {TYPES.get(kind, kind)}", fields), type_at + 4


def _record(span: Span, start: int, mdns: bool) -> tuple[Field, int]:
    name, length = _domain_name(span, start)
    type_at = start + length
    kind, rrclass, _, data_length = span.unpack("!HHIH", type_at)
    offset = type_at + 10
    data = span.sub(offset, data_length)
    fields = [
        span.field("dns.resp.name", "名称", name, start, length),
        span.field("dns.resp.type", "类型", kind, type_at, 2, text=TYPES.get(kind, str(kind))),
        span.field("dns.resp.class", "类别", rrclass & 0x7FFF if mdns else rrclass, type_at + 2, 2),
        span.number("dns.resp.ttl", "TTL", type_at + 4, 4),
        span.number("dns.resp.len", "数据长度", type_at + 8, 2),
    ]
    if mdns:
        fields.append(span.field("dns.resp.cache_flush", "清除缓存", bool(rrclass & 0x8000), type_at + 2, 2))
    fields.extend(_record_data(span, data, kind))
    return span.sub(start, length + 10 + data_length).layer("dns.record", f"{name} · {TYPES.get(kind, kind)}", fields), offset + data_length


def _record_data(message: Span, data: Span, kind: int) -> list[Field]:
    if (kind == 1 and len(data) == 4) or (kind == 28 and len(data) == 16):
        name = "dns.a" if kind == 1 else "dns.aaaa"
        value = str(ip_address(data.bytes(0, len(data))))
        return [data.field(name, TYPES[kind], value, 0, len(data))]
    if kind in (2, 5, 12, 15, 33):
        prefix = {15: 2, 33: 6}.get(kind, 0)
        target, length = _domain_name(message, data.start - message.start + prefix)
        fields = []
        if kind in (15, 33):
            fields.append(data.number("dns.preference", "优先级", 0, 2))
        if kind == 33:
            fields.extend([data.number("dns.srv.weight", "权重", 2, 2), data.number("dns.srv.port", "端口", 4, 2)])
        fields.append(data.field(f"dns.{TYPES[kind].lower()}", "目标名称", target, prefix, length))
        return fields
    if kind == 16:
        fields = []
        cursor = 0
        while cursor < len(data) and len(fields) < MAX_DNS_ENTRIES:
            length = data.uint(cursor)
            value = data.bytes(cursor + 1, length).decode("utf-8", "replace")
            fields.append(data.field("dns.txt", "文本", value, cursor + 1, length))
            cursor += length + 1
        return fields
    return [data.payload(label="资源记录数据")] if len(data) else []
