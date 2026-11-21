from ipaddress import ip_address

from sniffer.dissect.field import Field, ParseError, Span

TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}
MAX_DNS_ENTRIES = 256
OPCODES = {0: "标准", 1: "反向", 2: "状态", 4: "通知", 5: "更新", 6: "DSO"}
RCODES = {1: "格式错误", 2: "服务器失败", 3: "名称不存在", 4: "未实现", 5: "拒绝"}


def dns_info(span: Span, *, tcp: bool = False) -> str | None:
    """快速验证报头、名称、记录和长度，同时提取摘要所需的少量值。"""
    incomplete = False
    try:
        if tcp:
            size = span.uint(0, 2)
            if size < 12:
                return None
            incomplete = size > len(span) - 2
            span = span.sub(2, min(size, len(span) - 2))
        xid, flags, questions, answers, authority, additional = span.unpack("!HHHHHH", 0)
        opcode = (flags >> 11) & 15
        if opcode not in OPCODES or flags & 0x40:
            return None
        if questions + answers + authority + additional > MAX_DNS_ENTRIES:
            return None
    except ParseError:
        return None
    response = bool(flags & 0x8000)
    title = f"{OPCODES[opcode]}{'应答' if response else '查询'} 0x{xid:04x}"
    cursor = 12
    question = answer = None
    try:
        for index in range(questions):
            name, length = _domain_name(span, cursor)
            kind, _ = span.unpack("!HH", cursor + length)
            if not index:
                question = f"{TYPES.get(kind, kind)} {name}"
            cursor += length + 4
        for index in range(answers + authority + additional):
            owner, name_size = _domain_name(span, cursor)
            start = cursor + name_size
            kind, _, _, size = span.unpack("!HHIH", start)
            data = span.sub(start + 10, size)
            result = _summary_rdata(span, data, kind) if index < answers or kind in (2, 5, 12, 15, 16, 33) else None
            if index < answers and (answer is None or kind in (1, 28)):
                preview = f"{TYPES.get(kind, kind)} {result or owner}"
                if answer is None or not answer.startswith(("A ", "AAAA ")):
                    answer = preview
            cursor = start + 10 + size
    except ParseError as error:
        if not incomplete or not error.missing or question is None:
            return None
    if not incomplete and cursor != len(span):
        # 有些实现为 DNS 消息附加零填充；它不会覆盖报头声明的记录。
        if any(span.raw[span.start + cursor:span.end]):
            return None
    rcode = flags & 15
    parts = [title]
    if response and rcode:
        parts.append(RCODES.get(rcode, f"应答码 {rcode}"))
    if question:
        parts.append(question)
    if response and answer:
        parts.append(answer)
    return " ".join(parts)


def _summary_rdata(message: Span, data: Span, kind: int) -> str | None:
    if kind in (1, 28):
        size = 4 if kind == 1 else 16
        if len(data) != size:
            raise ParseError("DNS 地址记录长度异常")
        return str(ip_address(data.bytes(0, size)))
    if kind in (2, 5, 12, 15, 33):
        prefix = {15: 2, 33: 6}.get(kind, 0)
        name, size = _domain_name(message, data.start - message.start + prefix)
        if prefix + size != len(data):
            raise ParseError("DNS 名称记录长度异常")
        return name
    if kind == 16:
        cursor = 0
        while cursor < len(data):
            size = data.uint(cursor)
            data.require(cursor + 1, size)
            cursor += 1 + size
    return None


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
        if len(span) - cursor < 2:
            records.append(span.missing("dns.tcp.incomplete", 2 - (len(span) - cursor), tcp_segment=True).as_incomplete())
            break
        size = span.uint(cursor, 2)
        block = span.sub(cursor, min(size + 2, len(span) - cursor))
        parts = [
            block.number("dns.tcp.length", "消息长度", 0, 2),
            _parse_message(block.sub(2), mdns=False),
        ]
        incomplete = len(block) < size + 2
        if incomplete:
            parts.append(block.missing("dns.tcp.incomplete", size + 2 - len(block), tcp_segment=True))
        layer = block.layer("dns.tcp.message", "TCP DNS 消息", parts)
        records.append(layer.as_incomplete() if incomplete else layer)
        cursor += len(block)
    return span.layer("dns.tcp", "TCP DNS", records, filterable=any(record.filterable for record in records))


def _parse_message(span: Span, *, mdns: bool) -> Field:
    if len(span) < 12:
        fields = [
            span.number(name, title, offset, 2)
            for name, title, offset in _HEADER_PARTS
            if len(span) >= offset + 2
        ]
        fields.append(span.missing("dns.incomplete", 12 - len(span)))
        return span.layer("dns", "DNS · 报头不完整", fields)
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
        try:
            for _ in range(min(count, budget)):
                if kind == "qry":
                    item, cursor = _question(span, cursor, mdns)
                else:
                    item, cursor = _record(span, cursor, mdns)
                entries.append(item)
        except ParseError as error:
            if entries:
                fields.append(span.sub(start, cursor - start).layer(f"dns.section.{kind}", title, entries))
            if error.missing:
                fields.append(span.missing("dns.incomplete", error.missing))
            else:
                fields.append(span.field("malformed", f"DNS 数据异常 · {error}", None, cursor, len(span) - cursor))
            break
        budget -= len(entries)
        if entries:
            fields.append(span.sub(start, cursor - start).layer(f"dns.section.{kind}", title, entries))
        if count > len(entries):
            fields.append(span.payload(cursor, label="超出单条 DNS 消息的展示上限"))
            break
    label = "应答" if is_response else "查询"
    return span.layer("dns", f"DNS {label} · 事务 0x{transaction:04x}", fields)


_HEADER_PARTS = (
    ("dns.id", "事务 ID", 0), ("dns.flags", "标志", 2),
    ("dns.count.queries", "查询数", 4), ("dns.count.answers", "应答数", 6),
    ("dns.count.auth_rr", "授权记录数", 8), ("dns.count.add_rr", "附加记录数", 10),
)


def _question(span: Span, start: int, mdns: bool) -> tuple[Field, int]:
    name, length = _domain_name(span, start)
    type_at = start + length
    if len(span) - type_at < 4:
        fields = [span.field("dns.qry.name", "名称", name, start, length)]
        if len(span) - type_at >= 2:
            fields.append(span.number("dns.qry.type", "类型", type_at, 2))
        fields.append(span.missing("dns.incomplete", type_at + 4 - len(span)))
        return span.sub(start).layer("dns.question", name, fields), len(span)
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
    data = span.sub(offset, min(data_length, len(span) - offset))
    fields = [
        span.field("dns.resp.name", "名称", name, start, length),
        span.field("dns.resp.type", "类型", kind, type_at, 2, text=TYPES.get(kind, str(kind))),
        span.field("dns.resp.class", "类别", rrclass & 0x7FFF if mdns else rrclass, type_at + 2, 2),
        span.number("dns.resp.ttl", "TTL", type_at + 4, 4),
        span.number("dns.resp.len", "数据长度", type_at + 8, 2),
    ]
    if mdns:
        fields.append(span.field("dns.resp.cache_flush", "清除缓存", bool(rrclass & 0x8000), type_at + 2, 2))
    if len(data) == data_length:
        fields.extend(_record_data(span, data, kind))
    else:
        if len(data):
            fields.append(data.payload(label="已捕获的资源记录数据"))
        fields.append(data.missing("dns.incomplete", data_length - len(data)))
    end = offset + len(data)
    return span.sub(start, end - start).layer("dns.record", f"{name} · {TYPES.get(kind, kind)}", fields), end


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
