from struct import unpack_from

from sniffer.dissect.field import Field, ParseError, Span

RECORD_TYPES = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data", 24: "Heartbeat"}
HANDSHAKE_TYPES = {1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions", 11: "Certificate", 20: "Finished"}
VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
CIPHERS = {
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384", 0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
}
EXTENSIONS = {0: "server_name", 10: "supported_groups", 13: "signature_algorithms", 16: "ALPN", 43: "supported_versions", 51: "key_share"}


def tls_record_header(raw: bytes, start: int, end: int) -> tuple[int, int, int] | None:
    if end - start < 5:
        return None
    kind, version, length = unpack_from("!BHH", raw, start)
    if kind not in RECORD_TYPES or not 0x0300 <= version <= 0x0303 or length > 18_432:
        return None
    if not length and kind != 23:
        return None
    return kind, version, length


def tls_info(raw: bytes, start: int, end: int, kind: int, record_length: int) -> str:
    record_end = min(end, start + 5 + record_length)
    if kind != 22 or start + 5 >= record_end:
        return RECORD_TYPES[kind]
    return tls_handshake_info(Span(raw, start + 5, record_end))


def tls_handshake_info(data: Span) -> str:
    handshake_type = data.uint(0)
    if handshake_type == 2:
        return "Server Hello"
    if handshake_type != 1:
        return HANDSHAKE_TYPES.get(handshake_type, "Handshake")
    try:
        handshake_end = min(len(data), 4 + data.uint(1, 3))
        name = _first_sni(data.sub(4, handshake_end - 4))
    except ParseError:
        name = None
    return f"Client Hello · SNI={name}" if name else "Client Hello"


def _first_sni(span: Span) -> str | None:
    # 列表只扫描向量长度和扩展头，不创建 Field 或遍历大 key_share。
    cursor = 35 + span.uint(34)
    cursor += 2 + span.uint(cursor, 2)
    cursor += 1 + span.uint(cursor)
    limit = min(len(span), cursor + 2 + span.uint(cursor, 2))
    cursor += 2
    for _ in range(32):
        if cursor + 4 > limit:
            break
        kind, size = span.unpack("!HH", cursor)
        start = cursor + 4
        if kind == 0:
            extension = span.sub(start, min(size, limit - start))
            list_size = extension.uint(0, 2)
            name_type, name_length = extension.unpack("!BH", 2)
            if name_type == 0 and 0 < name_length <= 253 and name_length + 3 <= list_size:
                name = extension.bytes(5, name_length)
                if all(value in b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_" for value in name):
                    return name.decode("ascii")
            break
        cursor = start + size
    return None


def parse_tls(span: Span, _registry, _network) -> Field:
    fields = []
    cursor = 0
    for _ in range(32):
        if cursor >= len(span):
            break
        if len(span) - cursor < 5:
            fields.append(span.payload(cursor, label="TLS 记录头未完整捕获"))
            break
        header = tls_record_header(span.raw, span.start + cursor, span.end)
        if header is None:
            fields.append(span.payload(cursor, label="TLS 记录边界未知"))
            break
        kind, _, declared_length = header
        record = span.sub(cursor, min(declared_length + 5, len(span) - cursor))
        incomplete = len(record) < declared_length + 5
        parts = [
            record.field("tls.record.content_type", "内容类型", kind, 0, 1, text=RECORD_TYPES[kind]),
            _version(record, "tls.record.version", 1),
            record.number("tls.record.length", "记录长度", 3, 2),
        ]
        if kind == 22 and len(record) > 5:
            parts.extend(_handshakes(record.sub(5), record_incomplete=incomplete))
        elif len(record) > 5:
            parts.append(record.payload(5, "tls.record.payload", "记录内容"))
        title = f"TLS 记录 · {RECORD_TYPES[kind]}"
        if incomplete:
            context = "记录抓包截断" if record.capture_truncated else "记录跨 TCP 段"
            title += f" · {context}：本段含 {len(record) - 5} / {declared_length} 字节"
            parts.append(record.missing("tls.record.truncated", declared_length + 5 - len(record), tcp_segment=True))
        fields.append(record.layer("tls.record", title, parts))
        cursor += len(record)
    if not fields:
        raise ParseError("没有 TLS 记录")
    return span.layer("tls", "TLS", fields)


def parse_tls_handshake(span: Span, _registry, _network) -> Field:
    return span.layer("tls", "TLS · 重组握手", _handshakes(span, record_incomplete=False))


def _version(span: Span, name: str, offset: int) -> Field:
    value = span.uint(offset, 2)
    return span.field(name, "版本", value, offset, 2, text=f"{VERSIONS.get(value, '未知')} (0x{value:04x})")


def _handshakes(span: Span, *, record_incomplete: bool) -> list[Field]:
    fields = []
    cursor = 0
    while cursor < len(span) and len(fields) < 32:
        if len(span) - cursor < 4:
            fields.append(span.payload(cursor, label="握手报头未完整捕获"))
            break
        kind = span.uint(cursor)
        size = span.uint(cursor + 1, 3)
        message = span.sub(cursor, min(4 + size, len(span) - cursor))
        title = HANDSHAKE_TYPES.get(kind, f"类型 {kind}")
        details = [
            message.field("tls.handshake.type", "握手类型", kind, 0, 1, text=title),
            message.number("tls.handshake.length", "握手长度", 1, 3),
        ]
        incomplete = len(message) < size + 4
        if kind in (1, 2):
            details.extend(_hello(message.sub(4), client=kind == 1, incomplete=incomplete))
        elif len(message) > 4:
            details.append(message.payload(4, label="握手数据"))
        if incomplete and not record_incomplete:
            details.append(message.field(
                "tls.handshake.incomplete", f"握手其余 {size + 4 - len(message)} 字节跨 TLS 记录",
                None, len(message), 0,
            ))
        fields.append(message.layer("tls.handshake", title, details))
        cursor += len(message)
    return fields


def _hello(span: Span, *, client: bool, incomplete: bool) -> list[Field]:
    fields = []
    try:
        fields.append(_version(span, "tls.handshake.version", 0))
        fields.append(span.field("tls.handshake.random", "随机数", span.bytes(2, 32).hex(), 2, 32))
        size_field = span.number("tls.handshake.session_id_length", "会话 ID 长度", 34)
        fields.append(size_field)
        session_length = size_field.value
        if session_length:
            fields.append(span.field("tls.handshake.session_id", "会话 ID", span.bytes(35, session_length).hex(), 35, session_length))
        cursor = 35 + session_length
        if client:
            size = span.uint(cursor, 2)
            if size % 2:
                raise ParseError("ClientHello 加密套件列表长度不是偶数")
            vector = span.sub(cursor + 2, min(size, len(span) - cursor - 2))
            suites = [_cipher(vector, index) for index in range(0, min(len(vector) & ~1, 512), 2)]
            fields.append(vector.layer("tls.handshake.ciphersuites", "加密套件", suites))
            cursor += 2 + size
            size = span.uint(cursor)
            vector = span.sub(cursor + 1, min(size, len(span) - cursor - 1))
            fields.append(vector.layer("tls.handshake.compression_methods", "压缩方式", [
                vector.number("tls.handshake.comp_method", "压缩方式", index) for index in range(len(vector))
            ]))
            cursor += 1 + size
        else:
            fields.append(_cipher(span, cursor))
            fields.append(span.number("tls.handshake.comp_method", "压缩方式", cursor + 2))
            cursor += 3
        if cursor < len(span):
            size = span.uint(cursor, 2)
            block = span.sub(cursor + 2, min(size, len(span) - cursor - 2))
            extensions = _extensions(block, client)
            if len(block) < size and not incomplete:
                extensions.append(block.missing("tls.handshake.extensions_missing", size - len(block)))
            fields.append(block.layer("tls.handshake.extensions", "扩展", extensions))
    except ParseError as error:
        if not incomplete:
            fields.append(span.field("malformed", f"握手格式异常 · {error}", None, len(span), 0))
    return fields


def _cipher(span: Span, offset: int) -> Field:
    value = span.uint(offset, 2)
    return span.field("tls.handshake.ciphersuite", "加密套件", value, offset, 2, text=CIPHERS.get(value, f"0x{value:04x}"))


def _extensions(span: Span, client: bool) -> list[Field]:
    fields = []
    cursor = 0
    while cursor < len(span) and len(fields) < 128:
        if len(span) - cursor < 4:
            fields.append(span.payload(cursor, label="扩展头未完整"))
            break
        kind, size = span.unpack("!HH", cursor)
        extension = span.sub(cursor, min(4 + size, len(span) - cursor))
        parts = [
            extension.number("tls.handshake.extension.type", "类型", 0, 2),
            extension.number("tls.handshake.extension.len", "长度", 2, 2),
        ]
        data = extension.sub(4)
        try:
            if kind == 0 and len(data):
                parts.extend(_extension_names(data))
            elif kind == 16:
                parts.extend(_alpn(data))
            elif kind == 43:
                versions = data.sub(1, min(data.uint(0), len(data) - 1)) if client else data
                parts.extend(_version(versions, "tls.handshake.extensions_supported_version", index) for index in range(0, len(versions) & ~1, 2))
            elif kind == 51:
                parts.extend(_key_share(data, client))
            elif len(data):
                parts.append(data.payload(label="扩展数据"))
        except ParseError as error:
            parts.append(data.payload(label=f"扩展内容不完整或异常 · {error}"))
        if len(data) < size:
            parts.append(data.missing("tls.handshake.extension.incomplete", size - len(data)))
        fields.append(extension.layer("tls.handshake.extension", EXTENSIONS.get(kind, f"扩展 {kind}"), parts, kind))
        cursor += len(extension)
    return fields


def _extension_names(span: Span) -> list[Field]:
    vector = span.sub(2, min(span.uint(0, 2), len(span) - 2))
    fields = []
    cursor = 0
    while cursor < len(vector) and len(fields) < 32:
        if len(vector) - cursor < 3:
            break
        name_type, size = vector.unpack("!BH", cursor)
        if cursor + 3 + size > len(vector):
            fields.append(vector.missing("tls.handshake.extensions_server_name.incomplete", cursor + 3 + size - len(vector)))
            break
        name = vector.bytes(cursor + 3, size).decode("ascii", "replace")
        fields.append(vector.field("tls.handshake.extensions_server_name", f"服务器名称（类型 {name_type}）", name, cursor + 3, size))
        cursor += 3 + size
    return fields


def _alpn(span: Span) -> list[Field]:
    vector = span.sub(2, min(span.uint(0, 2), len(span) - 2))
    fields = []
    cursor = 0
    while cursor < len(vector) and len(fields) < 64:
        size = vector.uint(cursor)
        if not size:
            raise ParseError("ALPN 协议名长度为零")
        if cursor + 1 + size > len(vector):
            fields.append(vector.missing("tls.handshake.extensions_alpn.incomplete", cursor + 1 + size - len(vector)))
            break
        name = vector.bytes(cursor + 1, size).decode("ascii", "replace")
        fields.append(vector.field("tls.handshake.extensions_alpn_str", "ALPN", name, cursor + 1, size))
        cursor += 1 + size
    return fields


def _key_share(span: Span, client: bool) -> list[Field]:
    if client:
        span = span.sub(2, min(span.uint(0, 2), len(span) - 2))
    fields = []
    cursor = 0
    while cursor + 2 <= len(span) and len(fields) < 32:
        fields.append(span.number("tls.handshake.extensions_key_share_group", "密钥交换组", cursor, 2, hexadecimal=True))
        cursor += 2
        if cursor + 2 > len(span):
            break
        size = span.uint(cursor, 2)
        fields.append(span.number("tls.handshake.extensions_key_share_key_exchange_length", "密钥参数长度", cursor, 2))
        cursor += 2
        available = min(size, len(span) - cursor)
        if available:
            fields.append(span.sub(cursor, available).payload(label="密钥参数"))
        cursor += size
    return fields
