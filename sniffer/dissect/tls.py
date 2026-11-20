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


def parse_tls(span: Span, _registry, _network) -> Field:
    fields = []
    cursor = 0
    for _ in range(32):
        if cursor >= len(span):
            break
        if len(span) - cursor < 5:
            fields.append(span.payload(cursor, label="TLS 记录头未完整捕获"))
            break
        kind, version, declared_length = span.unpack("!BHH", cursor)
        if kind not in RECORD_TYPES or version >> 8 != 3:
            fields.append(span.payload(cursor, label="TLS 记录边界未知"))
            break
        record = span.sub(cursor, min(declared_length + 5, len(span) - cursor))
        parts = [
            record.field("tls.record.content_type", "内容类型", kind, 0, 1, text=RECORD_TYPES[kind]),
            _version(record, "tls.record.version", 1),
            record.number("tls.record.length", "记录长度", 3, 2),
        ]
        if len(record) < declared_length + 5:
            parts.append(record.field("tls.record.truncated", "TLS 记录未完整捕获", True, len(record), 0))
        if kind == 22 and len(record) > 5:
            parts.extend(_handshakes(record.sub(5)))
        elif len(record) > 5:
            parts.append(record.payload(5, "tls.record.payload", "记录内容"))
        fields.append(record.layer("tls.record", f"TLS 记录 · {RECORD_TYPES[kind]}", parts))
        cursor += len(record)
    if not fields:
        raise ParseError("没有 TLS 记录")
    return span.layer("tls", "TLS", fields)


def _version(span: Span, name: str, offset: int) -> Field:
    value = span.uint(offset, 2)
    return span.field(name, "版本", value, offset, 2, text=f"{VERSIONS.get(value, '未知')} (0x{value:04x})")


def _handshakes(span: Span) -> list[Field]:
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
        if len(message) < size + 4:
            details.append(message.payload(4, label="握手跨记录或 TCP 段"))
        elif kind in (1, 2):
            try:
                details.extend(_hello(message.sub(4), client=kind == 1))
            except ParseError as error:
                details.append(message.sub(4).layer("malformed", f"握手格式异常 · {error}", ()))
        elif size:
            details.append(message.payload(4, label="握手数据"))
        fields.append(message.layer("tls.handshake", title, details))
        cursor += len(message)
    return fields


def _hello(span: Span, *, client: bool) -> list[Field]:
    session_length = span.uint(34)
    fields = [
        _version(span, "tls.handshake.version", 0),
        span.field("tls.handshake.random", "随机数", span.bytes(2, 32).hex(), 2, 32),
        span.number("tls.handshake.session_id_length", "会话 ID 长度", 34),
    ]
    if session_length:
        fields.append(span.field("tls.handshake.session_id", "会话 ID", span.bytes(35, session_length).hex(), 35, session_length))
    cursor = 35 + session_length
    if client:
        size = span.uint(cursor, 2)
        if size % 2:
            raise ParseError("ClientHello 加密套件列表长度不是偶数")
        vector = span.sub(cursor + 2, size)
        suites = [_cipher(vector, index) for index in range(0, min(size, 512), 2)]
        fields.append(vector.layer("tls.handshake.ciphersuites", "加密套件", suites))
        cursor += 2 + size
        size = span.uint(cursor)
        vector = span.sub(cursor + 1, size)
        fields.append(vector.layer("tls.handshake.compression_methods", "压缩方式", [
            vector.number("tls.handshake.comp_method", "压缩方式", index) for index in range(size)
        ]))
        cursor += 1 + size
    else:
        fields.extend([_cipher(span, cursor), span.number("tls.handshake.comp_method", "压缩方式", cursor + 2)])
        cursor += 3
    if cursor < len(span):
        block = span.sub(cursor + 2, span.uint(cursor, 2))
        fields.append(block.layer("tls.handshake.extensions", "扩展", _extensions(block, client)))
    return fields


def _cipher(span: Span, offset: int) -> Field:
    value = span.uint(offset, 2)
    return span.field("tls.handshake.ciphersuite", "加密套件", value, offset, 2, text=CIPHERS.get(value, f"0x{value:04x}"))


def _extensions(span: Span, client: bool) -> list[Field]:
    fields = []
    cursor = 0
    while cursor < len(span) and len(fields) < 128:
        kind, size = span.unpack("!HH", cursor)
        extension = span.sub(cursor, 4 + size)
        parts = [
            extension.number("tls.handshake.extension.type", "类型", 0, 2),
            extension.number("tls.handshake.extension.len", "长度", 2, 2),
        ]
        data = extension.sub(4)
        if kind == 0 and size:
            parts.extend(_extension_names(data))
        elif kind == 16:
            parts.extend(_alpn(data))
        elif kind == 43:
            versions = data.sub(1, data.uint(0)) if client else data
            if len(versions) % 2:
                raise ParseError("支持版本列表长度不是偶数")
            parts.extend(_version(versions, "tls.handshake.extensions_supported_version", index) for index in range(0, len(versions), 2))
        elif size:
            parts.append(data.payload(label="扩展数据"))
        fields.append(extension.layer("tls.handshake.extension", EXTENSIONS.get(kind, f"扩展 {kind}"), parts, kind))
        cursor += len(extension)
    return fields


def _extension_names(span: Span) -> list[Field]:
    vector = span.sub(2, span.uint(0, 2))
    fields = []
    cursor = 0
    while cursor < len(vector) and len(fields) < 32:
        name_type, size = vector.unpack("!BH", cursor)
        name = vector.bytes(cursor + 3, size).decode("ascii", "replace")
        fields.append(vector.field("tls.handshake.extensions_server_name", f"服务器名称（类型 {name_type}）", name, cursor + 3, size))
        cursor += 3 + size
    return fields


def _alpn(span: Span) -> list[Field]:
    vector = span.sub(2, span.uint(0, 2))
    fields = []
    cursor = 0
    while cursor < len(vector) and len(fields) < 64:
        size = vector.uint(cursor)
        if not size:
            raise ParseError("ALPN 协议名长度为零")
        name = vector.bytes(cursor + 1, size).decode("ascii", "replace")
        fields.append(vector.field("tls.handshake.extensions_alpn_str", "ALPN", name, cursor + 1, size))
        cursor += 1 + size
    return fields
