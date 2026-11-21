import re

from sniffer.dissect.field import Field, ParseError, Span

REQUEST_LINE = re.compile(rb"([A-Z][A-Z0-9_-]*) ([!-~]+) (HTTP/1\.[01])")
STATUS_LINE = re.compile(rb"(HTTP/1\.[01]) ([1-5][0-9]{2})(?: ([\t -~\x80-\xff]*))?")
MAX_START_LINE = 2048
MAX_HEADER_BYTES = 16_384
MAX_HEADERS = 128


def parse_http(span: Span, _registry, _network) -> Field:
    return _parse_text_headers(span, "http")


def parse_ssdp(span: Span, _registry, _network) -> Field:
    return _parse_text_headers(span, "ssdp")


def _start_line(raw: bytes, start: int, end: int, *, ssdp: bool = False):
    limit = min(end, start + MAX_START_LINE)
    terminator = raw.find(b"\r\n", start, limit)
    if terminator < 0 and limit != end:
        return None
    line_end = end if terminator < 0 else terminator
    if terminator < 0 and line_end > start and raw[line_end - 1] == 13:
        line_end -= 1
    found = STATUS_LINE.fullmatch(raw, start, line_end)
    if found:
        return found, True, line_end, terminator >= 0
    found = REQUEST_LINE.fullmatch(raw, start, line_end)
    if found and (not ssdp or found.group(1) in (b"M-SEARCH", b"NOTIFY")):
        return found, False, line_end, terminator >= 0
    return None


def http_info(raw: bytes, start: int, end: int, *, ssdp: bool = False) -> str | None:
    matched = _start_line(raw, start, end, ssdp=ssdp)
    if matched is None:
        return None
    return raw[start:min(matched[2], start + 160)].decode("latin-1", "replace")


def _parse_text_headers(span: Span, prefix: str) -> Field:
    end = min(span.end, span.start + MAX_HEADER_BYTES)
    title = prefix.upper()
    matched = _start_line(span.raw, span.start, span.end, ssdp=prefix == "ssdp")
    if matched is None:
        raise ParseError(f"不是有效的 {title} 首行")
    match, response, first_end, terminated = matched
    first_line = span.raw[span.start:first_end].decode("latin-1", "replace")
    title = f"{title} · {first_line}"
    if response:
        fields = _line_fields(span, match, prefix, ("version", "response.code", "response.phrase"), ("版本", "状态码", "原因"))
    else:
        fields = _line_fields(span, match, prefix, ("request.method", "request.uri", "version"), ("方法", "目标", "版本"))
    if not terminated:
        return _incomplete_headers(span, prefix, title, fields, len(span))
    cursor = first_end + 2
    for _ in range(MAX_HEADERS):
        line_end = span.raw.find(b"\r\n", cursor, end)
        if line_end < 0:
            if cursor < end and span.raw.find(b":", cursor, end) > cursor:
                fields.append(_header(span.sub(cursor - span.start, end - cursor), prefix))
                cursor = end
            break
        if cursor == line_end:
            cursor += 2
            if cursor < span.end:
                fields.append(span.payload(cursor - span.start, f"{prefix}.body", "消息体"))
            return span.layer(prefix, title, fields)
        fields.append(_header(span.sub(cursor - span.start, line_end - cursor), prefix))
        cursor = line_end + 2
    return _incomplete_headers(span, prefix, title, fields, cursor - span.start)


def _incomplete_headers(span: Span, prefix: str, title: str, fields: list[Field], offset: int) -> Field:
    fields.append(_missing_headers(span, prefix, offset))
    layer = span.layer(prefix, title, fields)
    if prefix == "http" and span.raw.find(b"\r\n\r\n", span.start, span.end) < 0:
        return layer.as_incomplete()
    return layer


def _missing_headers(span: Span, prefix: str, offset: int) -> Field:
    if span.capture_truncated:
        title = "抓包截断 · 预留未完整的头部"
    elif len(span) > MAX_HEADER_BYTES:
        title = "头部超过展示上限"
    else:
        title = "头部未结束 · 后续 TCP 段可能还有内容" if prefix == "http" else "头部未结束"
    return span.field(f"{prefix}.headers_incomplete", title, None, offset, len(span) - offset)


def _line_fields(span: Span, match, prefix: str, names: tuple[str, ...], labels: tuple[str, ...]) -> list[Field]:
    fields = []
    for index, (name, label) in enumerate(zip(names, labels), start=1):
        data = match.group(index)
        if data is None:
            continue
        value = int(data) if name == "response.code" else data.decode("latin-1", "replace")
        fields.append(span.field(f"{prefix}.{name}", label, value, match.start(index) - span.start, len(data)))
    return fields


def _header(span: Span, prefix: str) -> Field:
    raw = span.bytes(0, len(span))
    name, found, value_with_space = raw.partition(b":")
    if not found:
        return span.field(f"{prefix}.header", "头部行", raw.decode("latin-1", "replace"), 0, len(raw))
    value = value_with_space.strip(b" \t")
    skipped = len(value_with_space) - len(value_with_space.lstrip(b" \t"))
    value_offset = len(name) + 1 + skipped
    name_text = name.decode("ascii", "replace")
    suffix = name_text.lower().replace("-", "_")
    return span.layer(f"{prefix}.header", f"{name_text}: {value.decode('latin-1', 'replace')}", [
        span.field(f"{prefix}.header.name", "头部名称", name_text, 0, len(name)),
        span.field(f"{prefix}.{suffix}", "头部值", value.decode("latin-1", "replace"), value_offset, len(value)),
    ])
