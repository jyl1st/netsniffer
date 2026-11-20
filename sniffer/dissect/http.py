import re

from sniffer.dissect.field import Field, ParseError, Span

REQUEST_LINE = re.compile(rb"([A-Z]+(?:-[A-Z]+)*) ([^ \r\n]+) (HTTP/1\.[01])")
STATUS_LINE = re.compile(rb"(HTTP/1\.[01]) ([0-9]{3})(?: ([^\r\n]*))?")
MAX_HEADER_BYTES = 16_384
MAX_HEADERS = 128


def parse_http(span: Span, _registry, _network) -> Field:
    return _parse_text_headers(span, "http")


def parse_ssdp(span: Span, _registry, _network) -> Field:
    return _parse_text_headers(span, "ssdp")


def _parse_text_headers(span: Span, prefix: str) -> Field:
    end = min(span.end, span.start + MAX_HEADER_BYTES)
    first_end = span.raw.find(b"\r\n", span.start, end)
    title = prefix.upper()
    if first_end < 0:
        return span.layer(prefix, f"{title} · 首行未完整捕获", [span.payload()])
    first_line = span.raw[span.start:first_end]
    status = STATUS_LINE.fullmatch(first_line)
    request = REQUEST_LINE.fullmatch(first_line)
    if status:
        fields = _line_fields(span, status, prefix, ("version", "response.code", "response.phrase"), ("版本", "状态码", "原因"))
    elif request:
        fields = _line_fields(span, request, prefix, ("request.method", "request.uri", "version"), ("方法", "目标", "版本"))
    else:
        raise ParseError(f"{title} 首行格式无效")
    cursor = first_end + 2
    for _ in range(MAX_HEADERS):
        line_end = span.raw.find(b"\r\n", cursor, end)
        if line_end < 0:
            break
        if cursor == line_end:
            cursor += 2
            if cursor < span.end:
                fields.append(span.payload(cursor - span.start, f"{prefix}.body", "消息体"))
            return span.layer(prefix, f"{title} · {first_line.decode('latin-1', 'replace')}", fields)
        fields.append(_header(span.sub(cursor - span.start, line_end - cursor), prefix))
        cursor = line_end + 2
    if cursor <= span.end:
        fields.append(span.payload(cursor - span.start, label="头部未完整捕获或超过展示上限"))
    return span.layer(prefix, f"{title} · {first_line.decode('latin-1', 'replace')}", fields)


def _line_fields(span: Span, match, prefix: str, names: tuple[str, ...], labels: tuple[str, ...]) -> list[Field]:
    fields = []
    for index, (name, label) in enumerate(zip(names, labels), start=1):
        data = match.group(index)
        if data is None:
            continue
        value = int(data) if name == "response.code" else data.decode("latin-1", "replace")
        fields.append(span.field(f"{prefix}.{name}", label, value, match.start(index), len(data)))
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
