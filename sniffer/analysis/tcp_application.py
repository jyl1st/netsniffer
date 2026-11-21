from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace

from sniffer.analysis.streams import Endpoint, TransportFlow
from sniffer.analysis.tcp import (
    ACK, RST, SYN, WINDOW_BYTES, ReassembledMessage, TcpApplication, TcpSegment, TcpSequenceBuffer,
)
from sniffer.dissect.app_detect import Application, identify_application
from sniffer.dissect.field import Span
from sniffer.dissect.http import MAX_HEADER_BYTES, MAX_START_LINE, http_info
from sniffer.dissect.tls import tls_handshake_info, tls_record_header
from sniffer.model.packet import PacketRecord

MAX_CONNECTIONS = 128
MAX_MESSAGES_PER_PACKET = 32


@dataclass(slots=True)
class _Direction:
    buffer: TcpSequenceBuffer = field(default_factory=TcpSequenceBuffer)
    message_starts: deque[int] = field(default_factory=lambda: deque(maxlen=MAX_MESSAGES_PER_PACKET))
    http_body_remaining: int = 0
    opaque: bool = False
    tls_hello: bytearray = field(default_factory=bytearray)
    tls_encrypted: bool = False

    def stop_parsing(self) -> None:
        self.buffer.clear()
        self.opaque = True


@dataclass(slots=True)
class _Connection:
    directions: dict[Endpoint, _Direction] = field(default_factory=dict)
    protocol: str | None = None
    initial_syn: tuple[Endpoint, int] | None = None


class TcpApplicationTracker:
    """由文件读取线程或实时抓包线程独占，按捕获顺序处理 TCP 帧。"""

    def __init__(self):
        self._connections: OrderedDict[tuple[Endpoint, Endpoint], _Connection] = OrderedDict()

    def process(self, record: PacketRecord) -> PacketRecord:
        segment, flow = record.summary.tcp, record.summary.flow
        if segment is None or flow is None:
            return record

        syn = bool(segment.flags & SYN)
        if segment.flags & RST:
            self._connections.pop(flow.endpoints, None)
            return record
        if not syn and segment.start == segment.end:
            return record

        connection = self._connection(flow, segment, syn)
        direction = connection.directions.get(flow.source)
        if direction is None:
            direction = connection.directions[flow.source] = _Direction()
        payload = record.raw[segment.start:segment.end]
        buffer = direction.buffer
        start = buffer.add(segment.sequence, payload if not direction.opaque else b"", syn=syn)
        if not direction.opaque:
            _recognize(connection, buffer, flow, start, payload)
        keep_local = start in direction.message_starts or (
            not direction.opaque and not direction.http_body_remaining and start == buffer.position
        )
        messages: tuple[ReassembledMessage, ...] = ()
        if not direction.opaque and buffer.anchored:
            if connection.protocol in ("DNS", "HTTP", "TLS"):
                local_protocol = record.summary.protocol if keep_local else None
                messages = _complete_messages(direction, connection.protocol, local_protocol, start, payload)
            elif connection.protocol is not None:
                if keep_local:
                    direction.message_starts.append(start)
                direction.stop_parsing()

        protocol = connection.protocol
        if not payload or protocol is None:
            return record
        keep_local = keep_local and record.summary.protocol in ("TCP", protocol)
        if keep_local and record.summary.protocol == protocol and not messages:
            return record
        description = f"{protocol} · 沿用 TCP 流识别"
        if messages:
            description = f"{protocol} · TCP 重组"
            hello = next((item.data for item in messages if item.parser == "tls_handshake"), None)
            if hello is not None:
                description += f" · {tls_handshake_info(Span(hello, 0, len(hello)))}"
            else:
                result = _identify(messages[0].data, flow)
                if result and result.protocol == protocol:
                    description += f" · {result.info}"
        application = TcpApplication(protocol, keep_local, messages, f"{description} · {segment.transport_info}")
        return replace(record, tcp_application=application)

    def _connection(self, flow: TransportFlow, segment: TcpSegment, syn: bool) -> _Connection:
        key = flow.endpoints
        connection = self._connections.get(key)
        initial = (flow.source, segment.sequence) if syn and not segment.flags & ACK else None
        if connection is not None and initial is not None and connection.initial_syn != initial:
            # 新的初始 SYN 表示四元组被下一条连接复用。同序号的 SYN 重传沿用现有状态。
            if connection.initial_syn is not None or connection.protocol is not None:
                connection = None
        if connection is None:
            self._connections[key] = connection = _Connection()
        if initial is not None:
            connection.initial_syn = initial
        self._connections.move_to_end(key)
        if len(self._connections) > MAX_CONNECTIONS:
            self._connections.popitem(last=False)
        return connection


def _identify(payload: bytes, flow: TransportFlow) -> Application | None:
    return identify_application(payload, 0, len(payload), 6, flow.source[1], flow.destination[1])


def _recognize(
    connection: _Connection, buffer: TcpSequenceBuffer, flow: TransportFlow, start: int, payload: bytes,
) -> None:
    if buffer.anchored and connection.protocol is not None:
        return
    data = buffer.contiguous()
    if data:
        protocol = _confirmed_protocol(bytes(data), flow)
        if protocol and connection.protocol in (None, protocol):
            connection.protocol = protocol
            buffer.advance(0)
            return
    position = buffer.position
    # 从连接中途开始抓包时，可用新段的已校验报头定位首个消息边界。
    if not buffer.anchored and position is not None and start > position:
        protocol = _confirmed_protocol(payload, flow)
        if protocol and connection.protocol in (None, protocol):
            connection.protocol = protocol
            buffer.advance(start - position)


def _confirmed_protocol(data: bytes, flow: TransportFlow) -> str | None:
    result = _identify(data, flow)
    if result is None or result.protocol is None:
        return None
    # DNS 的端口只是线索，等到长度前缀限定的整个消息可校验才沿用识别。
    if result.protocol == "DNS" and len(data) < int.from_bytes(data[:2], "big") + 2:
        return None
    if result.protocol == "HTTP" and data.find(b"\r\n", 0, MAX_START_LINE) < 0:
        return None
    return result.protocol


def _complete_messages(
    direction: _Direction, protocol: str, local_protocol: str | None, start: int, payload: bytes,
) -> tuple[ReassembledMessage, ...]:
    messages = []
    buffer = direction.buffer
    parser = "dns_tcp" if protocol == "DNS" else protocol.lower()
    for _ in range(MAX_MESSAGES_PER_PACKET):
        data = buffer.contiguous()
        if not data:
            break
        if direction.http_body_remaining:
            skip = min(len(data), direction.http_body_remaining)
            direction.http_body_remaining -= skip
            buffer.advance(skip)
            continue
        length = _message_size(protocol, data)
        if length is None or length > len(data):
            break
        position = buffer.position
        assert position is not None
        direction.message_starts.append(position)
        offset = position - start
        message = bytes(data[:length])
        # DNS 和 TLS 的帧内解析器本来就能读同一段内的多个消息。
        already_local = (
            protocol == local_protocol and offset >= 0 and (offset == 0 or protocol != "HTTP")
            and message == payload[offset:offset + length]
        )
        if not already_local:
            messages.append(ReassembledMessage(parser, message))
        buffer.advance(length)
        if protocol == "TLS":
            handshake = _tls_hello(direction, message)
            if handshake is not None:
                messages.append(ReassembledMessage("tls_handshake", handshake))
        elif protocol == "HTTP":
            body_length = _http_body_length(message)
            if body_length is None:
                direction.stop_parsing()
                break
            direction.http_body_remaining = body_length
    return tuple(messages)


def _tls_hello(direction: _Direction, record: bytes) -> bytes | None:
    kind = record[0]
    pending = direction.tls_hello
    if kind != 22:
        pending.clear()
        direction.tls_encrypted |= kind in (20, 23)
        return None
    if direction.tls_encrypted or (not pending and record[5] not in (1, 2)):
        return None
    was_partial = bool(pending)
    pending.extend(record[5:])
    if len(pending) < 4:
        return None
    length = 4 + int.from_bytes(pending[1:4], "big")
    if len(pending) < length <= WINDOW_BYTES:
        return None
    hello = bytes(pending[:length]) if was_partial and length <= len(pending) else None
    pending.clear()
    return hello


def _message_size(protocol: str, data: bytearray) -> int | None:
    if protocol == "TLS":
        header = tls_record_header(data, 0, len(data))
        return 5 + header[2] if header is not None else None
    if protocol == "DNS":
        size = int.from_bytes(data[:2], "big")
        return size + 2 if len(data) >= 2 and size >= 12 else None
    stop = data.find(b"\r\n\r\n", 0, MAX_HEADER_BYTES)
    if stop >= 0 and http_info(data, 0, stop + 4) is not None:
        return stop + 4
    return None


def _http_body_length(message: bytes) -> int | None:
    first, *headers = message.split(b"\r\n")
    response = first.startswith(b"HTTP/")
    if response:
        status = int(first.split(b" ", 2)[1])
        if status == 101:
            return None  # 协议升级后的字节没有 HTTP/1.x 消息边界。
        if status < 200 or status in (204, 304):
            return 0

    lengths = set()
    for header in headers:
        name, _, value = header.partition(b":")
        name = name.lower()
        if name == b"transfer-encoding":
            return None
        if name == b"content-length":
            for item in value.split(b","):
                digits = item.strip(b" \t")
                if not digits.isdigit() or len(digits) > 16:
                    return None
                lengths.add(int(digits))
    if len(lengths) == 1:
        return lengths.pop()
    return None if lengths or response else 0
