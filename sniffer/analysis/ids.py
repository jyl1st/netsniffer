from base64 import b64decode
from binascii import Error as Base64Error
from collections import Counter, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from decimal import Decimal
from enum import Enum
from ipaddress import ip_address
from struct import unpack_from
from urllib.parse import unquote_to_bytes

from sniffer.analysis.streams import Endpoint, TransportFlow
from sniffer.analysis.tcp import ACK, HALF_SEQUENCE_SPACE, RST, SEQUENCE_MASK, SYN, TcpSegment, TcpSequenceBuffer
from sniffer.dissect.ethernet import VLAN_TYPES
from sniffer.dissect.http import MAX_HEADER_BYTES, REQUEST_LINE
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SCAN_WINDOW_SECONDS = 10
SCAN_MIN_PORTS = 15
MAX_FORM_BYTES = 16_384
MAX_FTP_LINE_BYTES = 4_096
FTP_CONTROL_PORT = 21
PASSWORD_FIELDS = frozenset((b"password", b"passwd", b"pwd", b"pass"))
FORM_USERNAME_FIELDS = frozenset((b"username", b"user"))

Direction = tuple[Endpoint, Endpoint]


class AlertKind(Enum):
    ARP_SPOOFING = "ARP 欺骗"
    SYN_SCAN = "SYN 扫描"
    PLAINTEXT_CREDENTIAL = "明文凭据"


class AlertSeverity(Enum):
    HIGH = "高"
    WARNING = "警告"


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    kind: AlertKind
    severity: AlertSeverity
    first_frame: int
    frames: tuple[int, ...]
    source: str
    description: str


def analyze_alerts(records: Sequence[PacketRecord]) -> tuple[SecurityAlert, ...]:
    """按原始帧号分析一次抓包快照。输出只包含打码后的凭据描述。"""
    alerts: list[SecurityAlert] = []
    arp_bindings: dict[str, tuple[str, int]] = {}
    scans = _SynScans()
    credentials = _Credentials(alerts)
    for frame, record in enumerate(records, 1):
        if record.summary.protocol == "ARP":
            alert = _check_arp(record, frame, arp_bindings)
            if alert is not None:
                alerts.append(alert)
        segment, flow = record.summary.tcp, record.summary.flow
        if segment is not None and flow is not None:
            if record.timestamp is not None:
                scans.observe(flow, segment, frame, record.timestamp)
            credentials.observe(record, flow, segment, frame)
    credentials.finish()
    alerts.extend(scans.alerts())
    return tuple(sorted(alerts, key=lambda alert: alert.first_frame))


def _check_arp(
    record: PacketRecord, frame: int, bindings: dict[str, tuple[str, int]],
) -> SecurityAlert | None:
    raw = record.raw
    if record.linktype != LINKTYPE_ETHERNET or len(raw) < 14:
        return None
    ether_type, = unpack_from("!H", raw, 12)
    start = 14
    while ether_type in VLAN_TYPES and start < 46 and len(raw) >= start + 4:
        ether_type, = unpack_from("!H", raw, start + 2)
        start += 4
    if ether_type != 0x0806 or len(raw) < start + 28:
        return None
    # ARP 的 sender 可能与外层以太网源地址不同，按 ARP 中声明的绑定比较。
    hardware, network, mac_size, ip_size, operation = unpack_from("!HHBBH", raw, start)
    if (hardware, network, mac_size, ip_size) != (1, 0x0800, 6, 4) or operation not in (1, 2):
        return None
    sender = raw[start + 14:start + 18]
    if sender == bytes(4):
        return None
    mac = raw[start + 8:start + 14].hex(":")
    address = str(ip_address(sender))
    previous = bindings.get(address)
    bindings[address] = mac, frame
    if previous is None or previous[0] == mac:
        return None
    old_mac, old_frame = previous
    gratuitous = sender == raw[start + 24:start + 28]
    prefix = "免费 ARP 改写" if gratuitous else "ARP 映射变更"
    return SecurityAlert(
        AlertKind.ARP_SPOOFING, AlertSeverity.HIGH if gratuitous else AlertSeverity.WARNING,
        old_frame, (old_frame, frame), f"{address} / {mac}",
        f"{prefix}：{address} 由 {old_mac}（帧 {old_frame}）变为 {mac}（帧 {frame}）。",
    )


@dataclass(slots=True)
class _Probe:
    frame: int
    timestamp: Decimal
    port: int
    ack_expected: int
    # 0 无响应，1 关闭，2 开放。一次 SYN/ACK 优先于后续 RST。
    result: int = 0
    reply: int | None = None


class _SynScans:
    def __init__(self):
        self._groups: dict[tuple[bytes, bytes], list[_Probe]] = defaultdict(list)
        self._pending: dict[Direction, _Probe] = {}

    def observe(self, flow: TransportFlow, tcp: TcpSegment, frame: int, timestamp: Decimal) -> None:
        source, target = flow.source, flow.destination
        if tcp.flags == SYN and tcp.payload_len == 0:
            probe = _Probe(frame, timestamp, target[1], (tcp.sequence + 1) & SEQUENCE_MASK)
            self._groups[source[0], target[0]].append(probe)
            self._pending[source, target] = probe
            return
        if tcp.flags & RST:
            result = 1
        elif tcp.flags & (SYN | ACK) == (SYN | ACK):
            result = 2
        else:
            return
        # 响应必须是反向四元组，若声明了 ACK，还须确认相应的 SYN。
        probe = self._pending.get((target, source))
        if probe is not None and result > probe.result and 0 <= timestamp - probe.timestamp <= SCAN_WINDOW_SECONDS:
            if not tcp.flags & ACK or tcp.ack == probe.ack_expected:
                probe.result, probe.reply = result, frame

    def alerts(self) -> Iterator[SecurityAlert]:
        for (source, target), probes in self._groups.items():
            if len(probes) < SCAN_MIN_PORTS:
                continue
            probes.sort(key=lambda probe: (probe.timestamp, probe.frame))
            for window in _scan_windows(probes):
                results: dict[int, int] = {}
                frames = set()
                for probe in window:
                    results[probe.port] = max(probe.result, results.get(probe.port, 0))
                    frames.add(probe.frame)
                    if probe.reply is not None:
                        frames.add(probe.reply)
                counts = Counter(results.values())
                opened = ", ".join(str(port) for port in sorted(results) if results[port] == 2) or "无"
                address = str(ip_address(source))
                yield SecurityAlert(
                    AlertKind.SYN_SCAN, AlertSeverity.WARNING, min(frames), tuple(sorted(frames)), address,
                    f"{address} 向 {ip_address(target)} 的 {len(results)} 个端口发送 SYN。"
                    f"开放 {counts[2]}（端口 {opened}），关闭 {counts[1]}，过滤（无响应）{counts[0]}。",
                )


def _scan_windows(probes: list[_Probe]) -> Iterator[list[_Probe]]:
    # 滑动窗口按源和目标主机分别统计不同目的端口，重发同端口的 SYN 不增加计数。
    ports: Counter[int] = Counter()
    start = 0
    stop = 0
    while stop < len(probes):
        probe = probes[stop]
        while probe.timestamp - probes[start].timestamp > SCAN_WINDOW_SECONDS:
            port = probes[start].port
            ports[port] -= 1
            if ports[port] == 0:
                del ports[port]
            start += 1
        ports[probe.port] += 1
        stop += 1
        if len(ports) >= SCAN_MIN_PORTS:
            # 达到阈值后纳入该窗口内余下的探测，只生成一条汇总告警。
            while stop < len(probes) and probes[stop].timestamp - probes[start].timestamp <= SCAN_WINDOW_SECONDS:
                stop += 1
            yield probes[start:stop]
            start = stop
            ports.clear()


@dataclass(slots=True)
class _FormBody:
    sequence: int
    size: int
    frame: int
    frames: set[int] = field(default_factory=set)
    buffer: TcpSequenceBuffer = field(default_factory=TcpSequenceBuffer)

    def __post_init__(self) -> None:
        self.buffer.add(self.sequence, b"")
        self.buffer.advance(0)

    def feed(self, sequence: int, payload: bytes, frame: int) -> bool:
        delta = ((sequence - self.sequence + HALF_SEQUENCE_SPACE) & SEQUENCE_MASK) - HALF_SEQUENCE_SPACE
        start, stop = max(0, -delta), min(len(payload), self.size - delta)
        if start < stop:
            self.buffer.add((sequence + start) & SEQUENCE_MASK, payload[start:stop])
            self.frames.add(frame)
        data = self.buffer.contiguous()
        return data is not None and len(data) >= self.size


@dataclass(slots=True)
class _HttpDirection:
    seen_headers: set[int] = field(default_factory=set)
    form: _FormBody | None = None


@dataclass(slots=True)
class _FtpDirection:
    buffer: TcpSequenceBuffer = field(default_factory=TcpSequenceBuffer)
    user: str = ""
    user_frame: int | None = None
    discarding_line: bool = False


class _Credentials:
    def __init__(self, alerts: list[SecurityAlert]):
        self.alerts = alerts
        self._http: dict[Direction, _HttpDirection] = {}
        self._ftp: dict[Direction, _FtpDirection] = {}

    def observe(self, record: PacketRecord, flow: TransportFlow, tcp: TcpSegment, frame: int) -> None:
        key = flow.source, flow.destination
        if tcp.flags & RST or tcp.flags & (SYN | ACK) == SYN:
            self._end_direction(key)
            self._end_direction((flow.destination, flow.source))
        if tcp.flags & RST:
            return
        if flow.destination[1] == FTP_CONTROL_PORT:
            if tcp.payload_len or tcp.flags & SYN:
                self._read_ftp(record.raw[tcp.start:tcp.end], tcp, key, frame)
        elif tcp.payload_len and (record.protocol == "HTTP" or key in self._http):
            self._read_http(record, tcp, key, frame)

    def finish(self) -> None:
        for (source, _), state in self._http.items():
            self._finish_form(source, state)

    def _end_direction(self, key: Direction) -> None:
        http = self._http.pop(key, None)
        if http is not None:
            self._finish_form(key[0], http)
        self._ftp.pop(key, None)

    def _read_http(self, record: PacketRecord, tcp: TcpSegment, key: Direction, frame: int) -> None:
        payload = record.raw[tcp.start:tcp.end]
        sequence = (tcp.sequence + bool(tcp.flags & SYN)) & SEQUENCE_MASK
        source = key[0]
        state = self._http.setdefault(key, _HttpDirection())
        if state.form is not None and state.form.feed(sequence, payload, frame):
            self._finish_form(source, state)

        app = record.tcp_application
        # 重组器只为需要重组展示的 HTTP 消息附完整头部，帧内完整的头部从当前负载读取。
        headers: list[tuple[bytes, int | None]] = []
        end = payload.find(b"\r\n\r\n", 0, MAX_HEADER_BYTES)
        if record.summary.protocol == "HTTP" and (app is None or app.keep_local_fields) and end >= 0:
            headers.append((payload[:end + 4], end + 4))
        if app is not None:
            headers.extend((message.data, _header_end_in_payload(message.data, payload))
                           for message in app.messages if message.parser == "http")

        for header, offset in headers:
            request, headers_by_name = _http_request(header)
            if request is None:
                continue
            end_sequence = (sequence + offset) & SEQUENCE_MASK if offset is not None else None
            if end_sequence is not None:
                if end_sequence in state.seen_headers:
                    continue
                state.seen_headers.add(end_sequence)
            basic = _decode_basic(headers_by_name.get(b"authorization", b""))
            if basic is not None:
                user, masked = basic
                self._report(source, (frame,), f"HTTP Basic 用户 {user}，密码 {masked}。")
            content_type = headers_by_name.get(b"content-type", b"").split(b";", 1)[0].strip().lower()
            if request != b"POST" or content_type != b"application/x-www-form-urlencoded" or end_sequence is None:
                continue
            length = headers_by_name.get(b"content-length", b"")
            if not length.isdigit() or len(length) > 16 or b"transfer-encoding" in headers_by_name:
                continue
            self._finish_form(source, state)
            size = min(int(length), MAX_FORM_BYTES)
            if size:
                state.form = _FormBody(end_sequence, size, frame)
                if state.form.feed(sequence, payload, frame):
                    self._finish_form(source, state)

    def _finish_form(self, source: Endpoint, state: _HttpDirection) -> None:
        form = state.form
        state.form = None
        if form is None:
            return
        body = form.buffer.contiguous()
        if not body:
            return
        masked_fields = []
        username = ""
        for item in bytes(body).split(b"&"):
            name, equal, value = item.partition(b"=")
            if not equal or not value:
                continue
            decoded_name = _form_decode(name).lower()
            if decoded_name in PASSWORD_FIELDS:
                masked_fields.append(f"{decoded_name.decode('ascii')}={_mask(_form_decode(value))}")
            elif not username and decoded_name in FORM_USERNAME_FIELDS:
                username = _visible(_form_decode(value))
        if masked_fields:
            frames = tuple(sorted(form.frames | {form.frame}))
            summary = "、".join(masked_fields)
            user = f"用户 {username}，" if username else ""
            self._report(source, frames, f"HTTP POST 表单{user}含明文密码字段 {summary}。")

    def _read_ftp(self, payload: bytes, tcp: TcpSegment, key: Direction, frame: int) -> None:
        state = self._ftp.setdefault(key, _FtpDirection())
        buffer = state.buffer
        buffer.add(tcp.sequence, payload, syn=bool(tcp.flags & SYN))
        if not buffer.anchored:
            buffer.advance(0)
        while data := buffer.contiguous():
            end = data.find(b"\n")
            if end < 0:
                if len(data) > MAX_FTP_LINE_BYTES or state.discarding_line:
                    buffer.advance(len(data))
                    state.discarding_line = True
                break
            if not state.discarding_line and end <= MAX_FTP_LINE_BYTES:
                command, space, value = bytes(data[:end]).removesuffix(b"\r").partition(b" ")
                if space and value:
                    self._ftp_command(state, command.upper(), value, key[0], frame)
            state.discarding_line = False
            buffer.advance(end + 1)

    def _ftp_command(self, state: _FtpDirection, command: bytes, value: bytes, source: Endpoint, frame: int) -> None:
        if command == b"USER":
            state.user = _visible(value)
            state.user_frame = frame
        elif command == b"PASS":
            user = f"用户 {state.user}，" if state.user_frame is not None else ""
            frames = tuple(sorted({state.user_frame or frame, frame}))
            self._report(source, frames, f"FTP USER/PASS {user}密码 {_mask(value)}。")

    def _report(self, source: Endpoint, frames: tuple[int, ...], description: str) -> None:
        self.alerts.append(SecurityAlert(
            AlertKind.PLAINTEXT_CREDENTIAL, AlertSeverity.HIGH, frames[0], frames,
            str(ip_address(source[0])), description,
        ))


def _header_end_in_payload(header: bytes, payload: bytes) -> int | None:
    # 重组元数据只含头部。用当前段里一致的头部尾巴定位消息体起点，跨缺口时可能没有交集。
    start = payload.find(header)
    if start >= 0:
        return start + len(header)
    cursor = payload.find(b"\r\n\r\n", 0, min(len(header), len(payload)))
    while cursor >= 0:
        end = cursor + 4
        if header.endswith(payload[:end]):
            return end
        cursor = payload.find(b"\r\n\r\n", end, min(len(header), len(payload)))
    for size in range(min(3, len(payload)), 0, -1):
        if payload[:size] == b"\r\n\r\n"[-size:]:
            return size
    return None


def _http_request(header: bytes) -> tuple[bytes | None, dict[bytes, bytes]]:
    line, _, rest = header.partition(b"\r\n")
    request = REQUEST_LINE.fullmatch(line)
    if request is None:
        return None, {}
    headers = {}
    for line in rest.split(b"\r\n"):
        name, colon, value = line.partition(b":")
        if colon:
            headers.setdefault(name.lower(), value.strip())
    return request.group(1), headers


def _decode_basic(value: bytes) -> tuple[str, str] | None:
    parts = value.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != b"basic":
        return None
    try:
        user, colon, password = b64decode(parts[1], validate=True).partition(b":")
    except Base64Error:
        return None
    if colon:
        return _visible(user), _mask(password)
    return None


def _form_decode(value: bytes) -> bytes:
    return unquote_to_bytes(value.replace(b"+", b" "))


def _visible(value: bytes) -> str:
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        text = value.decode("latin-1")
    return "".join(char if char.isprintable() else "�" for char in text)


def _mask(value: bytes) -> str:
    # 在构建告警前立即打码。原始密码只在分析局部变量和原捕获字节中存在。
    first = value[:4].decode("utf-8", "replace")[:1]
    if first == "�":
        first = value[:1].decode("latin-1")
    return (first if first.isprintable() else "") + "***"
