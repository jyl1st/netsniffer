from decimal import Decimal

from sniffer.dissect.field import Field, Span

MODES = {1: "主动对等", 2: "被动对等", 3: "客户端", 4: "服务端", 5: "广播", 6: "控制消息", 7: "私有"}


def ntp_info(span: Span) -> str | None:
    flags = span.uint(0)
    version, mode = (flags >> 3) & 7, flags & 7
    if version not in (1, 2, 3, 4):
        return None
    if 1 <= mode <= 5 and len(span) >= 48 and span.uint(1) <= 16:
        if (len(span) % 4 == 0 and -6 <= span.uint(2, signed=True) <= 17
                and -40 <= span.uint(3, signed=True) <= 5 and span.uint(40, 8) and _valid_time_tail(span)):
            return f"NTPv{version} · {MODES[mode]}"
    if mode == 6 and _valid_control(span):
        return f"NTPv{version} · 控制消息"
    return None


def _valid_control(span: Span) -> bool:
    if len(span) < 12 or span.uint(0) >> 6:
        return False
    flags = span.uint(1)
    opcode = flags & 31
    if opcode not in range(1, 13) and opcode != 31:
        return False
    if not flags & 0x80 and (flags & 0x60 or span.uint(8, 2)):
        return False
    size = span.uint(10, 2)
    end = 12 + size
    if size > 468 or end > len(span):
        return False
    if end == len(span):
        return True
    padded = (end + 3) & ~3
    return len(span) - padded in (0, 20, 24) and not any(span.bytes(end, padded - end))


def _valid_time_tail(span: Span) -> bool:
    cursor = 48
    for _ in range(16):
        left = len(span) - cursor
        if left in (0, 4, 20, 24, 36):
            return True
        if left < 16:
            return False
        size = span.uint(cursor + 2, 2)
        if not 16 <= size <= left or size % 4:
            return False
        cursor += size
    return False


def parse_ntp(span: Span, _registry, _network) -> Field:
    if not len(span):
        return span.layer("ntp", "NTP · 报头不完整", [span.missing("ntp.incomplete", 1)])
    flags = span.uint(0)
    mode = flags & 7
    fields = [
        span.field("ntp.flags.li", "闰秒指示", flags >> 6, 0, 1),
        span.field("ntp.flags.vn", "版本", (flags >> 3) & 7, 0, 1),
        span.field("ntp.flags.mode", "模式", mode, 0, 1, text=MODES.get(mode, str(mode))),
    ]
    if mode in (6, 7):
        fields.append(span.payload(1, label="NTP 控制或私有数据"))
        minimum = 12 if mode == 6 else 8
        if len(span) < minimum:
            fields.append(span.missing("ntp.incomplete", minimum - len(span)))
        return span.layer("ntp", f"NTP · {MODES[mode]}", fields)

    for name, label, offset in (("stratum", "层级", 1), ("poll", "轮询间隔指数", 2), ("precision", "精度指数", 3)):
        if offset < len(span):
            fields.append(span.number(f"ntp.{name}", label, offset, signed=offset != 1))
    if len(span) >= 8:
        fields.append(span.field("ntp.rootdelay", "根延迟（秒）", Decimal(span.uint(4, 4, signed=True)) / 65536, 4, 4))
    if len(span) >= 12:
        fields.append(span.field("ntp.rootdispersion", "根离散（秒）", Decimal(span.uint(8, 4)) / 65536, 8, 4))
    if len(span) >= 16:
        fields.append(span.number("ntp.refid", "参考 ID", 12, 4, hexadecimal=True))
    for offset, name, label in (
        (16, "reftime", "参考时刻"), (24, "org", "起始时刻"),
        (32, "rec", "接收时刻"), (40, "xmt", "发送时刻"),
    ):
        if offset + 8 > len(span):
            break
        seconds, fraction = span.unpack("!II", offset)
        value = Decimal(seconds) + Decimal(fraction) / (1 << 32)
        fields.append(span.field(f"ntp.{name}", label, value, offset, 8))
    if len(span) > 48:
        fields.append(span.payload(48, label="NTP 扩展或认证数据"))
    elif len(span) < 48:
        fields.append(span.missing("ntp.incomplete", 48 - len(span)))
    return span.layer("ntp", f"NTP · {MODES.get(mode, mode)}", fields)
