from decimal import Decimal

from sniffer.dissect.field import Field, Span

MODES = {1: "主动对等", 2: "被动对等", 3: "客户端", 4: "服务端", 5: "广播", 6: "控制消息", 7: "私有"}


def parse_ntp(span: Span, _registry, _network) -> Field:
    flags = span.uint(0)
    mode = flags & 7
    fields = [
        span.field("ntp.flags.li", "闰秒指示", flags >> 6, 0, 1),
        span.field("ntp.flags.vn", "版本", (flags >> 3) & 7, 0, 1),
        span.field("ntp.flags.mode", "模式", mode, 0, 1, text=MODES.get(mode, str(mode))),
    ]
    if mode in (6, 7):
        fields.append(span.payload(1, label="NTP 控制或私有数据"))
        return span.layer("ntp", f"NTP · {MODES[mode]}", fields)

    span.require(0, 48)
    fields.extend([
        span.number("ntp.stratum", "层级", 1),
        span.number("ntp.poll", "轮询间隔指数", 2, signed=True),
        span.number("ntp.precision", "精度指数", 3, signed=True),
        span.field("ntp.rootdelay", "根延迟（秒）", Decimal(span.uint(4, 4, signed=True)) / 65536, 4, 4),
        span.field("ntp.rootdispersion", "根离散（秒）", Decimal(span.uint(8, 4)) / 65536, 8, 4),
        span.number("ntp.refid", "参考 ID", 12, 4, hexadecimal=True),
    ])
    for offset, name, label in (
        (16, "reftime", "参考时刻"), (24, "org", "起始时刻"),
        (32, "rec", "接收时刻"), (40, "xmt", "发送时刻"),
    ):
        seconds, fraction = span.unpack("!II", offset)
        value = Decimal(seconds) + Decimal(fraction) / (1 << 32)
        fields.append(span.field(f"ntp.{name}", label, value, offset, 8))
    if len(span) > 48:
        fields.append(span.payload(48, label="NTP 扩展或认证数据"))
    return span.layer("ntp", f"NTP · {MODES.get(mode, mode)}", fields)
