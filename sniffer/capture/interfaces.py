from dataclasses import dataclass
from ipaddress import ip_address
from time import monotonic

import psutil
from scapy.all import conf

ETHERNET = "有线"
WIRELESS = "无线"
VIRTUAL = "虚拟"
LOOPBACK = "回环"
OTHER = "其他"

VIRTUAL_MARKERS = (
    "virtual", "vmware", "vbox", "hyper-v", "vethernet", "miniport",
    "vpn", "tunnel", "wireguard", "wintun", "tap-", "wi-fi direct", "虚拟",
)


@dataclass(frozen=True, slots=True)
class Adapter:
    device: str
    name: str
    description: str
    kind: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    mac: str

    @property
    def has_usable_ip(self) -> bool:
        return any(
            not (address.is_link_local or address.is_loopback or address.is_unspecified)
            for address in map(ip_address, self.ipv4 + self.ipv6)
        )


def _adapter_kind(interface) -> str:
    # Windows IANA ifType：6 为以太网、24 为软件回环、71 为无线。
    description = f"{interface.name} {interface.description}".casefold()
    if interface.type == 24 or "loopback" in description or "回环" in description:
        return LOOPBACK
    if interface.type in (53, 131) or any(marker in description for marker in VIRTUAL_MARKERS):
        return VIRTUAL
    if interface.type == 71 or "wireless" in description or "802.11" in description:
        return WIRELESS
    if interface.type == 6:
        return ETHERNET
    return OTHER


def list_adapters() -> list[Adapter]:
    adapters = []
    for interface in conf.ifaces.values():
        name = interface.name or interface.network_name
        kind = _adapter_kind(interface)
        mac = interface.mac
        if mac in ("00:00:00:00:00:00", ""):
            mac = "—"
        adapters.append(
            Adapter(
                interface.network_name,
                name,
                interface.description or name,
                kind,
                tuple(sorted(set(interface.ips.get(4, ())))),
                tuple(sorted(set(interface.ips.get(6, ())))),
                mac or "—",
            )
        )
    return sorted(adapters, key=lambda adapter: (adapter.kind not in (WIRELESS, ETHERNET), adapter.name))


def read_counters() -> tuple[float, dict[str, int]]:
    counters = psutil.net_io_counters(pernic=True) or {}
    return monotonic(), {
        name: values.bytes_sent + values.bytes_recv for name, values in counters.items()
    }


def preferred_adapter(adapters: list[Adapter], rates: dict[str, float]) -> int:
    return max(
        range(len(adapters)),
        key=lambda row: (
            adapters[row].kind in (WIRELESS, ETHERNET) and adapters[row].has_usable_ip,
            adapters[row].has_usable_ip,
            rates.get(adapters[row].name, 0),
        ),
        default=-1,
    )
