from collections import defaultdict
from dataclasses import dataclass, field
from ipaddress import IPv6Address, ip_address
from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM
from threading import Event

import psutil

from sniffer.analysis.streams import Endpoint, TransportFlow, TransportProtocol

SocketKey = tuple[TransportProtocol, Endpoint, Endpoint | None]
REFRESH_SECONDS = 1.0


@dataclass(frozen=True, slots=True)
class ProcessOwner:
    pid: int
    name: str | None

    @property
    def label(self) -> str:
        return f"{self.name} ({self.pid})" if self.name else f"PID {self.pid}"


@dataclass(frozen=True, slots=True)
class ProcessMatch:
    local: Endpoint
    owner: ProcessOwner


@dataclass(frozen=True, slots=True)
class _Snapshot:
    sockets: dict[SocketKey, ProcessOwner | None] = field(default_factory=dict)
    local_ips: frozenset[bytes] = frozenset()

    def owner(
        self, protocol: TransportProtocol, local: Endpoint, remote: Endpoint, *, allow_bound: bool,
    ) -> ProcessOwner | None:
        connected = (protocol, local, remote)
        if connected in self.sockets:
            return self.sockets[connected]
        if not allow_bound:
            return None
        bound = (protocol, local, None)
        if bound in self.sockets:
            return self.sockets[bound]
        ip, port = local
        if ip in self.local_ips:
            return self.sockets.get((protocol, (bytes(len(ip)), port), None))
        return None


def _packed_ip(text: str) -> bytes:
    address = ip_address(text.split("%", 1)[0])
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped.packed
    return address.packed


def _process_owner(pid: int) -> ProcessOwner | None:
    try:
        return ProcessOwner(pid, psutil.Process(pid).name() or None)
    except psutil.NoSuchProcess:
        return None
    except (psutil.AccessDenied, OSError):
        return ProcessOwner(pid, None)


def _local_ips() -> frozenset[bytes]:
    try:
        interfaces = psutil.net_if_addrs()
    except (psutil.Error, OSError):
        return frozenset()
    return frozenset(
        _packed_ip(address.address) for addresses in interfaces.values() for address in addresses
        if address.family in (AF_INET, AF_INET6)
    )


def _read_snapshot() -> _Snapshot:
    bindings: dict[SocketKey, set[int | None]] = defaultdict(set)
    for connection in psutil.net_connections(kind="inet"):
        if not connection.laddr or connection.family not in (AF_INET, AF_INET6):
            continue
        if connection.type == SOCK_STREAM:
            protocol: TransportProtocol = "tcp"
            if not connection.raddr and connection.status != psutil.CONN_LISTEN:
                continue
        elif connection.type == SOCK_DGRAM:
            protocol = "udp"
        else:
            continue
        local = (_packed_ip(connection.laddr[0]), connection.laddr[1])
        remote = (_packed_ip(connection.raddr[0]), connection.raddr[1]) if connection.raddr else None
        bindings[protocol, local, remote].add(connection.pid or None)

    owners: dict[int, ProcessOwner | None] = {}
    sockets: dict[SocketKey, ProcessOwner | None] = {}
    for key, pids in bindings.items():
        if len(pids) != 1 or None in pids:
            sockets[key] = None
            continue
        pid = next(iter(pids))
        assert pid is not None
        if pid not in owners:
            owners[pid] = _process_owner(pid)
        sockets[key] = owners[pid]
    return _Snapshot(sockets, _local_ips())


class ProcessMapper:
    def __init__(self):
        self._snapshot = _Snapshot()

    def refresh(self) -> None:
        # 只交接构建完毕的快照。查询失败时不沿用过期的套接字所有者。
        try:
            self._snapshot = _read_snapshot()
        except (psutil.Error, OSError, ValueError):
            self._snapshot = _Snapshot()

    def run(self, stopped: Event) -> None:
        while not stopped.is_set():
            self.refresh()
            stopped.wait(REFRESH_SECONDS)

    def match(self, flow: TransportFlow, *, initial_syn: bool = False) -> tuple[ProcessMatch, ...]:
        snapshot = self._snapshot
        if not snapshot.sockets:
            return ()
        source = snapshot.owner(flow.protocol, flow.source, flow.destination, allow_bound=flow.protocol == "udp")
        destination = snapshot.owner(
            flow.protocol, flow.destination, flow.source, allow_bound=flow.protocol == "udp" or initial_syn,
        )
        matches = []
        if source is not None:
            matches.append(ProcessMatch(flow.source, source))
        if destination is not None and (flow.destination != flow.source or destination != source):
            matches.append(ProcessMatch(flow.destination, destination))
        return tuple(matches)
