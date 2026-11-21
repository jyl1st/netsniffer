from collections.abc import Sequence
from dataclasses import dataclass, field

from sniffer.analysis.process_map import ProcessOwner
from sniffer.analysis.streams import Endpoint
from sniffer.model.packet import PacketRecord


@dataclass(frozen=True, slots=True)
class ProcessStream:
    number: int
    peers: tuple[Endpoint, ...]
    packets: int
    wire_bytes: int


@dataclass(slots=True)
class _Counts:
    peers: set[Endpoint] = field(default_factory=set)
    packets: int = 0
    wire_bytes: int = 0


def summarize_process_streams(records: Sequence[PacketRecord]) -> list[tuple[ProcessOwner, tuple[ProcessStream, ...]]]:
    owners: dict[int, ProcessOwner] = {}
    streams: dict[int, dict[int, _Counts]] = {}
    for record in records:
        flow, number = record.summary.flow, record.stream_id
        if not record.processes or flow is None or flow.protocol != "tcp" or number is None:
            continue
        counted = set()
        for match in record.processes:
            owner = match.owner
            if owner.name is not None or owner.pid not in owners:
                owners[owner.pid] = owner
            groups = streams.setdefault(owner.pid, {})
            counts = groups.get(number)
            if counts is None:
                groups[number] = counts = _Counts()
            peer = flow.destination if match.local == flow.source else flow.source
            counts.peers.add(peer)
            # 同一进程拥有回环连接的两端时，仍然只计一次帧。
            if owner.pid not in counted:
                counts.packets += 1
                counts.wire_bytes += record.wire_length
                counted.add(owner.pid)

    result = []
    for pid, groups in streams.items():
        entries = tuple(
            ProcessStream(number, tuple(sorted(counts.peers)), counts.packets, counts.wire_bytes)
            for number, counts in sorted(groups.items())
        )
        result.append((owners[pid], entries))
    return sorted(result, key=lambda item: ((item[0].name or "").casefold(), item[0].pid))
