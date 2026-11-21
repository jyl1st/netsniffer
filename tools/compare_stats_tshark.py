"""比较所有合成样例的 NetSniffer 与 TShark 统计口径。"""

import argparse
import os
import re
import subprocess
from decimal import Decimal
from pathlib import Path
from statistics import median
from tempfile import TemporaryDirectory
from time import perf_counter

from sniffer.analysis.stats import StatsSnapshot, conversations, endpoints, io_buckets, protocol_hierarchy
from sniffer.capture.pcap_io import read_capture

_PROTOCOL = {"Ethernet": "eth", "IPv4": "ip", "IPv6": "ipv6", "Loopback": "null"}
_HIERARCHY_ROW = re.compile(r"^( *)\S+\s+frames:(\d+)\s+bytes:(\d+)\s*$")
_CONVERSATIONS = {"IPv4": "ip", "IPv6": "ipv6", "TCP": "tcp", "UDP": "udp"}
_ENDPOINTS = {"IPv4": "ip", "TCP": "tcp", "UDP": "udp"}
_CONV_ROW = re.compile(
    r"^\s*(\S+)\s+<->\s+(\S+)\s+(\d+)\s+([\d,]+) bytes\s+(\d+)\s+([\d,]+) bytes"
    r"\s+(\d+)\s+([\d,]+) bytes(?:\s|$)"
)
_IO_ROW = re.compile(
    r"^\|\s*(-?\d+(?:\.\d+)?)\s*<>\s*(?:-?\d+(?:\.\d+)?|Dur)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|"
)


def _tshark_hierarchy(output: str) -> dict:
    nodes = {}
    path = []
    for line in output.splitlines():
        match = _HIERARCHY_ROW.match(line)
        if match is None:
            continue
        indent, frames, size = match.groups()
        depth = len(indent) // 2
        del path[depth:]
        path.append(line.strip().split()[0])
        nodes[tuple(path)] = int(frames), int(size)
    if ("frame",) in nodes:
        return nodes
    roots = [counts for key, counts in nodes.items() if len(key) == 1]
    root = sum(counts[0] for counts in roots), sum(counts[1] for counts in roots)
    return {("frame",): root, **{("frame", *key): counts for key, counts in nodes.items()}}


def _hierarchy(snapshot: StatsSnapshot) -> dict:
    return {
        tuple(_PROTOCOL.get(layer, layer.lower()) for layer in path): (counts.frames, counts.bytes)
        for path, counts in protocol_hierarchy(snapshot).items()
    }


def _section(output: str, title: str) -> list[str]:
    # TShark 的会话和端点报表用整行等号分隔。
    for section in re.split(r"^={10,}\s*$", output, flags=re.MULTILINE):
        lines = section.strip().splitlines()
        if lines and lines[0] == title:
            return lines[1:]
    return []


def _address(token: str, with_port: bool) -> tuple[str, int | None]:
    if not with_port:
        return token, None
    ip, _, port = token.rpartition(":")
    return ip.strip("[]"), int(port)


def _conv_value(a, b, forward, reverse, total):
    if a <= b:
        return (a, b), (*forward, *reverse, *total)
    return (b, a), (*reverse, *forward, *total)


def _tshark_conversations(output: str, group: str) -> dict:
    rows = {}
    for line in _section(output, f"{group} Conversations"):
        match = _CONV_ROW.match(line)
        if match is None:
            if "<->" in line:
                raise ValueError(f"无法读取 TShark 会话行: {line}")
            continue
        a, b, *counts = match.groups()
        ra, rb, fa, fb, total_frames, total_bytes = [int(item.replace(",", "")) for item in counts]
        with_port = group in ("TCP", "UDP")
        key, value = _conv_value(_address(a, with_port), _address(b, with_port),
                                 (fa, fb), (ra, rb), (total_frames, total_bytes))
        rows[key] = value
    return rows


def _our_conversations(entries) -> dict:
    return dict(_conv_value(row.a, row.b, (row.forward.frames, row.forward.bytes),
                            (row.reverse.frames, row.reverse.bytes), (row.frames, row.bytes)) for row in entries)


def _tshark_endpoints(output: str, group: str) -> dict:
    rows = {}
    has_port = group in ("TCP", "UDP")
    for line in _section(output, f"{group} Endpoints"):
        parts = line.split()
        if not parts or parts[0].startswith(("Filter:", "|")):
            continue
        column = 2 if has_port else 1
        if len(parts) != column + 6:
            raise ValueError(f"无法读取 TShark 端点行: {line}")
        port = int(parts[1]) if has_port else None
        rows[(parts[0], port)] = tuple(int(item.replace(",", "")) for item in parts[column:])
    return rows


def _our_endpoints(entries) -> dict:
    return {row.address: (row.frames, row.bytes, row.sent.frames, row.sent.bytes,
                          row.received.frames, row.received.bytes) for row in entries}


def _tshark_io(output: str) -> dict:
    result = {}
    for line in output.splitlines():
        match = _IO_ROW.match(line)
        if match:
            start, frames, size = match.groups()
            if int(frames):
                result[Decimal(start)] = int(frames), int(size)
    return result


def _benchmark(path: Path) -> None:
    snapshot = StatsSnapshot.from_records(read_capture(path))
    print(f"性能样例 {path.name}: {len(snapshot.frames):,} 帧，只计统计耗时，五次取中位数")
    for name, analyze in (("协议层级", protocol_hierarchy), ("会话", conversations),
                          ("端点", endpoints), ("IO 图表 (1 s)", io_buckets)):
        times = []
        for _ in range(5):
            start = perf_counter()
            result = analyze(snapshot)
            times.append((perf_counter() - start) * 1000)
            del result
        print(f"  {name}: {median(times):.1f} ms")


def _report(label: str, ours: dict, theirs: dict) -> bool:
    differences = [key for key in ours.keys() | theirs.keys() if ours.get(key) != theirs.get(key)]
    if not differences:
        print(f"  {label}: 一致 ({len(ours)} 行)")
        return True
    print(f"  {label}: {len(differences)} 行差异 (NetSniffer / TShark)")
    for key in sorted(differences, key=str):
        print(f"    {key}: {ours.get(key, '—')} / {theirs.get(key, '—')}")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--samples", type=Path, default=Path("samples"))
    parser.add_argument("--benchmark", type=Path, help="另测指定抓包的四项统计耗时")
    args = parser.parse_args()
    samples = sorted(args.samples.glob("*.pcap"))
    if not samples:
        parser.error(f"未找到样例: {args.samples}")

    labels = ["io,phs", *(f"conv,{protocol}" for protocol in _CONVERSATIONS.values()),
              *(f"endpoints,{protocol}" for protocol in _ENDPOINTS.values()), "io,stat,1"]
    matches = dict.fromkeys(labels, 0)
    with TemporaryDirectory() as config:
        # 使用空的个人配置目录，避免用户安装的 Lua 后置解析器改变协议层级。
        env = dict(os.environ, WIRESHARK_CONFIG_DIR=config)
        for path in samples:
            snapshot = StatsSnapshot.from_records(read_capture(path))
            output = subprocess.run(
                [args.tshark, "-n", "-r", str(path), "-q", *(arg for label in labels for arg in ("-z", label))], env=env,
                check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
            ).stdout
            print(path.name)
            matches["io,phs"] += _report("io,phs", _hierarchy(snapshot), _tshark_hierarchy(output))
            ours = conversations(snapshot)
            for group, protocol in _CONVERSATIONS.items():
                label = f"conv,{protocol}"
                matches[label] += _report(label, _our_conversations(ours[group]), _tshark_conversations(output, group))
            our_endpoints = endpoints(snapshot)
            for group, protocol in _ENDPOINTS.items():
                label = f"endpoints,{protocol}"
                matches[label] += _report(label, _our_endpoints(our_endpoints[group]), _tshark_endpoints(output, group))
            ours_io = {Decimal(bucket.index): (bucket.counts.frames, bucket.counts.bytes) for bucket in io_buckets(snapshot)}
            matches["io,stat,1"] += _report("io,stat,1", ours_io, _tshark_io(output))
    for label, count in matches.items():
        print(f"{label}: {count}/{len(samples)} 份样例完全一致")
    if args.benchmark:
        _benchmark(args.benchmark)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
