"""比较所有合成样例的 NetSniffer 与 TShark 统计口径。"""

import argparse
import os
import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

from sniffer.analysis.stats import StatsSnapshot, protocol_hierarchy
from sniffer.capture.pcap_io import read_capture

_PROTOCOL = {"Ethernet": "eth", "IPv4": "ip", "IPv6": "ipv6", "Loopback": "null"}
_HIERARCHY_ROW = re.compile(r"^( *)\S+\s+frames:(\d+)\s+bytes:(\d+)\s*$")


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
    args = parser.parse_args()
    samples = sorted(args.samples.glob("*.pcap"))
    if not samples:
        parser.error(f"未找到样例: {args.samples}")

    matches = 0
    with TemporaryDirectory() as config:
        # 使用空的个人配置目录，避免用户安装的 Lua 后置解析器改变协议层级。
        env = dict(os.environ, WIRESHARK_CONFIG_DIR=config)
        for path in samples:
            snapshot = StatsSnapshot.from_records(read_capture(path))
            output = subprocess.run(
                [args.tshark, "-n", "-r", str(path), "-q", "-z", "io,phs"], env=env,
                check=True, capture_output=True, text=True, encoding="utf-8", errors="replace",
            ).stdout
            print(path.name)
            matches += _report("io,phs", _hierarchy(snapshot), _tshark_hierarchy(output))
    print(f"io,phs: {matches}/{len(samples)} 份样例完全一致")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
