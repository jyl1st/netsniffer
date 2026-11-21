"""逐帧对照 Wireshark Lua 识别和 NetSniffer 的单帧应用识别。"""

import argparse
import os
import shutil
import subprocess
from pathlib import Path

from sniffer.capture.pcap_io import read_capture_preview
from sniffer.dissect.app_detect import identify_application
from sniffer.model.packet import PacketRecord

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "wireshark_plugin" / "netsniffer_appid.lua"
SAMPLES = ROOT / "samples"
Label = tuple[str, str]
EMPTY: Label = "", ""


def _payload_bounds(record: PacketRecord) -> tuple[int, int] | None:
    summary = record.summary
    return (summary.tcp.start, summary.tcp.end) if summary.tcp is not None else summary.udp_payload


def _local_label(record: PacketRecord) -> Label:
    flow = record.summary.flow
    bounds = _payload_bounds(record)
    if flow is None or bounds is None:
        return EMPTY
    result = identify_application(
        record.raw, *bounds, 6 if flow.protocol == "tcp" else 17, flow.source[1], flow.destination[1],
    )
    return (result.protocol, result.basis) if result is not None and result.protocol is not None else EMPTY


def _lua_labels(tshark: str, sample: Path) -> dict[int, Label]:
    command = [
        tshark, "-n", "-r", str(sample), "-X", f"lua_script:{SCRIPT}", "-T", "fields", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "netsniffer.app", "-e", "netsniffer.basis",
    ]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    errors = result.stderr.strip()
    if result.returncode or errors:
        raise RuntimeError(errors or f"TShark 返回 {result.returncode}")
    rows = {}
    for line in result.stdout.splitlines():
        number, app, basis = line.split("\t", 2)
        frame = int(number)
        if frame in rows:
            raise ValueError(f"TShark 重复输出帧 {frame}")
        rows[frame] = app, basis
    return rows


def _difference(record: PacketRecord, python: Label, lua: Label) -> str:
    bounds, flow = _payload_bounds(record), record.summary.flow
    if bounds is None or flow is None:
        return "两边的传输层识别或可用负载范围不同"
    if python[0] == lua[0]:
        return "应用相同，内容与端口判据的优先级不同"
    start, end = bounds
    if python[0] == "DNS" and flow.protocol == "tcp" and end - start >= 2:
        if int.from_bytes(record.raw[start:start + 2], "big") > end - start - 2:
            return "Lua 要求单帧含完整 DNS 消息，Python 可识别部分 DNS over TCP"
    if python[0] == "NTP" and record.raw[start] & 7 == 6:
        return "Lua 覆盖常见 NTP 时间消息，Python 另支持 NTP 控制消息"
    return f"单帧内容校验结果不同（{flow.protocol.upper()} {flow.source[1]}→{flow.destination[1]}，负载 {end - start} 字节）"


def compare(tshark: str, sample: Path) -> tuple[int, int]:
    preview = read_capture_preview(sample)
    if preview.truncated:
        raise ValueError(f"{sample.name} 超出 NetSniffer 文件预览上限")
    records = preview.records
    lua = _lua_labels(tshark, sample)
    if lua.keys() != set(range(1, len(records) + 1)):
        raise ValueError(f"{sample.name} 的两边帧号不一致（Python {len(records)} 帧，TShark {len(lua)} 帧）")

    differences = []
    reassembled = []
    for frame, record in enumerate(records, 1):
        python = _local_label(record)
        if python != lua[frame]:
            differences.append((frame, python, lua[frame], _difference(record, python, lua[frame])))
        app = record.tcp_application
        if app is not None and (app.messages or app.protocol != python[0]):
            kinds = "/".join(dict.fromkeys(message.parser for message in app.messages)) or "沿用流识别"
            reassembled.append(f"{frame}={app.protocol}（{kinds}）")

    count = len(records)
    matching = count - len(differences)
    print(f"{sample.name}: {matching}/{count} 一致（{matching / count:.2%}）" if count else f"{sample.name}: 空样例")
    for frame, python, actual, reason in differences:
        print(f"  帧 {frame} · Python {python!r} · Lua {actual!r} · {reason}")
    if reassembled:
        print("  Python 流级结果（单帧对照之外） " + ", ".join(reassembled))
    return matching, count


def main() -> int:
    fallback = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark" / "tshark.exe"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", default=shutil.which("tshark") or str(fallback), help="TShark 可执行文件")
    args = parser.parse_args()
    samples = sorted(path for path in SAMPLES.iterdir() if path.suffix.lower() in (".pcap", ".pcapng"))
    matching = total = 0
    for path in samples:
        try:
            sample_matching, sample_total = compare(args.tshark, path)
        except (OSError, RuntimeError, ValueError) as error:
            parser.exit(2, f"{path.name}: {error}\n")
        matching += sample_matching
        total += sample_total
    if total == 0:
        parser.exit(2, "没有可对照的样例帧。\n")
    print(f"合计 {len(samples)} 个样例，{matching}/{total} 帧一致（{matching / total:.2%}）")
    return int(matching != total)


if __name__ == "__main__":
    raise SystemExit(main())
