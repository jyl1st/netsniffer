"""对照本机 TShark 与 NetSniffer 的阶段验收结果。"""

import argparse
import os
import shutil
import subprocess
from pathlib import Path

from sniffer.capture.pcap_io import read_capture
from sniffer.dissect.frame import dissect_frame
from sniffer.filter.evaluator import compile_filter

SAMPLES = Path(__file__).resolve().parents[1] / "samples"
FILTER_CASES = (
    ("(http || dns) && ip.src == 192.168.0.0/16", None, (1, 2)),
    ("tcp.flags.syn && !tcp.flags.ack", "tcp.flags.syn == 1 && tcp.flags.ack == 0", (4,)),
    ('tls.handshake.extensions_server_name contains "bilibili"', None, (6,)),
    ("udp.port == 53", None, (2, 3)),
    ("tcp.port in {80, 443, 8080}", None, (1, 4, 5, 6, 7)),
)


def _tshark_fields(
    executable: str, sample: Path, expression: str, fields: tuple[str, ...],
) -> list[str]:
    command = [
        executable, "-n", "-d", "tcp.port==8080,http", "-d", "tcp.port==443,tls",
        "-r", str(sample), "-Y", expression, "-T", "fields",
    ]
    for field in fields:
        command.extend(("-e", field))
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", check=False)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or f"TShark exit {result.returncode}")
    return result.stdout.splitlines()


def _trees(sample: Path):
    previous = None
    for number, record in enumerate(read_capture(sample), 1):
        yield dissect_frame(record, number, previous)
        previous = record.timestamp


def compare_protocol_fields(executable: str) -> int:
    cases = (
        ("tcp_http.pcap", "http.request.method", "http.request", ("http.request.uri", "http.host"), ("/hello", "sniffer.example")),
        ("tls_client_hello.pcap", "tls.handshake.type == 1", None, ("tls.handshake.extensions_server_name",), ("sniffer.example",)),
        ("dns.pcap", "dns.flags.response == 1", None, ("dns.a",), ("192.0.2.20",)),
    )
    differences = 0
    for filename, expression, external_expression, keys, expected in cases:
        sample = SAMPLES / filename
        program = compile_filter(expression)
        observed = []
        for tree in _trees(sample):
            if program.matches(tree):
                fields = {field.name: field.value for field in tree.walk()}
                observed.append("\t".join(str(fields.get(key, "")) for key in keys))
        external = _tshark_fields(executable, sample, external_expression or expression, keys)
        matched = observed == external == ["\t".join(expected)]
        differences += not matched
        print(f"{'OK' if matched else 'DIFF'} {filename} {expression} -> {observed} | TShark {external}")
    return differences


def compare_display_filters(executable: str) -> int:
    sample = SAMPLES / "display_filters.pcap"
    trees = tuple(_trees(sample))
    differences = 0
    for expression, external_expression, expected in FILTER_CASES:
        program = compile_filter(expression)
        observed = tuple(index for index, tree in enumerate(trees, 1) if program.matches(tree))
        external = tuple(map(int, _tshark_fields(executable, sample, external_expression or expression, ("frame.number",))))
        matched = observed == external == expected
        differences += not matched
        print(f"{'OK' if matched else 'DIFF'} {expression} -> {observed} | TShark {external} | expected {expected}")
    return differences


def compare_tcp_reassembly(executable: str) -> int:
    sample = SAMPLES / "tcp_reassembly.pcap"
    trees = tuple(_trees(sample))
    differences = 0
    for key, value, packet in (
        ("tls.handshake.extensions_server_name", "split.example", 5),
        ("http.host", "sniffer.example", 10),
        ("dns.qry.name", "sniffer.example", 15),
    ):
        expression = f'{key} == "{value}"'
        program = compile_filter(expression)
        observed = [
            f"{index}\t{value}" for index, tree in enumerate(trees, 1) if program.matches(tree)
        ]
        external = _tshark_fields(executable, sample, expression, ("frame.number", key))
        matched = observed == external == [f"{packet}\t{value}"]
        differences += not matched
        print(f"{'OK' if matched else 'DIFF'} {expression} -> {observed} | TShark {external}")
    return differences


def main() -> int:
    default = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Wireshark" / "tshark.exe"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", default=shutil.which("tshark") or str(default))
    parser.add_argument("--stage", choices=("2", "3", "4", "all"), default="all")
    args = parser.parse_args()
    differences = 0
    if args.stage in ("2", "all"):
        differences += compare_protocol_fields(args.tshark)
    if args.stage in ("3", "all"):
        differences += compare_display_filters(args.tshark)
    if args.stage in ("4", "all"):
        differences += compare_tcp_reassembly(args.tshark)
    print(f"Differences: {differences}")
    return int(differences != 0)


if __name__ == "__main__":
    raise SystemExit(main())
