from ctypes import create_string_buffer
from dataclasses import replace
from ipaddress import ip_address
from pathlib import Path
from socket import AF_INET, AF_INET6, SOCK_DGRAM, SOCK_STREAM
from types import SimpleNamespace

import psutil

from samples.make_samples import HTTP_REQUEST, dns_packets, tcp_segment
from sniffer.analysis.process_flows import summarize_process_streams
from sniffer.analysis.process_map import ProcessMapper, ProcessMatch, ProcessOwner
from sniffer.analysis.streams import StreamIndex, TransportFlow
from sniffer.capture.engine import CaptureSession, CaptureSettings
from sniffer.capture.pcap_io import read_capture, write_capture
from sniffer.dissect.frame import dissect_frame
from sniffer.filter.evaluator import compile_filter
from sniffer.model.packet import LINKTYPE_ETHERNET, PacketRecord

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def _socket(local, remote=(), *, pid=10, kind=SOCK_STREAM, status=psutil.CONN_ESTABLISHED, family=AF_INET):
    return SimpleNamespace(laddr=local, raddr=remote, type=kind, status=status, family=family, pid=pid)


def _endpoint(address, port):
    return ip_address(address).packed, port


def _mapper(monkeypatch, sockets, *, addresses=((AF_INET, "192.0.2.10"),), names=None):
    names = names or {}
    monkeypatch.setattr(psutil, "net_connections", lambda *, kind: list(sockets))
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {"test": [
        SimpleNamespace(family=family, address=address) for family, address in addresses
    ]})

    def process(pid):
        if pid in names and names[pid] is None:
            raise psutil.AccessDenied(pid)
        return SimpleNamespace(name=lambda: names.get(pid, f"test-{pid}.exe"))

    monkeypatch.setattr(psutil, "Process", process)
    mapper = ProcessMapper()
    mapper.refresh()
    return mapper


def test_connection_mapping_distinguishes_protocol_and_both_endpoints(monkeypatch):
    local = _endpoint("192.0.2.10", 5000)
    first = _endpoint("192.0.2.20", 80)
    other = _endpoint("192.0.2.21", 80)
    mapper = _mapper(monkeypatch, [
        _socket(("192.0.2.10", 5000), ("192.0.2.20", 80), pid=11),
        _socket(("192.0.2.10", 5000), ("192.0.2.21", 80), pid=12),
        _socket(("192.0.2.10", 5000), pid=13, kind=SOCK_DGRAM),
    ])
    assert mapper.match(TransportFlow("tcp", local, first)) == (ProcessMatch(local, ProcessOwner(11, "test-11.exe")),)
    assert mapper.match(TransportFlow("tcp", other, local))[0].owner.pid == 12
    assert mapper.match(TransportFlow("udp", local, other))[0].owner.pid == 13
    assert mapper.match(TransportFlow("tcp", local, _endpoint("192.0.2.22", 80))) == ()


def test_wildcards_match_only_local_addresses_and_listener_only_inbound_syn(monkeypatch):
    local = _endpoint("192.0.2.10", 80)
    remote = _endpoint("192.0.2.20", 5000)
    foreign = _endpoint("192.0.2.21", 80)
    mapper = _mapper(monkeypatch, [
        _socket(("0.0.0.0", 80), pid=20, status=psutil.CONN_LISTEN),
        _socket(("0.0.0.0", 80), pid=21, kind=SOCK_DGRAM),
    ])
    assert mapper.match(TransportFlow("tcp", remote, local), initial_syn=True)[0].owner.pid == 20
    assert mapper.match(TransportFlow("tcp", remote, local)) == ()
    assert mapper.match(TransportFlow("tcp", local, remote), initial_syn=True) == ()
    assert mapper.match(TransportFlow("udp", local, remote))[0].owner.pid == 21
    for protocol in ("tcp", "udp"):
        assert mapper.match(TransportFlow(protocol, remote, foreign), initial_syn=True) == ()


def test_ipv6_scope_and_mapped_ipv4_keep_process_pid_when_name_is_denied(monkeypatch):
    local, peer = _endpoint("fe80::1", 1234), _endpoint("fe80::2", 4321)
    v4, other = _endpoint("192.0.2.10", 5000), _endpoint("192.0.2.20", 80)
    mapper = _mapper(monkeypatch, [
        _socket(("fe80::1%14", 1234), ("fe80::2%14", 4321), pid=31, family=AF_INET6),
        _socket(("::ffff:192.0.2.10", 5000), ("::ffff:192.0.2.20", 80), pid=32, family=AF_INET6),
    ], names={32: None})
    assert mapper.match(TransportFlow("tcp", peer, local))[0].owner.pid == 31
    assert mapper.match(TransportFlow("tcp", v4, other))[0].owner == ProcessOwner(32, None)


def test_ambiguous_owner_and_failed_refresh_do_not_reuse_labels(monkeypatch):
    local = _endpoint("192.0.2.10", 5000)
    peer = _endpoint("192.0.2.20", 80)
    sockets = [_socket(("192.0.2.10", 5000), ("192.0.2.20", 80), pid=1)]
    mapper = _mapper(monkeypatch, sockets)
    flow = TransportFlow("tcp", local, peer)
    assert mapper.match(flow)[0].owner.pid == 1
    sockets.append(_socket(("192.0.2.10", 5000), ("192.0.2.20", 80), pid=2))
    mapper.refresh()
    assert mapper.match(flow) == ()
    sockets.pop()
    mapper.refresh()
    assert mapper.match(flow)[0].owner.pid == 1

    def denied(*, kind):
        raise psutil.AccessDenied()

    monkeypatch.setattr(psutil, "net_connections", denied)
    mapper.refresh()
    assert mapper.match(flow) == ()


def test_capture_queue_tags_both_processes_and_saved_files_do_not_reassign_pids(monkeypatch, tmp_path):
    session = CaptureSession(CaptureSettings("test"))
    session._process_map = _mapper(monkeypatch, [
        _socket(("192.0.2.10", 49152), ("192.0.2.20", 8080), pid=41),
        _socket(("192.0.2.20", 8080), ("192.0.2.10", 49152), pid=42),
    ], names={41: "msedge.exe", 42: "python.exe"})
    raw = bytes(tcp_segment(8080, "PA", 1001, 2001) / HTTP_REQUEST)
    header = SimpleNamespace(caplen=len(raw), len=len(raw), ts=SimpleNamespace(tv_sec=1, tv_usec=0))
    session._receive(header, create_string_buffer(raw), LINKTYPE_ETHERNET)
    record, = session.drain()
    tree = dissect_frame(record)
    assert [owner.pid for owner in record.process_owners] == [41, 42]
    assert compile_filter('proc.name == "msedge.exe"').matches(tree)
    assert compile_filter("proc.pid == 42").matches(tree)
    assert all(not item.length for item in tree.walk() if item.name.startswith("proc."))
    saved = tmp_path / "captured.pcap"
    write_capture(saved, [record])
    imported, = read_capture(saved)
    assert not imported.processes
    assert not compile_filter("proc").matches(dissect_frame(imported))


def test_process_view_counts_one_packet_when_one_process_owns_both_ends():
    tcp = read_capture(SAMPLES / "tcp_http.pcap")[3]
    assert tcp.summary.flow is not None
    endpoints = tcp.summary.flow.endpoints
    owner = ProcessOwner(50, "test.exe")
    tagged = replace(tcp, processes=tuple(ProcessMatch(endpoint, owner) for endpoint in endpoints))
    raw_udp = bytes(dns_packets()[0])
    udp = PacketRecord.from_bytes(None, raw_udp, LINKTYPE_ETHERNET, len(raw_udp)).with_stream(StreamIndex())
    udp = replace(udp, processes=(ProcessMatch(endpoints[0], owner),))
    (row_owner, (stream,)), = summarize_process_streams([tcp, tagged, tagged, udp])
    assert row_owner == owner
    assert stream.number == tcp.stream_id
    assert stream.peers == endpoints
    assert stream.packets == 2
    assert stream.wire_bytes == 2 * tcp.wire_length
