"""生成供协议分析和告警测试使用的离线以太网 pcap。"""

import argparse
from decimal import Decimal
from pathlib import Path

from scapy.all import (
    ARP,
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    IPv6,
    TCP,
    UDP,
    Ether,
    ICMPv6EchoReply,
    ICMPv6EchoRequest,
    Packet,
    wrpcap,
)

CLIENT_IP = "192.0.2.10"
SERVER_IP = "192.0.2.20"
CLIENT_MAC = "02:00:00:00:00:10"
SERVER_MAC = "02:00:00:00:00:20"
OTHER_MAC = "02:00:00:00:00:30"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
CLIENT_PORT = 49152
HOSTNAME = b"sniffer.example"
START_TIME = Decimal("1700000000")
HTTP_REQUEST = b"GET /hello HTTP/1.1\r\nHost: sniffer.example\r\n\r\n"
HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"


def ethernet(*, reply: bool = False) -> Ether:
    if reply:
        return Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    return Ether(src=CLIENT_MAC, dst=SERVER_MAC)


def ipv4(*, reply: bool = False) -> Packet:
    if reply:
        return ethernet(reply=True) / IP(src=SERVER_IP, dst=CLIENT_IP)
    return ethernet() / IP(src=CLIENT_IP, dst=SERVER_IP)


def tcp_segment(
    server_port: int,
    flags: str,
    seq: int,
    ack: int = 0,
    *,
    reply: bool = False,
) -> Packet:
    sport, dport = (server_port, CLIENT_PORT) if reply else (CLIENT_PORT, server_port)
    return ipv4(reply=reply) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)


def tcp_handshake(server_port: int) -> list[Packet]:
    # SYN 各消耗一个序号，双方发完握手包后的序号分别为 1001 和 2001。
    return [
        tcp_segment(server_port, "S", 1000),
        tcp_segment(server_port, "SA", 2000, 1001, reply=True),
        tcp_segment(server_port, "A", 1001, 2001),
    ]


def http_packets(*, retransmit: bool = False) -> list[Packet]:
    request = tcp_segment(8080, "PA", 1001, 2001) / HTTP_REQUEST
    packets = [*tcp_handshake(8080), request]
    if retransmit:
        packets.append(request.copy())
    client_next_seq = 1001 + len(HTTP_REQUEST)
    packets.extend(
        [
            tcp_segment(8080, "PA", 2001, client_next_seq, reply=True) / HTTP_RESPONSE,
            tcp_segment(8080, "A", client_next_seq, 2001 + len(HTTP_RESPONSE)),
        ]
    )
    return packets


def dns_packets() -> list[Packet]:
    question = DNSQR(qname=HOSTNAME, qtype="A")
    return [
        ipv4() / UDP(sport=CLIENT_PORT, dport=53) / DNS(id=1, rd=1, qd=question),
        ipv4(reply=True)
        / UDP(sport=53, dport=CLIENT_PORT)
        / DNS(
            id=1, qr=1, rd=1, ra=1, qd=question,
            an=DNSRR(rrname=HOSTNAME, type="A", ttl=60, rdata=SERVER_IP),
        ),
    ]


def tls_packets() -> list[Packet]:
    # 明文 ClientHello 只需构造记录与握手头。SNI 的列表、扩展和扩展块各有长度字段。
    server_name = b"\x00" + len(HOSTNAME).to_bytes(2, "big") + HOSTNAME
    server_names = len(server_name).to_bytes(2, "big") + server_name
    sni = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    random = int(START_TIME).to_bytes(4, "big") + bytes(range(28))
    empty_session = b"\x00"
    cipher_suites = b"\x00\x02\x00\x2f"
    compression = b"\x01\x00"
    extensions = len(sni).to_bytes(2, "big") + sni
    version = b"\x03\x03"
    hello = version + random + empty_session + cipher_suites + compression + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    record = b"\x16" + version + len(handshake).to_bytes(2, "big") + handshake
    return [
        *tcp_handshake(443),
        tcp_segment(443, "PA", 1001, 2001) / record,
    ]


def arp_packets() -> list[Packet]:
    return [
        Ether(src=CLIENT_MAC, dst=BROADCAST_MAC)
        / ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, hwdst="00:00:00:00:00:00", pdst=SERVER_IP),
        ethernet(reply=True)
        / ARP(op=2, hwsrc=SERVER_MAC, psrc=SERVER_IP, hwdst=CLIENT_MAC, pdst=CLIENT_IP),
    ]


def make_samples(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    arp_conflict = Ether(src=OTHER_MAC, dst=BROADCAST_MAC) / ARP(
        op=2, hwsrc=OTHER_MAC, psrc=SERVER_IP, hwdst=BROADCAST_MAC, pdst=SERVER_IP
    )
    traces = {
        "tcp_http": http_packets(),
        "dns": dns_packets(),
        "tls_client_hello": tls_packets(),
        "icmp": [
            ipv4() / ICMP(type=8, id=1, seq=1) / b"echo",
            ipv4(reply=True) / ICMP(type=0, id=1, seq=1) / b"echo",
        ],
        "arp": arp_packets(),
        "ipv6": [
            ethernet()
            / IPv6(src="2001:db8::10", dst="2001:db8::20")
            / ICMPv6EchoRequest(id=1, seq=1, data=b"echo"),
            ethernet(reply=True)
            / IPv6(src="2001:db8::20", dst="2001:db8::10")
            / ICMPv6EchoReply(id=1, seq=1, data=b"echo"),
        ],
        "tcp_retransmission": http_packets(retransmit=True),
        "arp_conflict": [*arp_packets(), arp_conflict],
        "syn_scan": [tcp_segment(port, "S", 1000) for port in range(10000, 10016)],
    }
    for name, packets in traces.items():
        interval = Decimal("0.250") if name == "tcp_retransmission" else Decimal("0.010")
        for index, packet in enumerate(packets):
            packet.time = START_TIME + index * interval
        wrpcap(str(output_dir / f"{name}.pcap"), packets)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=Path(__file__).resolve().parent)
    make_samples(parser.parse_args().output_dir)


if __name__ == "__main__":
    main()
