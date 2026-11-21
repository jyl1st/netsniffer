"""生成供协议分析和告警测试使用的离线以太网 pcap。"""

import argparse
from decimal import Decimal
from pathlib import Path
from struct import pack

from scapy.all import (
    ARP,
    BOOTP,
    DHCP,
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


def flow_graph_packets() -> list[Packet]:
    client = 1001 + len(HTTP_REQUEST)
    server = 2001 + len(HTTP_RESPONSE)
    return [
        *http_packets(),
        tcp_segment(8080, "FA", client, server),
        tcp_segment(8080, "A", server, client + 1, reply=True),
        tcp_segment(8080, "FA", server, client + 1, reply=True),
        tcp_segment(8080, "A", client + 1, server + 1),
        *tcp_handshake(8081),
        tcp_segment(8081, "R", 2001, reply=True),
        tcp_segment(8082, "PA", 7000, 3000, reply=True) / b"midstream",
        tcp_segment(8082, "A", 3000, 7009),
    ]


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


def tls_client_hello(hostname: bytes = HOSTNAME, *, leading_extensions: bytes = b"") -> bytes:
    # 明文 ClientHello 只需构造记录与握手头。SNI 的列表、扩展和扩展块各有长度字段。
    server_name = b"\x00" + len(hostname).to_bytes(2, "big") + hostname
    server_names = len(server_name).to_bytes(2, "big") + server_name
    sni = b"\x00\x00" + len(server_names).to_bytes(2, "big") + server_names
    random = int(START_TIME).to_bytes(4, "big") + bytes(range(28))
    empty_session = b"\x00"
    cipher_suites = b"\x00\x02\x00\x2f"
    compression = b"\x01\x00"
    extension_data = leading_extensions + sni
    extensions = len(extension_data).to_bytes(2, "big") + extension_data
    version = b"\x03\x03"
    hello = version + random + empty_session + cipher_suites + compression + extensions
    handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
    return b"\x16" + version + len(handshake).to_bytes(2, "big") + handshake


def tls_packets(hostname: bytes = HOSTNAME) -> list[Packet]:
    return [
        *tcp_handshake(443),
        tcp_segment(443, "PA", 1001, 2001) / tls_client_hello(hostname),
    ]


def arp_packets() -> list[Packet]:
    return [
        Ether(src=CLIENT_MAC, dst=BROADCAST_MAC)
        / ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT_IP, hwdst="00:00:00:00:00:00", pdst=SERVER_IP),
        ethernet(reply=True)
        / ARP(op=2, hwsrc=SERVER_MAC, psrc=SERVER_IP, hwdst=CLIENT_MAC, pdst=CLIENT_IP),
    ]


def application_packets() -> list[Packet]:
    hostname = "实验设备.local".encode("utf-8")
    dhcp = (
        Ether(src=CLIENT_MAC, dst=BROADCAST_MAC)
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(xid=0x12345678, chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")))
        / DHCP(options=[("message-type", "discover"), ("hostname", b"sniffer-lab"), "end"])
    )
    mdns = (
        Ether(src=CLIENT_MAC, dst="01:00:5e:00:00:fb")
        / IP(src=CLIENT_IP, dst="224.0.0.251", ttl=255)
        / UDP(sport=5353, dport=5353)
        / DNS(id=0, rd=0, qd=DNSQR(qname=hostname))
    )
    ssdp = (
        Ether(src=CLIENT_MAC, dst="01:00:5e:7f:ff:fa")
        / IP(src=CLIENT_IP, dst="239.255.255.250")
        / UDP(sport=CLIENT_PORT, dport=1900)
        / b'M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    )
    ntp = ipv4() / UDP(sport=CLIENT_PORT, dport=123) / (
        b"\x23\x00\x06\xec" + bytes(36) + pack("!II", 3_908_988_800, 1 << 31)
    )
    # TLS 1.2 ServerHello 的 ALPN 可在明文握手中解析。
    version = b"\x03\x03"
    alpn = b"\x00\x10\x00\x05\x00\x03\x02h2"
    body = version + bytes(range(32)) + b"\x00\xc0\x2f\x00" + pack("!H", len(alpn)) + alpn
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    server_hello = tcp_segment(443, "PA", 2001, 1001, reply=True) / (b"\x16" + version + pack("!H", len(handshake)) + handshake)
    ssh = tcp_segment(2222, "PA", 2001, 1001, reply=True) / b"SSH-2.0-NetSnifferSample\r\n"
    # RFC 9001 附录 A.2 的完整、受保护的 QUIC v1 Client Initial。
    initial = bytes.fromhex(Path(__file__).with_name("quic_initial_rfc9001.hex").read_text(encoding="ascii"))
    quic = ipv4() / UDP(sport=CLIENT_PORT, dport=4443) / initial
    return [dhcp, mdns, ssdp, ntp, server_hello, ssh, quic]


def display_filter_packets() -> list[Packet]:
    http = http_packets()[3]
    http[IP].src = "192.168.34.5"
    query, response = dns_packets()
    query[IP].src = "192.168.34.7"
    syn, syn_ack, _ = tcp_handshake(443)
    selected = tls_packets(b"bilibili.example")[-1]
    selected[TCP].sport = 53006
    other = tls_packets()[-1]
    other[TCP].sport = 53007
    return [http, query, response, syn, syn_ack, selected, other]


def tcp_reassembly_packets() -> list[Packet]:
    # 让 SNI 和 HTTP Host 落在段边界之后，再切开 DNS 的长度前缀。
    padding = pack("!HH", 21, 1250) + bytes(1250)
    tls = tls_client_hello(b"split.example", leading_extensions=padding)
    dns = bytes(DNS(id=1, rd=1, qd=DNSQR(qname=HOSTNAME, qtype="A")))
    packets = []
    for port, message, split in (
        (443, tls, 1200), (8080, HTTP_REQUEST, 30), (53, pack("!H", len(dns)) + dns, 1),
    ):
        packets.extend(tcp_handshake(port))
        packets.append(tcp_segment(port, "PA", 1001, 2001) / message[:split])
        packets.append(tcp_segment(port, "PA", 1001 + split, 2001) / message[split:])
    return packets


def make_samples(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    arp_conflict = Ether(src=OTHER_MAC, dst=BROADCAST_MAC) / ARP(
        op=2, hwsrc=OTHER_MAC, psrc=SERVER_IP, hwdst=BROADCAST_MAC, pdst=SERVER_IP
    )
    traces = {
        "tcp_http": http_packets(),
        "tcp_flow_graph": flow_graph_packets(),
        "dns": dns_packets(),
        "tls_client_hello": tls_packets(),
        "application_protocols": application_packets(),
        "display_filters": display_filter_packets(),
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
        "tcp_reassembly": tcp_reassembly_packets(),
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
