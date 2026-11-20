from scapy.all import ARP, DNS, ICMP, IPv6, TCP, rdpcap

from samples.make_samples import HOSTNAME, HTTP_REQUEST, make_samples


def test_samples_are_reproducible_and_readable(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    make_samples(first)
    make_samples(second)

    expected_counts = {
        "tcp_http": 6,
        "dns": 2,
        "tls_client_hello": 4,
        "application_protocols": 7,
        "display_filters": 7,
        "icmp": 2,
        "arp": 2,
        "ipv6": 2,
        "tcp_retransmission": 7,
        "arp_conflict": 3,
        "syn_scan": 16,
    }
    assert {path.stem for path in first.glob("*.pcap")} == expected_counts.keys()

    traces = {}
    for scenario, count in expected_counts.items():
        filename = f"{scenario}.pcap"
        path = first / filename
        assert path.read_bytes() == (second / filename).read_bytes()
        traces[scenario] = rdpcap(str(path))
        assert len(traces[scenario]) == count

    http = traces["tcp_http"]
    assert [str(packet[TCP].flags) for packet in http[:3]] == ["S", "SA", "A"]
    assert http[2][TCP].ack == http[1][TCP].seq + 1
    assert bytes(http[3][TCP].payload) == HTTP_REQUEST
    assert http[4][TCP].ack == http[3][TCP].seq + len(HTTP_REQUEST)

    dns = traces["dns"]
    assert dns[0][DNS].qd[0].qname == HOSTNAME + b"."
    assert dns[1][DNS].qr == 1
    tls = bytes(traces["tls_client_hello"][-1][TCP].payload)
    assert tls[:3] == b"\x16\x03\x03"
    assert int.from_bytes(tls[3:5], "big") == len(tls[5:])
    assert tls[5] == 1
    assert int.from_bytes(tls[6:9], "big") == len(tls[9:])
    # ClientHello 的固定字段、空会话 ID、单一套件和压缩方式共 41 字节。
    extensions = tls[9 + 41:]
    assert int.from_bytes(extensions[:2], "big") == len(extensions[2:])
    assert extensions[2:4] == b"\x00\x00"
    assert int.from_bytes(extensions[4:6], "big") == len(extensions[6:])
    assert int.from_bytes(extensions[6:8], "big") == len(extensions[8:])
    assert extensions[8] == 0
    assert int.from_bytes(extensions[9:11], "big") == len(HOSTNAME)
    assert extensions[11:] == HOSTNAME

    assert traces["icmp"][0][ICMP].type == 8
    assert traces["ipv6"][0][IPv6].src == "2001:db8::10"
    assert [packet[ARP].op for packet in traces["arp"]] == [1, 2]

    original, duplicate = traces["tcp_retransmission"][3:5]
    assert bytes(original) == bytes(duplicate)
    assert duplicate.time > original.time

    first_claim, second_claim = traces["arp_conflict"][1:3]
    assert first_claim[ARP].psrc == second_claim[ARP].psrc
    assert first_claim[ARP].hwsrc != second_claim[ARP].hwsrc

    syns = traces["syn_scan"]
    assert all(str(packet[TCP].flags) == "S" for packet in syns)
    assert len({packet[TCP].dport for packet in syns}) == len(syns)
