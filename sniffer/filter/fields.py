from collections.abc import Iterable

# 当前协议解析器发出的字段，包括协议节点和诊断节点。
FIELD_NAMES = frozenset("""
app app.basis app.invalid_http app.port_hint
application
arp arp.dst.hw_mac arp.dst.proto arp.dst.proto_ipv4 arp.hw.size arp.hw.type arp.incomplete arp.opcode
arp.proto.size arp.proto.type arp.src.hw_mac arp.src.proto arp.src.proto_ipv4
data
dhcp dhcp.cookie dhcp.flags dhcp.hops dhcp.hw.len dhcp.hw.mac_addr dhcp.hw.type dhcp.id dhcp.incomplete
dhcp.ip.ciaddr dhcp.ip.giaddr dhcp.ip.siaddr dhcp.ip.yiaddr dhcp.op dhcp.option dhcp.option.broadcast
dhcp.option.client_id dhcp.option.dns_server dhcp.option.domain_name dhcp.option.end dhcp.option.hostname
dhcp.option.incomplete dhcp.option.lease_time dhcp.option.length dhcp.option.message_type
dhcp.option.parameter_request dhcp.option.rebinding_time dhcp.option.renewal_time dhcp.option.requested_ip
dhcp.option.router dhcp.option.server_id dhcp.option.subnet_mask dhcp.option.type dhcp.option.vendor_class
dhcp.options dhcp.secs
dns dns.a dns.aaaa dns.cname dns.count.add_rr dns.count.answers dns.count.auth_rr dns.count.queries
dns.flags dns.flags.authoritative dns.flags.opcode dns.flags.rcode dns.flags.recavail dns.flags.recdesired
dns.flags.response dns.flags.truncated dns.id dns.incomplete dns.mx dns.ns dns.preference dns.ptr
dns.qry.class dns.qry.name dns.qry.qu dns.qry.type dns.question dns.record dns.resp.cache_flush
dns.resp.class dns.resp.len dns.resp.name dns.resp.ttl dns.resp.type dns.section.additional
dns.section.answer dns.section.authority dns.section.qry dns.srv dns.srv.port dns.srv.weight dns.tcp
dns.tcp.incomplete dns.tcp.length dns.tcp.message dns.txt
eth eth.dst eth.incomplete eth.src eth.type
frame frame.cap_len frame.len frame.number frame.time frame.time_delta
http http.body http.content_length http.header http.header.name http.headers_incomplete http.host
http.request.method http.request.uri http.response.code http.response.phrase http.user_agent http.version
icmp icmp.checksum icmp.checksum.valid icmp.code icmp.data icmp.ident icmp.incomplete icmp.mtu
icmp.pointer icmp.redir_gw icmp.seq icmp.timestamp.originate icmp.timestamp.receive
icmp.timestamp.transmit icmp.type
icmpv6 icmpv6.checksum icmpv6.checksum.valid icmpv6.code icmpv6.data icmpv6.echo.identifier
icmpv6.echo.sequence_number icmpv6.incomplete icmpv6.mtu icmpv6.nd.destination icmpv6.nd.na.flags
icmpv6.nd.ra.cur_hop_limit icmpv6.nd.ra.flags icmpv6.nd.ra.reachable_time icmpv6.nd.ra.retrans_timer
icmpv6.nd.ra.router_lifetime icmpv6.nd.target icmpv6.opt icmpv6.opt.incomplete icmpv6.opt.length
icmpv6.opt.linkaddr icmpv6.opt.prefix icmpv6.opt.prefix.valid_lifetime icmpv6.opt.prefix_len
icmpv6.opt.type icmpv6.pointer icmpv6.type
ip ip.checksum ip.checksum.valid ip.dsfield.dscp ip.dsfield.ecn ip.dst ip.flags.df ip.flags.mf ip.flags.rb
ip.frag_offset ip.hdr_len ip.id ip.incomplete ip.len ip.option ip.option.incomplete ip.option.type
ip.proto ip.src ip.truncated ip.ttl ip.version
ipv6 ipv6.ah.seq ipv6.ah.spi ipv6.dst ipv6.ext ipv6.ext.incomplete ipv6.ext.len ipv6.ext.nxt ipv6.flow
ipv6.frag.id ipv6.frag.more ipv6.frag.offset ipv6.hlim ipv6.incomplete ipv6.nxt ipv6.opt
ipv6.opt.incomplete ipv6.opt.type ipv6.plen ipv6.routing.segments_left ipv6.routing.type ipv6.src
ipv6.tclass ipv6.truncated ipv6.version
malformed malformed.incomplete
mdns
ntp ntp.flags.li ntp.flags.mode ntp.flags.vn ntp.incomplete ntp.org ntp.poll ntp.precision ntp.rec
ntp.refid ntp.reftime ntp.rootdelay ntp.rootdispersion ntp.stratum ntp.xmt
null null.family null.incomplete
quic quic.dcid quic.flags quic.scid quic.version
ssdp ssdp.body ssdp.header ssdp.header.name ssdp.headers_incomplete ssdp.host ssdp.man ssdp.mx
ssdp.request.method ssdp.request.uri ssdp.response.code ssdp.response.phrase ssdp.st ssdp.version
ssh ssh.banner
tcp tcp.ack tcp.checksum tcp.checksum.valid tcp.dstport tcp.flags tcp.flags.ack tcp.flags.cwr
tcp.flags.ece tcp.flags.fin tcp.flags.psh tcp.flags.rst tcp.flags.syn tcp.flags.urg tcp.hdr_len
tcp.incomplete tcp.len tcp.option tcp.option.incomplete tcp.option.kind tcp.option.length tcp.options
tcp.options.incomplete tcp.options.mss_val tcp.options.sack_le tcp.options.sack_re
tcp.options.timestamp.tsecr tcp.options.timestamp.tsval tcp.options.wscale.shift tcp.payload tcp.reassembled tcp.seq
tcp.srcport tcp.stream tcp.urgent_pointer tcp.window_size
tls tls.handshake tls.handshake.ciphersuite tls.handshake.ciphersuites tls.handshake.comp_method
tls.handshake.compression_methods tls.handshake.extension tls.handshake.extension.incomplete
tls.handshake.extension.len tls.handshake.extension.type tls.handshake.extensions
tls.handshake.extensions_alpn.incomplete tls.handshake.extensions_alpn_str
tls.handshake.extensions_key_share_group tls.handshake.extensions_key_share_key_exchange_length
tls.handshake.extensions_missing tls.handshake.extensions_server_name
tls.handshake.extensions_server_name.incomplete tls.handshake.extensions_supported_version
tls.handshake.incomplete tls.handshake.length tls.handshake.random tls.handshake.session_id
tls.handshake.session_id_length tls.handshake.type tls.handshake.version tls.record
tls.record.content_type tls.record.length tls.record.payload tls.record.truncated tls.record.version
udp udp.checksum udp.checksum.valid udp.dstport udp.incomplete udp.length udp.payload udp.srcport udp.stream
udp.truncated
vlan vlan.dei vlan.etype vlan.id vlan.incomplete vlan.priority
""".split())

ALIASES = {
    "ip.addr": ("ip.src", "ip.dst"),
    "ipv6.addr": ("ipv6.src", "ipv6.dst"),
    "tcp.port": ("tcp.srcport", "tcp.dstport"),
    "udp.port": ("udp.srcport", "udp.dstport"),
    "tcp.flags.push": ("tcp.flags.psh",),
    "tcp.flags.reset": ("tcp.flags.rst",),
    "tcp.seq_raw": ("tcp.seq",),
    "tcp.ack_raw": ("tcp.ack",),
    "tls.handshake.extensions.supported_version": ("tls.handshake.extensions_supported_version",),
    "dhcp.ip.client": ("dhcp.ip.ciaddr",),
    "dhcp.ip.your": ("dhcp.ip.yiaddr",),
    "dhcp.ip.server": ("dhcp.ip.siaddr",),
    "dhcp.ip.relay": ("dhcp.ip.giaddr",),
    "dhcp.option.dhcp": ("dhcp.option.message_type",),
}

SUGGESTIONS = tuple(sorted(FIELD_NAMES | ALIASES.keys()))


def known_field(name: str) -> bool:
    if name in FIELD_NAMES or name in ALIASES:
        return True
    # HTTP 与 SSDP 的任意头部名称在捕获时决定。
    prefix, _, header = name.partition(".")
    return prefix in ("http", "ssdp") and bool(header) and all(c.isalnum() or c == "_" for c in header)


def concrete_fields(names: Iterable[str]) -> frozenset[str]:
    return frozenset(field for name in names for field in ALIASES.get(name, (name,)))
