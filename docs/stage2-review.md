# 阶段 2 实流量复核

## 发现的问题

- 旧 QUIC 特征接受过宽，常用 UDP 服务端口与内容核对失败的 TCP 端口可能误标。已改为按强特征、经验证的端口、弱特征排序，并把端口失败显示为提示。
- TLS 记录跨段时会丢掉整个 ClientHello。DNS over TCP 会在消息未收齐时跳过消息，HTTP 可能把无效首行当成截断。已保留可读字段，并区分记录跨段和实际捕获截断。
- Ethernet、ARP、IPv4、IPv6、TCP、UDP、ICMP、ICMPv6、DHCP、NTP 的部分截断分支会丢弃已有字段。已保留完整字段并标注缺失位置。DNS、mDNS、SSDP、TLS 和 SSH 按各自的最小报头或首行判断，QUIC 长报头仍需可核对的边界才参与弱识别。
- TCP 原始序号目前保存在 tcp.seq 和 tcp.ack。Wireshark 区分 tcp.seq_raw、tcp.ack_raw 与相对序号。IPv4、TCP 标志位使用布尔值，DNS 等协议通过对应数字和文本字段保留原始值。阶段 3 应明确哪些值用于过滤。
- ip.addr、ipv6.addr、tcp.port、udp.port 需要求值器查询两端字段。阶段 3 将其实现为多值别名，协议树保留原始源和目标字段。

## 截断与识别检查

| 解析器 | 可保留的内容 |
|---|---|
| Ethernet / VLAN | MAC、外层类型和已完整的标签 |
| ARP / 回环 | 地址族或 ARP 报头，以及已完整的地址 |
| IPv4 | 报头字段与已经完整的选项 |
| IPv6 | 基础报头、已读扩展，及截断扩展中可读的类型和长度 |
| TCP | 固定报头和已完整的选项 |
| UDP | 已完整的源端口、目标端口和长度，缺失负载单独提示 |
| ICMP / ICMPv6 | 类型、代码、已完整的回显字段、邻居发现字段或选项 |
| DNS / mDNS / DNS over TCP | 报头、已读查询及应答、截断记录中可读的名称和类型 |
| HTTP / SSDP | 合法首行、已读头部和末尾可读的值 |
| TLS | 记录头、握手前缀和已到达的 Hello 扩展，包括 SNI |
| DHCP | BOOTP 报头、地址与已完整的选项 |
| NTP | 标志、时间报头中已完整的字段 |
| SSH | 验证横幅；无完整横幅时保留原始数据和端口提示 |
| QUIC | 验证长报头和长度；不足以确认时保留 UDP 和原始数据 |

使用固定种子 20261120 的 50,000 个均匀随机负载，长度覆盖 1 到 4,096 字节的十个档位。分别检查 TCP 普通端口及 22、443、8080，UDP 普通端口及 53、5353、123、67、68、1900、443。最终共 600,000 次判断，未观察到应用协议误标。收紧过程中观察到的 NTP 与 QUIC 误标促使校验加入 NTP 长度和填充约束，以及未知 QUIC 版本的长度一致性约束。另用 4,734 个样例截断前缀检查字段范围。[NTP 控制消息格式](https://datatracker.ietf.org/doc/html/rfc9327#section-2)

## 待定设计

- TCP 重组、捕获开始于连接中途时识别 HTTP/TLS 正文，以及已识别连接的后续短头 QUIC 数据需要跨包状态。TCP 流重组按计划留在阶段 4，QUIC 流级识别另行决定。
- 清单保留当前应用字段和详情节点名。阶段 3 可以将 Wireshark 同义名映射到现有字段，是否批量更名以及如何处理文件兼容性需先确认。

## 当前字段名

按当前代码中的字段和可展开节点收录。下表按本机 TShark 的注册表检查同名，协议节点、诊断节点、内部派生量和应用识别字段也包含在清单中。同名只代表拼写对应，语义差异见上文。

阶段 3 可优先补 `tcp.flags.push` → `tcp.flags.psh`、`tcp.flags.reset` → `tcp.flags.rst`、`tls.handshake.extensions.supported_version` → `tls.handshake.extensions_supported_version`。HTTP 的请求和响应版本目前统一为 `http.version`。DHCP 的 `dhcp.ip.client/your/server/relay` 分别对应项目里的 `dhcp.ip.ciaddr/yiaddr/siaddr/giaddr`，Wireshark 的 `dhcp.option.dhcp` 对应 `dhcp.option.message_type`。

| 组 | 与 TShark 同名 | 项目自定义或别名待定 |
|---|---|---|
| app | — | `app`, `app.basis`, `app.invalid_http`, `app.port_hint` |
| application | — | `application` |
| arp | `arp`, `arp.dst.hw_mac`, `arp.dst.proto`, `arp.dst.proto_ipv4`, `arp.hw.size`, `arp.hw.type`, `arp.opcode`, `arp.proto.size`, `arp.proto.type`, `arp.src.hw_mac`, `arp.src.proto`, `arp.src.proto_ipv4` | `arp.incomplete` |
| data | `data` | — |
| dhcp | `dhcp`, `dhcp.cookie`, `dhcp.flags`, `dhcp.hops`, `dhcp.hw.len`, `dhcp.hw.mac_addr`, `dhcp.hw.type`, `dhcp.id`, `dhcp.option.domain_name`, `dhcp.option.end`, `dhcp.option.hostname`, `dhcp.option.length`, `dhcp.option.router`, `dhcp.option.subnet_mask`, `dhcp.option.type`, `dhcp.secs` | `dhcp.incomplete`, `dhcp.ip.ciaddr`, `dhcp.ip.giaddr`, `dhcp.ip.siaddr`, `dhcp.ip.yiaddr`, `dhcp.op`, `dhcp.option`, `dhcp.option.broadcast`, `dhcp.option.client_id`, `dhcp.option.dns_server`, `dhcp.option.incomplete`, `dhcp.option.lease_time`, `dhcp.option.message_type`, `dhcp.option.parameter_request`, `dhcp.option.rebinding_time`, `dhcp.option.renewal_time`, `dhcp.option.requested_ip`, `dhcp.option.server_id`, `dhcp.option.vendor_class`, `dhcp.options` |
| dns | `dns`, `dns.a`, `dns.aaaa`, `dns.cname`, `dns.count.add_rr`, `dns.count.answers`, `dns.count.auth_rr`, `dns.count.queries`, `dns.flags`, `dns.flags.authoritative`, `dns.flags.opcode`, `dns.flags.rcode`, `dns.flags.recavail`, `dns.flags.recdesired`, `dns.flags.response`, `dns.flags.truncated`, `dns.id`, `dns.ns`, `dns.qry.class`, `dns.qry.name`, `dns.qry.qu`, `dns.qry.type`, `dns.resp.cache_flush`, `dns.resp.class`, `dns.resp.len`, `dns.resp.name`, `dns.resp.ttl`, `dns.resp.type`, `dns.srv.port`, `dns.srv.weight`, `dns.txt` | `dns.incomplete`, `dns.mx`, `dns.preference`, `dns.ptr`, `dns.question`, `dns.record`, `dns.section.additional`, `dns.section.answer`, `dns.section.authority`, `dns.section.qry`, `dns.srv`, `dns.tcp`, `dns.tcp.incomplete`, `dns.tcp.length`, `dns.tcp.message` |
| eth | `eth`, `eth.dst`, `eth.src`, `eth.type` | `eth.incomplete` |
| frame | `frame`, `frame.cap_len`, `frame.len`, `frame.number`, `frame.time`, `frame.time_delta` | — |
| http | `http`, `http.content_length`, `http.host`, `http.request.method`, `http.request.uri`, `http.response.code`, `http.response.phrase`, `http.user_agent` | `http.body`, `http.header`, `http.header.name`, `http.headers_incomplete`, `http.version` |
| icmp | `icmp`, `icmp.checksum`, `icmp.code`, `icmp.ident`, `icmp.mtu`, `icmp.pointer`, `icmp.redir_gw`, `icmp.seq`, `icmp.type` | `icmp.checksum.valid`, `icmp.data`, `icmp.incomplete`, `icmp.timestamp.originate`, `icmp.timestamp.receive`, `icmp.timestamp.transmit` |
| icmpv6 | `icmpv6`, `icmpv6.checksum`, `icmpv6.code`, `icmpv6.data`, `icmpv6.echo.identifier`, `icmpv6.echo.sequence_number`, `icmpv6.mtu`, `icmpv6.nd.ra.cur_hop_limit`, `icmpv6.nd.ra.reachable_time`, `icmpv6.nd.ra.retrans_timer`, `icmpv6.nd.ra.router_lifetime`, `icmpv6.opt`, `icmpv6.opt.length`, `icmpv6.opt.linkaddr`, `icmpv6.opt.prefix`, `icmpv6.opt.prefix.valid_lifetime`, `icmpv6.opt.type`, `icmpv6.pointer`, `icmpv6.type` | `icmpv6.checksum.valid`, `icmpv6.incomplete`, `icmpv6.nd.destination`, `icmpv6.nd.na.flags`, `icmpv6.nd.ra.flags`, `icmpv6.nd.target`, `icmpv6.opt.incomplete`, `icmpv6.opt.prefix_len` |
| ip | `ip`, `ip.checksum`, `ip.dsfield.dscp`, `ip.dsfield.ecn`, `ip.dst`, `ip.flags.df`, `ip.flags.mf`, `ip.flags.rb`, `ip.frag_offset`, `ip.hdr_len`, `ip.id`, `ip.len`, `ip.proto`, `ip.src`, `ip.ttl`, `ip.version` | `ip.checksum.valid`, `ip.incomplete`, `ip.option`, `ip.option.incomplete`, `ip.option.type`, `ip.truncated` |
| ipv6 | `ipv6`, `ipv6.dst`, `ipv6.flow`, `ipv6.hlim`, `ipv6.nxt`, `ipv6.opt`, `ipv6.opt.type`, `ipv6.plen`, `ipv6.routing.type`, `ipv6.src`, `ipv6.tclass`, `ipv6.version` | `ipv6.ah.seq`, `ipv6.ah.spi`, `ipv6.ext`, `ipv6.ext.incomplete`, `ipv6.ext.len`, `ipv6.ext.nxt`, `ipv6.frag.id`, `ipv6.frag.more`, `ipv6.frag.offset`, `ipv6.incomplete`, `ipv6.opt.incomplete`, `ipv6.routing.segments_left`, `ipv6.truncated` |
| malformed | — | `malformed`, `malformed.incomplete` |
| mdns | `mdns` | — |
| ntp | `ntp`, `ntp.flags.li`, `ntp.flags.mode`, `ntp.flags.vn`, `ntp.org`, `ntp.precision`, `ntp.rec`, `ntp.refid`, `ntp.reftime`, `ntp.rootdelay`, `ntp.rootdispersion`, `ntp.stratum`, `ntp.xmt` | `ntp.incomplete`, `ntp.poll` |
| null | `null`, `null.family` | `null.incomplete` |
| quic | `quic`, `quic.dcid`, `quic.scid`, `quic.version` | `quic.flags` |
| ssdp | `ssdp` | `ssdp.body`, `ssdp.header`, `ssdp.header.name`, `ssdp.headers_incomplete`, `ssdp.host`, `ssdp.man`, `ssdp.mx`, `ssdp.request.method`, `ssdp.request.uri`, `ssdp.response.code`, `ssdp.response.phrase`, `ssdp.st`, `ssdp.version` |
| ssh | `ssh` | `ssh.banner` |
| tcp | `tcp`, `tcp.ack`, `tcp.checksum`, `tcp.dstport`, `tcp.flags`, `tcp.flags.ack`, `tcp.flags.cwr`, `tcp.flags.ece`, `tcp.flags.fin`, `tcp.flags.syn`, `tcp.flags.urg`, `tcp.hdr_len`, `tcp.len`, `tcp.options`, `tcp.options.mss_val`, `tcp.options.sack_le`, `tcp.options.sack_re`, `tcp.options.timestamp.tsecr`, `tcp.options.timestamp.tsval`, `tcp.options.wscale.shift`, `tcp.payload`, `tcp.seq`, `tcp.srcport`, `tcp.urgent_pointer`, `tcp.window_size` | `tcp.checksum.valid`, `tcp.flags.psh`, `tcp.flags.rst`, `tcp.incomplete`, `tcp.option`, `tcp.option.incomplete`, `tcp.option.kind`, `tcp.option.length`, `tcp.options.incomplete` |
| tls | `tls`, `tls.handshake`, `tls.handshake.ciphersuite`, `tls.handshake.ciphersuites`, `tls.handshake.comp_method`, `tls.handshake.extension.len`, `tls.handshake.extension.type`, `tls.handshake.extensions_alpn_str`, `tls.handshake.extensions_key_share_group`, `tls.handshake.extensions_key_share_key_exchange_length`, `tls.handshake.extensions_server_name`, `tls.handshake.length`, `tls.handshake.random`, `tls.handshake.session_id`, `tls.handshake.session_id_length`, `tls.handshake.type`, `tls.handshake.version`, `tls.record`, `tls.record.content_type`, `tls.record.length`, `tls.record.version` | `tls.handshake.compression_methods`, `tls.handshake.extension`, `tls.handshake.extension.incomplete`, `tls.handshake.extensions`, `tls.handshake.extensions_alpn.incomplete`, `tls.handshake.extensions_missing`, `tls.handshake.extensions_server_name.incomplete`, `tls.handshake.extensions_supported_version`, `tls.handshake.incomplete`, `tls.record.payload`, `tls.record.truncated` |
| udp | `udp`, `udp.checksum`, `udp.dstport`, `udp.length`, `udp.payload`, `udp.srcport` | `udp.checksum.valid`, `udp.incomplete`, `udp.truncated` |
| vlan | `vlan`, `vlan.dei`, `vlan.etype`, `vlan.id`, `vlan.priority` | `vlan.incomplete` |

HTTP 和 SSDP 的任意头部还生成 http.<header>、ssdp.<header>。名称转为小写，连字符转为下划线，字段值保留实际字节范围。DHCP 未知选项显示为选项节点和原始数据。

参考 [Wireshark 显示过滤器字段](https://www.wireshark.org/docs/dfref/)、[TCP 字段](https://www.wireshark.org/docs/dfref/t/tcp.html)、[DNS 字段](https://www.wireshark.org/docs/dfref/d/dns.html)。
