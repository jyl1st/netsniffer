# netsniffer
Network packet sniffer & protocol analyzer with GUI (Python + Npcap + PySide6)

## 显示过滤器

开始抓包或打开抓包文件后，在包列表上方输入表达式并按 Enter 应用。清除过滤可以恢复全部包，保存抓包时会保存完整会话。

- `(http || dns) && ip.src == 192.168.0.0/16` 匹配来自指定网段的 HTTP 或 DNS 包。
- `tcp.flags.syn && !tcp.flags.ack` 匹配 TCP 初始 SYN。
- `tls.handshake.extensions_server_name contains "bilibili"` 匹配 SNI 含指定字符串的 TLS 握手。

这三条表达式可通过打开 `samples/display_filters.pcap` 试用。安装 TShark 后可在仓库根目录运行 `python -m tools.compare_tshark` 检查结果。[Windows 本机回环实测截图](docs/images/phase3-loopback-display-filter.png)
