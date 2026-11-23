# NetSniffer

NetSniffer 是一款面向 Windows 的图形化网络嗅探器与协议分析工具，使用 Python、Npcap 和 PySide6。可以实时捕获网络流量，也可以打开已有的 PCAP 或 PCAPNG 文件分析。

## 功能

- **抓包与文件读写**：选择网卡、设置 BPF 抓包过滤器、查看捕获与丢弃计数，打开或保存 PCAP 和 PCAPNG。
- **协议解析**：支持 Ethernet、VLAN、ARP、IPv4、IPv6、ICMP、TCP、UDP 及常见应用协议。包列表、协议详情和十六进制视图联动，支持从字段定位字节，也可反向定位。应用识别优先检查报文内容。
- **显示过滤**：支持按协议和字段筛选，可用比较、逻辑组合、CIDR 和正则。例如 `tcp.flags.syn && !tcp.flags.ack` 可筛出 TCP 初始 SYN。
- **流追踪与进程视图**：按流号双向追踪 TCP 或 UDP 并保存负载，支持 TCP 重组和实时抓包中的进程关联。TCP 时序图可标出握手、挥手和复位，点击箭头可定位原帧。
- **统计与安全分析**：提供协议层级、会话、端点和 IO 图表。按抓包快照检查 ARP 映射冲突、SYN 扫描和明文凭据，并列出 TCP 重传、重复 ACK、零窗口、复位与保活等专家信息。
- **Wireshark 扩展**：Lua 插件为 Wireshark 添加应用识别字段和统计窗口。

## 运行要求

- Windows 10 或 Windows 11（64 位）。
- 以管理员权限运行 NetSniffer。
- 先安装 [Npcap](https://npcap.com/)，并勾选「Install Npcap in WinPcap API-compatible Mode」。

## 运行 EXE

从 [GitHub Release v1.0](https://github.com/jyl1st/netsniffer/releases/tag/v1.0) 下载 `NetSniffer.exe`。双击程序并确认 UAC 提示。在欢迎页选择网卡后开始抓包，也可以通过「文件 → 打开抓包文件」分析已有文件。

## 从源码运行

在仓库根目录打开管理员终端。首次配置时创建 Conda 环境并安装依赖，之后运行前激活该环境即可。

```powershell
conda create -n netsniffer python=3.12 -y
conda activate netsniffer
python -m pip install -r requirements.txt
python main.py
```

在已激活的环境中运行测试：

```powershell
pytest -q
```

使用 PyInstaller 构建单文件程序，产物位于 `dist/NetSniffer.exe`。

```powershell
python -m PyInstaller --noconfirm --clean packaging/netsniffer.spec
```

## 安装 Wireshark Lua 插件

1. 在 Wireshark 的「帮助 → 关于 Wireshark → 文件夹」中找到 `Personal Lua Plugins`。Windows 上通常是 `%APPDATA%\Wireshark\plugins`。
2. 将 [netsniffer_appid.lua](wireshark_plugin/netsniffer_appid.lua) 复制进去，重启 Wireshark。
3. 打开抓包文件，在协议树中展开「NetSniffer 应用识别」。右键点击应用识别字段可将其添加为列。
4. 通过「工具 → NetSniffer 应用识别统计」查看已识别、端口不符和候选未确认的帧数。

## 目录说明

| 路径 | 内容 |
| --- | --- |
| `main.py` | 程序入口 |
| `sniffer/` | 抓包、协议解析、显示过滤、流量分析、记录模型与图形界面 |
| `samples/` | 合成抓包样例与生成脚本 |
| `tests/` | pytest 自动化测试 |
| `tools/` | TShark 对照与性能基准脚本 |
| `packaging/` | PyInstaller 配置与程序图标 |
| `wireshark_plugin/` | Wireshark Lua 插件 |
| `docs/images/` | 界面与验收截图 |

## 许可

本项目采用 MIT 许可，详见 [LICENSE](LICENSE)。
