# 设计决策

## 阶段 0 样例数据

可以构造一份混合抓包，也可以按场景拆成多个文件。采用分场景文件，便于测试导入和定位失败，并保留各场景内的包顺序与时间间隔。样例使用文档专用地址和固定时间戳，生成过程只写入本地 pcap。

ClientHello 只包含明文握手与 SNI。样例直接编写这些字段，Scapy 负责封装以太网帧和写 pcap，因此生成样例只需现有依赖。

## 阶段 1 抓包与呈现

网卡列表结合 Scapy 的 Npcap 设备标识、Windows 接口类型和驱动描述。虚拟网卡可能报告为以太网或无线，先根据驱动描述识别常见虚拟网卡。优先选中有可用地址的物理网卡，并用采样到的收发速率给多块候选网卡排序。

抓包线程生成轻量列表摘要，通过有界队列向 Qt 线程交接。界面定时批量更新列表，队列或会话达到上限时计入丢弃。抓包过滤直接在选中网卡的 Npcap 句柄上编译和安装，确保校验使用实际链路类型。

### 抓包吞吐与文件预览

用 Windows 回环网卡测试三档定速 UDP 流量，每档计划运行 4 秒。原先通过 Scapy 创建整包对象，中档实际约 2,370 包/秒，Qt 的 30 ms 计时器最大间隔为 391 ms，高档超时。现在抓包线程通过 `pcap_next_ex` 读取原始帧、微秒时间戳和线上帧长，再生成列表摘要。同一测试下三档均无丢包，最高档实际为 7,500 包/秒，30,000 帧全部显示，计时器最大间隔为 47 ms。两组数据来自本机的 Qt 离屏会话。

BPF 实时校验和实际开始抓包共用编译逻辑，校验在输入短暂停顿后于后台执行。打开超过 100,000 包或 128 MiB 帧数据的文件时，只加载上限以内的前缀，并在状态栏显示实际加载的包数。

## 阶段 2 协议解析

完整解析在选包时由后台线程执行，列表继续使用轻量摘要。协议树的每个字节范围都以帧首为原点。解析器通过有边界的字节区间读取报头，能将截断和格式错误显示为节点。应用识别优先使用内容特征，回退到端口时在列表和协议树中标明依据。

阶段 2 按单帧解析。跨 TCP 段的 HTTP、DNS 和 TLS 消息会展示首段完整可读的字段，完整消息留待阶段 4 流重组。校验和着色仅使用可验证的完整字节范围。出站抓包可能观察到网卡卸载前的校验和，详情中展示计算结果。

验收图 `docs/images/phase2-loopback-http.png` 来自在 Windows 本机启动的 8080 端口 HTTP 服务。NetSniffer 通过 Npcap 实际捕获回环流量，图中选中了请求的 Host 值。另用 `samples/` 中的离线 pcap 验证协议覆盖与字段偏移。

### 实流量复核

识别顺序为强内容特征、经内容核对的端口候选、QUIC 弱特征。HTTP 必须匹配合法首行，TLS 必须有合法的 5 字节记录头，SSH 必须有完整的版本横幅。端口候选未通过长度与结构核对时，使用 TCP 或 UDP，并在 Info 中显示端口提示。QUIC 只在至少一端为 UDP 443 或版本已知时参与判断，并检查连接 ID 及可取得的长度边界。DNS、mDNS、DHCP、NTP、SSDP 的服务端口排除 QUIC。离线 QUIC Initial 使用 [RFC 9001 附录 A.2](https://datatracker.ietf.org/doc/html/rfc9001#appendix-A.2) 的公开测试向量。

TLS 记录的声明长度可以大于单个 TCP 段的负载。按已捕获边界遍历 Hello 向量和扩展可以保留先到达的 SNI，也能避免在抓包线程维护连接状态。详情按 caplen 与 wirelen 区分抓包截断和跨 TCP 段。DNS over TCP 保留已到达的消息字段，HTTP 保留已读到的首行和头部。列表使用限定范围的字节检查提取首行、SNI 或 DNS 记录摘要，完整 Field 树留给按需解析。

改前和改后各用同一套 Windows 回环 UDP 压测，每档发送 4 秒。三档的实际速率均达到设定值，所有报文均被显示。

| 实际包/秒 | 发送与显示包数 | 改前丢弃 | 改后丢弃 | Qt 心跳最大间隔，改前 → 改后 |
|---:|---:|---:|---:|---:|
| 1,000 | 4,000 | 0 | 0 | 62 → 47 ms |
| 3,500 | 14,000 | 0 | 0 | 62 → 62 ms |
| 7,500 | 30,000 | 0 | 0 | 47 → 47 ms |

上述为 Qt 离屏回环压测，测量的是 Npcap、列表摘要和界面更新的整体吞吐。[自查与字段清单](stage2-review.md)

## 阶段 3 显示过滤器

显示过滤器使用阶段 2 的 Field 树。BPF 仍决定哪些帧进入抓包会话。后台线程按批次求值，列表保存符合条件的原始包序号，所以切换过滤器后包编号、相对时间和保存抓包的范围仍使用原始记录。新表达式或新文件会使旧批次失效。

字段别名查询两端的实际字段。单独使用布尔字段时按字段值判断，保证 `tcp.flags.syn && !tcp.flags.ack` 匹配初始 SYN。多值字段的相等比较取任意匹配，不等比较要求所有现存值均不匹配。没有字段时比较返回假。只有明确识别的协议参与协议存在性过滤。

`matches` 使用 Qt 提供的 PCRE2，并限制单次匹配的工作量。右键准备表达式只更新输入，右键应用会立即提交。历史和书签保存在本地应用设置中。[Wireshark 显示过滤器](https://www.wireshark.org/docs/man-pages/wireshark-filter.html) · [PCRE2 匹配限制](https://www.pcre.org/current/doc/html/pcre2pattern.html#SEC4)

每阶段收尾时运行 `python -m tools.compare_tshark` 对照已覆盖的验收项，可用 `--stage` 单独运行一阶段。阶段 3 的三条计划表达式分别命中样例的第 1、2 帧，第 4 帧和第 6 帧。加入两条端口比较用例及阶段 2 的三条已解析字段检查后，共八项与 TShark 一致。TShark 的布尔字段用显式值比较来对照初始 SYN。

验收图 `docs/images/phase3-loopback-display-filter.png` 来自在 Windows 上使用 Npcap 捕获的四条本机 TCP 连接。列表在抓包过程中套用显示过滤，36 帧中只显示 4 个初始 SYN，丢弃 0 帧。清除显示过滤即可查看全部捕获帧。

## 阶段 4 流追踪与进程追踪

### 50,000 帧显示过滤基线

在 `v0.5`（`0a2fbf7`）的显示过滤实现上，于 Windows 11（Intel Core i9-12900HX、Python 3.12.16、PySide6 6.12.0）运行 `python -m tools.benchmark_display_filter`。脚本循环使用 `samples/display_filters.pcap` 的 7 个合成帧生成临时抓包，将 50,000 帧预先载入列表，依次应用阶段 3 的三条验收表达式，共三轮。每次都核对了命中帧的原始序号。

耗时从点击“应用”算到最后一批结果写入列表模型，包含 Qt 调度和逐批更新。界面响应以主线程 30 ms Qt 心跳的实际最大间隔衡量。Qt 在离屏窗口中运行，这项数据反映事件循环的响应，未测桌面输入到屏幕呈现的延迟。

| 表达式 | 命中帧数 | 三轮耗时（ms） | 中位耗时（ms） | 三轮心跳最大间隔（ms） |
|---|---:|---|---:|---|
| `(http \|\| dns) && ip.src == 192.168.0.0/16` | 14,286 | 8,332.5 / 7,937.1 / 7,892.3 | 7,937.1 | 132.9 / 92.7 / 108.6 |
| `tcp.flags.syn && !tcp.flags.ack` | 7,143 | 7,951.1 / 7,696.1 / 7,522.3 | 7,696.1 | 118.4 / 91.8 / 84.2 |
| `tls.handshake.extensions_server_name contains "bilibili"` | 7,143 | 7,579.0 / 7,448.6 / 7,422.9 | 7,448.6 | 84.9 / 86.6 / 88.0 |

事件循环在求值期间持续运行，最长一次心跳间隔为 132.9 ms。以上结果用于后续阶段复测。

### TCP/UDP 流编号

将每一端的 IP 地址与端口作为整体，对两个端点排序后用作索引键。TCP 和 UDP 各自从 0 编号，以当前抓包中首次入库的顺序分配。打开另一个文件、清空或开始新抓包时使用新的索引，改变显示过滤条件时沿用已有编号。同一抓包中重用同一个四元组时沿用原编号。

轻解析提取端点。离线文件在读取线程中编号，实时包在确认能写入列表后做一次字典查询，使编号仅受已入库的帧影响，索引大小也受会话容量限制。缺少 TCP/UDP 基本报头或无法取得端口的后续 IP 分片没有流编号。详情树以零字节的生成字段显示流号，显示过滤器和字段右键菜单使用相同的字段。

接入流编号后以相同设置复测一轮，三条表达式的命中序号均正确，耗时依次为 8,101.7、7,976.2、7,863.6 ms，Qt 心跳最大间隔依次为 94.9、104.2、133.7 ms。

### TCP 重组

离线读取与实时抓包分别在后台按捕获顺序重组。每个方向使用独立的 TCP 序号窗口，有 SYN 时以 SYN 后的第一个序号为起点。重叠字节保留首次捕获的数据；存在缺口时等到该区间被补齐。对同时追踪的连接、序号窗口和不连续区间设定上限，避免缺包或长连接让缓存无限增长。

帧记录保持不可变。首段照常显示帧内字段，补齐消息的帧提供可过滤的重组字段。重组字段没有单帧字节偏移，详情树选中时不高亮十六进制。应用协议通过内容校验后由同一连接的两个方向共用，TCP 控制包仍显示为 TCP。

TLS 重组 TCP 上的记录，并拼接连续明文握手记录中的 ClientHello 或 ServerHello。DNS 按两字节长度前缀处理。HTTP/1.x 重组头部，并按 Content-Length 越过消息体继续识别下一条头部。遇到分块传输、以连接关闭标记结尾的消息体或协议升级时，该方向停止查找后续 HTTP 头部。协议依据见 [TCP 序号](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.4)、[TLS 记录](https://www.rfc-editor.org/rfc/rfc8446.html#section-5.1) 和 [HTTP 消息体长度](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3)。

合成样例 `samples/tcp_reassembly.pcap` 可用 `python -m tools.compare_tshark --stage 4` 对照 SNI、HTTP Host 与 DNS 查询名的值和完成帧，分别在第 5、10、15 帧与 TShark 一致。接入 TCP 重组后复测一轮 50,000 帧显示过滤，三条表达式的命中序号均正确，耗时为 7.63–8.19 秒，Qt 心跳最长间隔为 124.4 ms。

已识别的连接遇到序号缺口时，只用与连接协议一致且在单帧内通过内容校验的完整消息重新定位。以新帧起点为边界，放弃边界之前的残片，清除该方向的 HTTP 消息体计数和待拼接的 TLS 握手，保留边界以后的缓存和帧内字段。这样即便缺口后来才补齐，也优先保住后续已经可读的消息。

HTTP 消息体长度失步使用相同的重新定位逻辑。完整的响应头可提供新边界，完整的请求头越过旧消息体末尾时也可提供新边界。完全落在已知消息体内的请求首部继续按消息体处理，避免把正好出现在体内的 HTTP 文本当成请求。此处根据当前帧内容恢复，无需跨方向维护 HEAD 请求队列。

未补齐的应用消息以仅供查看的字段子树保留在详情中，字段值和帧内字节范围仍可查看和高亮。显示过滤跳过该子树，协议名也只在帧中有完整记录或消息时参与过滤。同一帧里已有的完整消息仍可匹配。只有流级推断、尚未补齐消息的数据帧保留协议标签供查看。这样跨段消息在补齐帧上命中一次，缺段始终未补齐时不命中，与 TShark 的重组口径一致。

用 `python -m tools.benchmark_display_filter --runs 1` 在同一 Windows 离屏环境中依次对照修复前 `a847e15` 和最终修复。两版均核对了全部命中序号。

| 表达式 | 命中帧数 | 修复前耗时（ms） | 修复后耗时（ms） |
|---|---:|---:|---:|
| `(http \|\| dns) && ip.src == 192.168.0.0/16` | 14,286 | 9,955.7 | 8,682.3 |
| `tcp.flags.syn && !tcp.flags.ack` | 7,143 | 8,036.8 | 7,997.7 |
| `tls.handshake.extensions_server_name contains "bilibili"` | 7,143 | 8,199.2 | 7,998.3 |

对照轮的 Qt 心跳最大间隔从 176.3 ms 降至 100.6 ms，三条表达式的耗时均未增加。此前一次三轮复测出现最长 700.9 ms 的心跳间隔，第三轮 SNI 过滤触发 30 秒超时。随后一前一后的对照均完整结束，耗时波动仍需结合这个异常观察。

#### 报告素材 · v0.5.2 到 v0.5.3 的重组回归与修复

TCP 重组让跨段字段可用于显示过滤，也引入了两个回归。第一，同一方向遇到永久缺段后，重组游标停在缺口，随后两条完整 HTTP 请求的帧内字段被覆盖。过滤 `http.host` 原来命中 `[1]`。修复后用内容已校验的完整请求恢复边界，缺段的首帧字段仍能查看，过滤命中 `[2, 3]`。第二，跨段 POST 原来在首段和补齐帧分别暴露一次请求字段，`http.request.method == "POST"` 命中 `[0, 1]`。将首段不完整字段标为仅供查看后，只有补齐帧 `[1]` 命中。两例均用零基测试索引复现，修复分别见 `6dc517a` 和 `f717029`。

### Follow Stream

对话框打开时对当前捕获记录取快照，根据传输协议和流号选出对应帧，使用帧内偏移读出原始 TCP/UDP 负载。TCP 按方向展开 32 位序号，重叠区间采用最先捕获的字节，缺口在预览和文本文件中标明。UDP 保留数据报的捕获顺序。两个方向各自按序排列，再按捕获位置合并；应用层重组的消费状态不会影响追踪结果。

从包列表右键打开追踪窗口，主窗口随即应用 `tcp.stream == N` 或 `udp.stream == N`，追踪内容取自打开时完整抓包中的匹配帧。两端使用不同颜色，方向选择同时作用于预览和保存。ASCII 与十六进制保存为带方向标签的文本。原始字节模式用转义预览，保存为二进制并跳过未捕获的区间。长流分页预览和整流导出共用同一份数据，整理和写文件均在后台执行。

以 `samples/tcp_retransmission.pcap` 验证完整的 HTTP 请求和应答，重传段只计一次。离屏 Qt 验证了 TCP 和 UDP 的右键入口、自动过滤、方向分色、三种格式、单向二进制保存及跨页预览。

### 进程映射

实时抓包期间每秒在独立线程读取一次套接字快照，抓包线程入队时按协议和两端实际地址查询。优先查带远端地址的套接字，UDP 可按已绑定的本地端点查找，TCP 监听套接字用于标记入站初始 SYN。通配绑定只匹配同地址族且属于本机网卡的地址。同一套接字键有多个候选或 PID 不可确定时留空。回环通信可关联两端的进程。离线文件保留抓包当时的字节，进程标签属于本次实时会话的元数据。

进程视图按抓包时已关联的 PID 汇总 TCP 流、对端、包数和线上帧字节数。双击后使用流号查看完整的已捕获流，包括未关联 PID 的帧。采样间隔内开始并结束的连接可能没有标签。Windows 可进一步用 ETW 的 TCP/IP 连接事件缩短关联盲区。 [psutil 套接字 API](https://psutil.io/api/#psutil.net_connections) · [Windows ETW TCP/IP 事件](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip)

阶段 4 验收让 Chrome 访问两个本机 HTTP 测试端口，并通过 Npcap 回环抓取 33 帧。`proc.name == "chrome.exe"` 命中 20 帧，进程视图列出 3 条 TCP 流，远端地址覆盖两个测试端口。右键按 PID 过滤、双击流应用显示过滤以及 Follow Stream 还原 HTTP 请求与应答均通过。 [进程视图验收截图](images/phase4-loopback-process-streams.png)

新连接的握手和第一个请求可能早于每秒一次的套接字快照。TCP 流任一帧获得归属后，列表按流号将进程匹配回填到已有帧并沿用到后续帧。匹配保留各自的本地端点，回环连接双方的 PID 可同时显示。如果同一本地端点在同一流内出现不同的 PID，列表撤销此前的推断，恢复并保留逐帧匹配。详情树使受影响的缓存失效，引用进程字段的显示过滤从需要重新评估的行继续处理。

本机发出初始 SYN、源端点尚未关联 PID 时，抓包线程会唤醒快照线程，多次请求可合并，刷新之间至少留 100 ms。快照读取前已经关闭的套接字及入站短连接仍可能漏标。如果流的最后一帧也早于可用快照，列表没有可用的匹配来回填。UDP 只保留逐帧匹配。后续可用 ETW 连接事件补充快照采样。 [Windows ETW TCP/IP 事件](https://learn.microsoft.com/en-us/windows/win32/etw/tcpip)

#### WLAN 真实网络验收（2026-11-21）

在 WLAN 网卡上以 `tcp` 为抓包过滤，用 Edge 访问多个 HTTPS 站点及 `http://neverssl.com`。共捕获 9,122 帧，丢弃 0 帧。实时应用 `proc.name == "msedge.exe" && tls.handshake.type == 1` 后显示 81 帧，命中帧均带 `msedge.exe` 标签。截图可见 `ntp.msn.cn`、`cn.bing.com` 等由 TCP 重组取得的 SNI。离线抓包还确认有 `www.bilibili.com`、`www.baidu.com` 和 `www.zhihu.com` 的 ClientHello。 [进程与 SNI 联合过滤截图](images/phase4-wlan-proc-sni.png)

实时进程视图为 `msedge.exe (5112)` 列出 235 条 TCP 流。用 NetSniffer 的导入与显示过滤逻辑重开本地 `real_pcaps/phase4-wlan-proc-sni.pcap`，对照实时截图中的「已关联包数」。流 5 的关联包数和 `tcp.stream == 5` 的帧数均为 511，流 6 的对应计数均为 140。两条流的初始 SYN 分别位于第 6、11 帧。进程标签为实时会话元数据，离线 pcap 复核的是流内总帧数。 [按进程查看 TCP 流截图](images/phase4-wlan-process-streams.png)

NeverSSL 的 TCP 流 291 完整还原了抓到的明文 HTTP 会话。双向 ASCII 视图分色显示 `GET /online`、301 重定向及 HTML 响应。离线按同一追踪逻辑复核得到 4,051 字节，序号无缺口，后续 `GET /online/` 和 200 HTML 响应完整。 [追踪 NeverSSL HTTP 流截图](images/phase4-wlan-follow-http.png)

第 730、880 帧分别在第 729、879 帧的 TLS 1.3 HelloRetryRequest 之后，由客户端在兼容性 CCS 后重发 ClientHello。两帧均正确命中 ClientHello 过滤，帧内也能解析 SNI，Info 却只显示 `Change Cipher Spec`。离线共命中 87 帧 ClientHello，其中 76 帧的 SNI 来自 TCP 重组，10 帧从帧内直接取得 SNI，另外 1 帧未取得可过滤的 SNI。

## 阶段 5 · 统计与可视化

### TCP 时序图

轻解析从现有 TCP 报头额外读取 ACK 号和原始窗口，从已计算的偏移得出捕获负载长度，与详情树 `tcp.len` 的口径一致。后台对抓包快照按流号汇总，使用轻解析的方向、标志和序号，图内保留原始帧号和相对该流首个有效时间戳的时间。首个初始 SYN 的发送端为 A；未捕获初始 SYN 时以首包源端为 A，标注「无握手」。每个方向使用该方向首个带 SYN 标志的序号作为基准；无 SYN 的方向用该方向首包的序号。ACK 以对端的基准计算，ACK 标志或对端基准缺失时显示 `—`。序号按 32 位无符号取模。

握手和挥手用确认范围校验阶段，SYN、FIN 各占用一个序号，带数据的 FIN 再加捕获的负载长度。合并 FIN 和对端 FIN 的确认时标注三次挥手，RST 单独标注并清除未完成的阶段。图以固定行距按捕获顺序布局，便于读出时间接近的包。长流最多绘制前 5,000 帧，每 100 帧一页，PNG 导出当前整页。点击箭头返回原始捕获帧；如果显示过滤隐藏了目标，清除过滤并提示；实时抓包时暂停自动滚动以保持定位。时序图使用打开窗口时的捕获快照。

`samples/tcp_flow_graph.pcap` 有完整的 HTTP 握手与挥手、RST 中断流及无握手流。Windows Qt 窗口验收中，流 0 第 1–3 帧标注三次握手，第 7–10 帧标注四次挥手。已验证统计菜单、包列表右键、Follow Stream 三个入口，以及未过滤、保留当前流过滤和目标被过滤隐藏时的跳转。 [合成样例截图](images/phase5-flowgraph-sample.png)

WLAN 实抓截图中，TCP 流 87 共 9 帧，显示三次握手、双向 HTTP 数据、完整四次挥手和 `svchost.exe` 进程标签。第 4182 帧的 ACK 确认第 4166 帧的 FIN，完成四次挥手。 [WLAN 实抓截图](images/phase5-flowgraph-wlan.png)

#### TCP 摘要字段的回环复测

在同一台 Windows 机器上，以阶段 4 末尾 `a240f22` 对比补充三个 TCP 摘要字段后的代码。用 Npcap 回环抓包和正常主窗口列表，Qt 以离屏方式运行，每档定速发送 4 秒。发包进程独立于界面进程，界面用 30 ms Qt 计时器记录实际最大间隔。UDP 档复用历史测试方法。另加 TCP 单向 60 字节负载档，BPF 只留发往测试端口的含数据帧，以覆盖新增字段读取路径。

| 流量与目标速率 | 实测发送速率（前 → 后） | 显示帧数（前 → 后） | 丢弃（前 → 后） | Qt 心跳最大间隔（前 → 后） |
|---|---:|---:|---:|---:|
| UDP · 1,000 包/秒 | 1,000.2 → 1,000.2 | 4,000 → 4,000 | 0 → 0 | 40.0 → 64.7 ms |
| UDP · 4,000 包/秒 | 4,000.2 → 4,000.2 | 16,000 → 16,000 | 0 → 0 | 61.1 → 52.2 ms |
| UDP · 7,500 包/秒 | 7,500.2 → 7,500.2 | 30,000 → 30,000 | 0 → 0 | 69.2 → 61.8 ms |
| TCP · 7,500 包/秒 | 7,500.2 → 7,500.2 | 30,000 → 30,000 | 0 → 0 | 67.8 → 65.9 ms |

最高测试档仍约 7,500 包/秒且无丢包，未测更高档。历史 47 ms 的心跳值在本次改前 UDP 最高档也未复现。UDP 低档的单次最大间隔波动较大，该档没有执行 TCP 新增字段的读取。保留三个字段的轻量读取，复用已有偏移计算长度，并把整个流的汇总交给后台线程。

## 范围取舍

- 阶段 5 交付时序图、协议层级、会话和端点统计。IO Graph、DNS / HTTP 请求汇总表的额外评分和演示收益有限，本轮取消。
- 阶段 6 保留专家信息及原有三类安全告警。DNS 多应答难以用统一口径区分正常行为与异常，HTTPS 解密覆盖的握手与密钥日志组合较多，容易反复返工。DNS 多应答告警、HTTPS 解密实现和首选项本轮取消。报告结合 Thor 思考题说明 HTTPS 解密原理。Lua 插件暂缓，阶段 6 完成后若有余力优先补回。
- Info 列精简、`example.com` 第 8 号包误标、显示过滤性能、TShark 对照真实抓包转入报告「不足与改进方向」。前三项可能改动解析或过滤核心，回归面较广。真实抓包对照还要核对抓包条件与脱敏范围，阶段验收继续用合成样例。
- 为 11 月 24 日 23:55 截止前的打包、报告和视频留出时间，优先完成阶段 7 的交付物。

### 对照《实验 1A & 1B 讲解》后的调整

- 课件强调 TCP 时序图，阶段 5 以三次握手与四次挥手的时序图验收作为 `v0.8` 的发布条件。课件未列出协议层级、会话和端点统计，三项改为选做。优先顺序为协议层级 → 会话 → 端点，时间不足时先砍端点。
- 课件明确写明基于 Wireshark 做良好的二次开发可加分。Lua 插件由暂缓改为必做，阶段 6 先做三类安全告警与专家信息（至少 TCP 重传、RST），再做 Lua。插件在 Wireshark 中增加“应用识别”字段和列，规则与 `sniffer/dissect/app_detect.py` 对应，报告附安装方法和效果截图。告警、专家信息和 Lua 均完成后打 `v0.9`。
- 课件要求在代码中实现对 libpcap/Npcap 的调用。报告抓包层补充实际调用链，说明网卡枚举与打开经过 Scapy 的接口封装，BPF 编译与设置、读包和丢包统计由项目调用 `scapy.libs.winpcapy` 提供的 ctypes 绑定。报告新增“问题排查与最佳实践”，按现象、排查、方案对比、结论整理案例并总结验证方法。

## 阶段 6 · 安全告警与专家信息

- ARP 规则比较请求和应答中的发送方 IPv4/MAC 声明，忽略 `0.0.0.0` 探测，免费 ARP 改写既有映射提升为高严重程度。映射变化也可能来自合法的地址重分配或设备切换，告警提供新旧帧用于人工确认。
- SYN 规则按源、目标主机分别计算 10 秒内的不同目的端口，阈值为 15。按反向四元组匹配响应，有 ACK 的响应还须确认原 SYN。SYN/ACK 表示开放，RST 表示关闭，无响应在表中归为过滤。捕获缺包或在响应到达前停止也会产生无响应，结果只代表当前快照。50 条连向不同主机的正常 HTTPS 握手均无扫描告警。
- HTTP Basic 优先使用既有 TCP 重组附加的完整头部，帧内完整时用轻解析给出的负载范围。表单从已知长度和消息体起点收集连续的已捕获字节，最多 16 KiB。缺少边界、分块编码和头部补齐时无法定位消息体起点的场景留作边界问题。FTP 只检查 TCP 21 的客户端命令。告警保留用户名和打码后的密码首字符，打开原始帧仍会看到捕获内容。
- 专家信息依赖 TCP 摘要，按四元组和方向维护已见序号区间。整段落在已见区间才标记重传，补齐缺口的段不标成重传。重传、零窗口、RST 为 Warning，重复 ACK 为 Note。独立乱序分类暂缓，需区分迟到、遗漏及捕获顺序变化。`alert.type`、`expert.message` 延后，接入需要为显示过滤维护快照分析结果与捕获变化的一致性。
- 安全告警和专家信息均在打开对话框后读取快照并在后台分析。安全告警可手动刷新快照。两窗都复用时序图的原始帧号跳转、隐藏目标时清除过滤，以及实时抓包时暂停自动滚动的逻辑。

### 验收与耗时

`security_demo.pcap` 的 60 帧产生 5 条告警。ARP 映射冲突 1 条，SYN 扫描 1 条（开放端口 10003、10014，关闭 18），明文凭据 3 条（HTTP Basic、HTTP 表单、FTP，密码均打码）。`tcp_retransmission.pcap` 的第 5 帧可从专家信息跳转。另用 `expert_events.pcap` 验证四类专家条目。原有 pcap 的字节内容保持一致。Windows 窗口已验证刷新、双击跳转和隐藏目标时清除过滤。131 项 pytest 通过，其中新增 19 项，既有 11 项合成 TShark 对照一致。 [安全告警截图](images/phase6-alerts-demo.png) · [专家信息截图](images/phase6-expert.png)

Windows 下导入后分别分析三次，表中为纯分析耗时中位数，文件读取、TCP 重组和 Qt 绘制另计。10 万帧文件在仓库外由 `security_demo.pcap` 和 `expert_events.pcap` 循环组成，相邻帧间隔 10 ms。

| 抓包 | 帧数 | 安全告警 | 专家信息 |
|---|---:|---:|---:|
| WLAN `phase4-wlan-proc-sni.pcap` | 9,122 | 5.4 ms | 13.0 ms |
| 合成 `phase6-benchmark-100k.pcap` | 100,000 | 324.0 ms | 148.0 ms |

WLAN 离线复查中，ARP、SYN 扫描、明文凭据告警各 0 条，扫描规则在该样本无误报。这份抓包使用 `tcp` 抓包过滤，含 0 个 ARP 帧，无法验证真实 ARP 误报率。代理状态以当时的捕获环境为准，无法从离线文件独立核对。专家信息为重传 473 条、重复 ACK 113 条、零窗口 0 条、RST 54 条。

### TCP 保活对照

负载为 0 或 1 字节、序号等于本方向已见下一序号减 1 且没有 SYN、FIN 或 RST 的段标记为「TCP 保活」（Note）。它不推进已发送区间。对端刚发过保活时，序号仍在本方向下一序号、确认号及非零窗口与本方向上一个 ACK 一致的纯 ACK 视为保活回应，从重复 ACK 排除。保活回应不单独出现在专家信息面板。11 帧合成复现中，两边均检出 3 个保活，重传和重复 ACK 均为 0。TShark 另外报告 3 个保活 ACK。 [Wireshark TCP 分析规则](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)

`phase4-wlan-proc-sni.pcap` 共 9,122 帧。以下 TShark 数字使用本机 4.4.5 和表内显示过滤式对每个类别单独计数。

| 类别 | NetSniffer | TShark 4.4.5 | TShark 过滤式 |
|---|---:|---:|---|
| 重传（含快速重传） | 454 | 459 | `tcp.analysis.retransmission \|\| tcp.analysis.fast_retransmission` |
| 重复 ACK | 92 | 87 | `tcp.analysis.duplicate_ack` |
| 零窗口 | 0 | 0 | `tcp.analysis.zero_window` |
| RST | 54 | 54 | `tcp.flags.reset==1` |
| 保活 | 24 | 24 | `tcp.analysis.keep_alive` |

NetSniffer 重传要求整段序号已被捕获，Wireshark 依据预期序号及快速重传时序等规则分流，并将伪重传放入另一字段。NetSniffer 的重复 ACK 比较确认号和原始窗口，Wireshark 还检查已建立的序号状态，并考虑 SACK 和零窗口。以上是两套规则的口径差异，未对差异帧逐条调整。 [新版专家信息截图](images/phase6-expert.png)

### Wireshark Lua 应用识别

`wireshark_plugin/netsniffer_appid.lua` 在 Wireshark 4.4.5 以 postdissector 读取本帧 TCP/UDP 负载，按强内容特征、经内容校验的端口候选、弱 QUIC 长头特征依次判定。`netsniffer.app` 与 `netsniffer.basis` 给出应用和依据。`netsniffer.port_guess` 单独记录端口猜测。`netsniffer.mismatch=True` 表示已确认的协议与端口猜测不同。`netsniffer.unconfirmed=True` 表示有负载、有端口猜测且当前帧内容无法确认协议。空负载只保留端口猜测。8080 在两边的端口表内都映射为 HTTP，确认 HTTP 时与端口猜测一致。合成演示包第 1 帧把 HTTP 发往 TCP 443，内容判定 HTTP、端口猜测 TLS，因而不符。

执行 `python -m tools.compare_lua_appid`，用 TShark 4.4.5 对 `samples/` 全部 **17 个 pcap、214 帧**比较 `app` 和 `basis`，一致率为 **100%**，单帧口径无不一致帧。脚本另列 Python 流级结果。`tcp_reassembly.pcap` 的帧 5、10、15 分别补齐 TLS、HTTP 和 DNS，`plaintext_credentials.pcap` 的帧 5、10 及 `security_demo.pcap` 的帧 50、55 也涉及重组或沿用流级识别。这些是单帧插件与完整 NetSniffer 的范围差异。TLS 记录头可先识别应用，跨段 SNI、重组 HTTP 头部及 DNS 消息由 Python 重组路径提供。

#### 安装与演示

1. 在 Wireshark 4.4.5 打开「帮助 → 关于 Wireshark → 文件夹」，确认 `Personal Lua Plugins`。Windows 本机的个人目录是 `%APPDATA%\Wireshark\plugins`，与 `tshark -G folders` 输出一致。
2. 把 `netsniffer_appid.lua` 放入该目录，重启 Wireshark，打开合成样例。也可直接用 `tshark -X lua_script:wireshark_plugin/netsniffer_appid.lua` 做离线对照。
3. 选中有识别结果的帧，展开「NetSniffer 应用识别」，右键应用识别字段并选「应用为列」。用 `netsniffer.mismatch == 1` 查找已识别协议与端口猜测不同的帧。用 `netsniffer.unconfirmed == 1` 查找候选未确认的帧，`tcp_reassembly.pcap` 中的续段可演示后一种情况。
4. 打开「工具 → NetSniffer 应用识别统计」。Listener 对整份抓包分列统计「端口不符」和「未确认」。已识别及端口不符帧按已识别应用分组，未确认帧按端口猜测分组。 [Wireshark Lua 菜单与窗口 API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Gui.html) · [Listener API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Listener.html)

#### Wireshark 4.4.5 实机验收

`v0.9` 的合成演示抓包 `phase6-lua-demo.pcap` 在包列表显示 `netsniffer.app` 自定义列。第 1 帧的协议树显示应用为 HTTP、识别依据为内容特征、端口猜测为 TLS、端口不符为 `True`。工具菜单的统计窗口显示已识别 11 帧，端口不符 1 帧。HTTP 共 2 帧，其中 1 帧端口不符。 [自定义列和协议树](images/phase6-lua-column.png)

拆分口径后，TShark 4.4.5 对 WLAN `phase4-wlan-proc-sni.pcap` 的 9,122 帧统计得出 `netsniffer.mismatch == 1` 为 **0** 帧，`netsniffer.unconfirmed == 1` 为 **4,436** 帧。使用独立的 Wireshark 配置目录加载工作区 Lua，以避免已安装的 v0.9 插件参与统计。17 个合成样例的 `app` 和 `basis` 仍为 **214/214 帧一致**。`v0.9` 远端标签仍指向原验收提交 `3aaeeff`。

更新后的插件在新一轮 Wireshark WLAN 实抓中验证了两个字段和统计分列。整份抓包共 3,928 帧，已识别 1,045 帧，端口不符 0 帧，未确认 1,551 帧（39.5%）。加上 `tcp.port == 443` 后，未确认剩 1,525 帧，与统计窗口的 TLS 候选行一致。另 26 帧归入 QUIC 候选。 [新版 WLAN 统计窗口](images/phase6-lua-stats.png)

## 阶段 7 · Windows 单文件打包

在仓库根目录激活 `netsniffer` 环境后构建。实测使用 Python 3.12.16 和 PyInstaller 6.22.3。

```powershell
python -m PyInstaller --noconfirm --clean packaging/netsniffer.spec
```

本轮 ICU 修复版的 `dist/NetSniffer.exe` 为 46,900,144 字节（44.73 MiB）。构建启用单文件、图标、Windows GUI 子系统与 `requireAdministrator` 清单，关闭 UPX。检查了包内的 Scapy Windows/libpcap 加载模块和 Qt `qwindows.dll`，并确认未收录 Npcap DLL 或驱动。Qt 的虚拟键盘插件会引入 QtQuick 和 QtQml，规格文件排除了这些组件。运行时由目标机器单独安装 Npcap。此轮全量 `pytest` 通过 134 项。

静态依赖复核确认 EXE 自带 Python 3.12 运行时、标准库、PySide6、Scapy 和全部 55 个项目模块。旧构建仅检查 DLL 名称时通过，但实机导入 `QtWidgets` 报“找不到指定的程序”。对比入口点后发现，依赖分析从开发工具的 Poppler 目录收录了同名 `icuuc.dll`。它仅导出了带版本后缀的部分 ICU 入口，而 Qt 需要 Windows 自带的无后缀入口。规格文件将构建进程的 DLL 搜索范围限制在 Windows 和当前 Python 环境，并排除 Windows 自带的 ICU DLL。重建后核对 Qt、ICU 和 C++ 运行时入口点通过。

GUI 子系统启动时没有控制台。启动入口为未捕获异常安装全局钩子，把异常堆栈追加到 `%LOCALAPPDATA%\NetSniffer\crash.log`，并通过 Windows 对话框提示日志路径。

干净系统使用 VirtualBox 7.2.4 的 2 vCPU、4 GiB 内存虚拟机，安装 Windows 11 Enterprise LTSC Evaluation（x64，安装镜像版本 26100.1742）。已准备 Npcap 1.90 安装程序和合成样例。冷启动实测与两端冒烟检查待补录。

虚拟机从安装 ISO 成功引导，安装界面达到 75% 后出现持续黑屏。VirtualBox 日志显示宿主使用 Hyper-V 后端，并多次报告虚拟机计时追赶失败。按范围调整，暂停虚拟机配置，改做本机的环境独立性测试。Windows 沙盒场景未测，包括未装 Npcap 时的提示和安装后抓包。

### 环境独立性复测

在从临时管理员 CMD 启动的进程中，`PATH` 只保留 `System32`、`Windows`、`Wbem`，清空 `PYTHONPATH`、`PYTHONHOME`、`QT_PLUGIN_PATH`、`QT_QPA_PLATFORM_PLUGIN_PATH` 和 `CONDA_PREFIX`。系统和用户环境变量未修改。修复版从启动子进程到首次检测到主窗口耗时 2,003 ms，包含单文件解压，未计入 UAC 等待。欢迎页正常显示网卡和流量曲线。

管理员 PowerShell 模块筛选输出如下，去除表格行尾空格。`MpOav.dll` 来自 Microsoft Defender 的反恶意软件平台。结果没有 Conda、`envs` 或外置 Python 目录。

```text
FileName
--------
E:\课程\软件安全与网络\netsniffer\dist\NetSniffer.exe
C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpOav.dll
```

用户随后在同一隔离启动的 EXE 中完成界面操作并提交验收截图。`security_demo.pcap` 的安全告警共 5 条，SYN 扫描警告列出开放端口 10003、10014，三条凭据告警均已打码。显示过滤 `tcp.flags.syn && !tcp.flags.ack` 在 60 帧中命中 23 帧。`tcp_http.pcap` 的追踪窗口可看到 HTTP 请求、`200 OK` 响应及正文，时序图显示 6 帧并标注三次握手。`expert_events.pcap` 分别显示重传、零窗口、RST 和重复 ACK。 [隔离环境下的安全告警截图](images/phase7-exe-clean.png)

旧版 WLAN 抓包截图显示接收 2,627 帧、丢弃 0 帧，所选进程关联 23 条 TCP 流。BPF 输入显示有效，但同一截图仍含 SSDP 1900 流量，无法据此确认当时的抓包句柄使用了 443 端口过滤。该版本的「重新开始」会复用上一轮抓包参数。

### 重新开始与 BPF

修复前「重新开始」复用了上一轮 BPF。修复后点击时读取当前输入，用上一次抓包的网卡异步编译。编译通过后才替换会话，编译失败会在状态栏提示并保留正在进行的抓包。状态栏常驻显示实际生效的表达式，无活跃过滤时显示「无」。Npcap 在新会话的抓包句柄上安装 BPF 成功后才更新该状态及替换包列表。回归测试覆盖抓包中使用新表达式重新开始，以及运行中和已停止时拒绝无效表达式。

用源码界面驱动 Npcap 实抓本机回环。无过滤时捕获到自发的 UDP，提交无效 BPF 时原会话继续。随后以 `tcp port 443` 重新开始，同时发出测试 UDP 和 TCP 流量。新会话得到 9 帧，状态栏显示实际表达式。用界面导出 PCAPNG，TShark 4.4.5 重读为 9 帧，`!(tcp.port == 443)` 命中 0 帧。

新版 EXE 的 WLAN 实抓共 450 帧，NetSniffer 显示丢弃 0。用 EXE 先后导出 `real.pcap` 和 `real.pcapng`，两份文件均在 Wireshark 4.4.5 中重读为 450 帧，与 NetSniffer 一致。`capinfos` 确认实际文件格式分别为纳秒精度 PCAP 和 PCAPNG。TShark 对两份文件分别执行 `!(tcp.port == 443)`，均命中 0 帧。已提供的 NetSniffer 截图拍在停止后，状态栏显示「抓包过滤：无」。显示实际过滤器的抓包进行中截图待补录。真实抓包文件留在本地测试目录。

### 阶段 5 统计窗口补齐

在功能冻结前按协议层级、会话、端点、IO 图表顺序补齐。各窗口对显示范围的快照后台统计，保留原始帧号和整份抓包的时间原点。字节数使用线路上的原始帧长。会话 A 取快照首次观察到的源端，TShark 对照时统一双向端点顺序。应用层标签取单帧摘要，IO 按左闭右开区间分桶，无时间戳的帧不进入 IO 分桶，空桶隐含为零。

在 TShark 4.4.5 上执行 `python -m tools.compare_stats_tshark --benchmark ../phase6-benchmark-100k.pcap`。对照使用空的个人配置目录，避免 Lua 后置解析器影响协议树。性能样例为阶段 6 的 100,000 帧合成文件，读入后只计统计耗时，五次取中位数。

| 统计 | TShark 完全一致的样例 | 100,000 帧耗时 |
| --- | --- | ---: |
| 协议层级 | `io,phs` 9/17 | 134.8 ms |
| 会话 | `conv,ip`、`conv,ipv6`、`conv,tcp`、`conv,udp` 各 17/17 | 140.6 ms |
| 端点 | `endpoints,ip`、`endpoints,tcp`、`endpoints,udp` 各 17/17 | 127.7 ms |
| IO 图表 | `io,stat,1` 17/17 | 65.9 ms |

协议层级的 Frame、链路、网络和传输层帧数及字节数一致。8 份样例的差异来自应用识别及 Wireshark 的额外子层。例如，非标准端口的 SSH 横幅在 NetSniffer 归为 SSH，TShark 默认归为 TCP 数据。ARP 冲突帧在 TShark 带 `text` 节点。HTTP 重传、跨段 HTTP/TLS/DNS、FTP 及表单子层采用各自的识别与重组口径。对照脚本逐条列出差异。[协议层级](images/phase5-stats-hierarchy.png) · [会话](images/phase5-stats-conversations.png) · [端点](images/phase5-stats-endpoints.png) · [IO 图表](images/phase5-stats-iograph.png)

按原命令重建包含四项统计的单文件 EXE，大小 62,802,814 字节（59.89 MiB），SHA-256 为 `E5A5F6219120B4A79AC9BE80EB049B7A2E505A4740E96F83A5DFD843A5267999`。包内已核对 pyqtgraph、NumPy、Scapy 和 Qt Windows 平台插件，仍由系统提供 Npcap 与 ICU。清空进程环境变量后首次出现主窗口耗时 2,231 ms，排除 UAC 等待。外部模块列表与上一版相同。全量 `pytest` 通过 144 项。四个统计窗口的截图由原生 Windows Qt 平台打开 `security_demo.pcap` 获得。源码交互复测中，四个窗口均对显示过滤剩下的 23 帧统计，IO 标记、时序图箭头和专家条目均可定位到原始帧。打包版全量交互冒烟尚待复验。
