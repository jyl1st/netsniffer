from ctypes import byref
from dataclasses import dataclass
from decimal import Decimal
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread

from scapy.all import AsyncSniffer, conf
from scapy.error import Scapy_Exception

from sniffer.model.packet import PacketRecord

FILTER_PRESETS = ("tcp port 443", "tcp", "udp", "port 53", "ip", "ip6", "icmp or icmp6", "arp")


@dataclass(frozen=True, slots=True)
class CaptureSettings:
    device: str
    expression: str = ""
    promiscuous: bool = False


class CaptureSession:
    def __init__(self, settings: CaptureSettings):
        self.settings = settings
        self.ready = Event()
        self.done = Event()
        self._stop = Event()
        self._lock = Lock()
        self._received = 0
        self._discarded = 0
        self._driver_drops = 0
        self.error: str | None = None
        self._queue: Queue[PacketRecord] = Queue(maxsize=4096)

    def start(self) -> None:
        Thread(target=self._run, name="NetSniffer capture", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()

    def drain(self, limit: int = 1000) -> list[PacketRecord]:
        packets = []
        for _ in range(limit):
            try:
                packets.append(self._queue.get_nowait())
            except Empty:
                break
        return packets

    def counts(self) -> tuple[int, int]:
        with self._lock:
            return self._received, self._discarded + self._driver_drops

    def _receive(self, packet, linktype: int) -> None:
        # 队列满时先跳过解析，避免让抓包线程在过载时做额外工作。
        discarded = self._queue.full()
        if not discarded:
            raw = packet.original
            record = PacketRecord.from_bytes(
                Decimal(str(packet.time)), raw, linktype, packet.wirelen or len(raw)
            )
            try:
                self._queue.put_nowait(record)
            except Full:
                discarded = True
        with self._lock:
            self._received += 1
            self._discarded += discarded

    def _run(self) -> None:
        try:
            if not conf.use_pcap:
                raise OSError("Npcap 不可用。请安装 Npcap 后重新启动。")
            # 句柄由此线程拥有，启动失败和正常停止都由上下文管理器释放。
            with conf.L2listen(iface=self.settings.device, promisc=self.settings.promiscuous) as listener:
                self._capture(listener)
        except (OSError, Scapy_Exception, ValueError) as error:
            self.error = str(error)
        except Exception as error:
            self.error = f"{type(error).__name__}: {error}"
        finally:
            self.done.set()

    def _capture(self, listener) -> None:
        pcap = listener.pcap_fd
        linktype = pcap.datalink()
        expression = self.settings.expression.strip()
        if "\x00" in expression:
            raise ValueError("BPF 表达式含有空字符。")
        if expression:
            try:
                pcap.setfilter(expression)
            except Scapy_Exception as error:
                raise ValueError(f"BPF 编译或安装失败。{error}") from error
        if self._stop.is_set():
            return
        sniffer = AsyncSniffer(
            opened_socket=listener,
            store=False,
            prn=lambda packet: self._receive(packet, linktype),
            started_callback=self.ready.set,
        )
        sniffer.start()
        # stop_cb 在 started_callback 前才创建，提前调用 stop 会触发 Scapy 的启动竞态。
        while sniffer.thread.is_alive():
            if self._stop.is_set() and self.ready.wait(0.05):
                if sniffer.running:
                    try:
                        sniffer.stop(join=False)
                    except Scapy_Exception:
                        if sniffer.running:
                            raise
                break
            sniffer.thread.join(0.05)
        sniffer.join()
        if not self._stop.is_set():
            raise OSError("网卡停止返回数据，抓包已结束。")
        if not listener.closed:
            self._read_driver_drops(pcap)

    def _read_driver_drops(self, pcap) -> None:
        from scapy.libs.winpcapy import pcap_stat, pcap_stats

        stats = pcap_stat()
        if pcap_stats(pcap.pcap, byref(stats)) == 0:
            with self._lock:
                self._driver_drops = stats.ps_drop
