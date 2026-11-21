from ctypes import POINTER, byref, c_ubyte, create_string_buffer, string_at
from dataclasses import dataclass, replace
from decimal import Decimal
from queue import Empty, Full, Queue
from threading import Event, Lock, Thread

from scapy.all import conf
from scapy.error import Scapy_Exception
from scapy.utils import decode_locale_str

from sniffer.analysis.process_map import ProcessMapper
from sniffer.analysis.tcp import ACK, SYN
from sniffer.analysis.tcp_application import TcpApplicationTracker
from sniffer.capture.bpf import install_capture_filter
from sniffer.model.packet import PacketRecord

IDLE_WAIT_SECONDS = 0.01


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
        self._tcp_applications = TcpApplicationTracker()
        self._process_map = ProcessMapper()

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

    def _receive(self, header, data, linktype: int) -> None:
        # 队列满时先跳过解析，避免让抓包线程在过载时做额外工作。
        discarded = self._queue.full()
        if not discarded:
            # Npcap 会复用接收缓冲区，帧字节必须在下次读取前复制出来。
            raw = string_at(data, header.caplen)
            timestamp = Decimal(header.ts.tv_sec) + Decimal(header.ts.tv_usec).scaleb(-6)
            record = PacketRecord.from_bytes(timestamp, raw, linktype, header.len)
            flow = record.summary.flow
            if flow is not None:
                segment = record.summary.tcp
                initial_syn = segment is not None and segment.flags & (SYN | ACK) == SYN
                matches = self._process_map.match(flow, initial_syn=initial_syn)
                if matches:
                    record = replace(record, processes=matches)
            try:
                self._queue.put_nowait(self._tcp_applications.process(record))
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
                Thread(target=self._process_map.run, args=(self._stop,), name="NetSniffer process map", daemon=True).start()
                self._capture(listener)
        except (OSError, Scapy_Exception, ValueError) as error:
            self.error = str(error)
        except Exception as error:
            self.error = f"{type(error).__name__}: {error}"
        finally:
            self._stop.set()
            self.done.set()

    def _capture(self, listener) -> None:
        from scapy.libs.winpcapy import (
            PCAP_ERRBUF_SIZE, pcap_geterr, pcap_next_ex, pcap_pkthdr, pcap_setnonblock,
        )

        handle = listener.pcap_fd.pcap
        linktype = listener.pcap_fd.datalink()
        install_capture_filter(handle, self.settings.expression)
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        if pcap_setnonblock(handle, 1, errbuf) != 0:
            raise OSError(f"无法设置 Npcap 非阻塞模式。{decode_locale_str(errbuf.value)}")

        header = POINTER(pcap_pkthdr)()
        data = POINTER(c_ubyte)()
        header_ptr, data_ptr = byref(header), byref(data)
        self.ready.set()
        try:
            while not self._stop.is_set():
                result = pcap_next_ex(handle, header_ptr, data_ptr)
                if result == 1:
                    self._receive(header.contents, data, linktype)
                elif result == 0:
                    self._stop.wait(IDLE_WAIT_SECONDS)
                else:
                    raise OSError(f"读取 Npcap 帧失败。{decode_locale_str(pcap_geterr(handle) or b'')}")
        finally:
            self._read_driver_drops(handle)

    def _read_driver_drops(self, handle) -> None:
        from scapy.libs.winpcapy import pcap_stat, pcap_stats

        stats = pcap_stat()
        if pcap_stats(handle, byref(stats)) == 0:
            with self._lock:
                self._driver_drops = stats.ps_drop
