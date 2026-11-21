from dataclasses import dataclass
from typing import Literal

TransportProtocol = Literal["tcp", "udp"]
Endpoint = tuple[bytes, int]


@dataclass(frozen=True, slots=True)
class TransportFlow:
    protocol: TransportProtocol
    source: Endpoint
    destination: Endpoint

    @property
    def endpoints(self) -> tuple[Endpoint, Endpoint]:
        # 地址和端口成对排序，使回包复用同一索引键。
        if self.source > self.destination:
            return self.destination, self.source
        return self.source, self.destination


class StreamIndex:
    """按入库顺序为一次抓包分配 TCP 和 UDP 流编号。"""

    def __init__(self):
        self._numbers: dict[TransportProtocol, dict[tuple[Endpoint, Endpoint], int]] = {
            "tcp": {}, "udp": {},
        }

    def number(self, flow: TransportFlow) -> int:
        numbers = self._numbers[flow.protocol]
        return numbers.setdefault(flow.endpoints, len(numbers))
