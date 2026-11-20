from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem

from sniffer.dissect.field import Field

PROTOCOL_LAYERS = frozenset({
    "eth", "vlan", "null", "arp", "ip", "ipv6", "icmp", "icmpv6", "tcp", "udp",
    "application", "dns", "dns.tcp", "mdns", "http", "tls", "dhcp", "ssdp", "ntp", "ssh", "quic",
})


class DetailTree(QTreeWidget):
    field_selected = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setUniformRowHeights(True)
        self.setAlternatingRowColors(True)
        self.setIndentation(16)
        self._tree: Field | None = None
        self._items: dict[int, QTreeWidgetItem] = {}
        self.currentItemChanged.connect(self._selection_changed)
        self.show_message("选择一个包以查看协议字段。")

    def show_message(self, message: str) -> None:
        self.clear()
        self._tree = None
        self._items.clear()
        item = QTreeWidgetItem(self, [message])
        item.setFlags(Qt.ItemFlag.ItemIsEnabled)

    def show_fields(self, tree: Field) -> None:
        self.clear()
        self._items.clear()
        self._tree = tree
        stack = [tree]
        while stack:
            layer = stack.pop()
            item = self._add_item(self, layer)
            nested_layers = []
            for child in layer.children:
                if child.name in PROTOCOL_LAYERS:
                    nested_layers.append(child)
                else:
                    self._add_field(item, child)
            stack.extend(reversed(nested_layers))
            # 显示应用标题及一级字段，链路到传输层按需展开。
            if layer.name in ("application", "http", "ssdp"):
                item.setExpanded(True)

    def _add_item(self, parent, field: Field) -> QTreeWidgetItem:
        item = QTreeWidgetItem(parent, [field.show])
        item.setData(0, Qt.ItemDataRole.UserRole, field)
        item.setToolTip(0, f"{field.name} · 字节 {field.offset}–{field.end - 1}" if field.length else field.name)
        self._items[id(field)] = item
        return item

    def _add_field(self, parent: QTreeWidgetItem, field: Field) -> None:
        item = self._add_item(parent, field)
        for child in field.children:
            self._add_field(item, child)

    def select_byte(self, offset: int) -> None:
        if self._tree is None:
            return
        field = self._tree.at_byte(offset)
        if field is None:
            return
        item = self._items[id(field)]
        ancestor = item.parent()
        while ancestor is not None:
            ancestor.setExpanded(True)
            ancestor = ancestor.parent()
        self.setCurrentItem(item)
        self.scrollToItem(item)

    def _selection_changed(self, current, _previous) -> None:
        field = current.data(0, Qt.ItemDataRole.UserRole) if current is not None else None
        self.field_selected.emit(field)
