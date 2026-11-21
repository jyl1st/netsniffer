import sys
from pathlib import Path

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPalette
from PySide6.QtWidgets import QApplication, QLabel, QStyle, QStyledItemDelegate, QStyleOptionViewItem

APP_VERSION = "v1.0"
ACCENT = "#007a78"
INK = "#183133"


def resource_path(relative: str) -> Path:
    root = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parents[2]))
    return root / relative


def toolbar_icon(name: str) -> QIcon:
    return QIcon(str(resource_path(f"sniffer/gui/icons/{name}.svg")))


def apply_theme(app: QApplication) -> None:
    app.setStyle("Fusion")
    font = QFont()
    font.setFamilies(["Microsoft YaHei UI", "Segoe UI"])
    font.setPointSizeF(9.5)
    app.setFont(font)

    palette = app.palette()
    for role, color in {
        QPalette.ColorRole.Window: "#f3f7f7",
        QPalette.ColorRole.WindowText: INK,
        QPalette.ColorRole.Base: "#ffffff",
        QPalette.ColorRole.AlternateBase: "#f5f9f9",
        QPalette.ColorRole.Text: INK,
        QPalette.ColorRole.Button: "#ffffff",
        QPalette.ColorRole.ButtonText: INK,
        QPalette.ColorRole.PlaceholderText: "#697e80",
        QPalette.ColorRole.Highlight: ACCENT,
        QPalette.ColorRole.HighlightedText: "#ffffff",
        QPalette.ColorRole.Link: ACCENT,
    }.items():
        palette.setColor(role, QColor(color))
    for role in (QPalette.ColorRole.WindowText, QPalette.ColorRole.Text, QPalette.ColorRole.ButtonText):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor("#859395"))
    app.setPalette(palette)
    app.setWindowIcon(QIcon(str(resource_path("packaging/netsniffer.ico"))))
    stylesheet = resource_path("sniffer/gui/theme.qss").read_text(encoding="utf-8")
    app.setStyleSheet(stylesheet.replace("@ICONS@", resource_path("sniffer/gui/icons").as_posix()))


class ElidedLabel(QLabel):
    def paintEvent(self, event) -> None:
        painter = QPainter(self)
        rect = self.contentsRect()
        text = self.fontMetrics().elidedText(self.text(), Qt.TextElideMode.ElideRight, rect.width())
        self.style().drawItemText(painter, rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                                  self.palette(), self.isEnabled(), text, QPalette.ColorRole.WindowText)


class BadgeDelegate(QStyledItemDelegate):
    def __init__(self, colors: dict[str, tuple[str, str]], parent=None):
        super().__init__(parent)
        self.colors = colors

    def sizeHint(self, option, index):
        size = super().sizeHint(option, index)
        size.setHeight(max(size.height(), option.fontMetrics.height() + 8))
        return size

    def paint(self, painter, option, index) -> None:
        item = QStyleOptionViewItem(option)
        self.initStyleOption(item, index)
        text = item.text
        color = self.colors.get(text.split(" ", 1)[0])
        if color is None:
            super().paint(painter, option, index)
            return
        item.text = ""
        style = item.widget.style() if item.widget is not None else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, item, painter, item.widget)
        metrics = item.fontMetrics
        width = min(item.rect.width() - 8, metrics.horizontalAdvance(text) + 16)
        height = min(item.rect.height() - 4, metrics.height() + 4)
        if width <= 0 or height <= 0:
            return
        pill = QRect(item.rect.left() + 4, item.rect.center().y() - height // 2, width, height)
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor(color[0]))
        painter.drawRoundedRect(pill, 5, 5)
        painter.setFont(item.font)
        painter.setPen(QColor(color[1]))
        visible = metrics.elidedText(text, Qt.TextElideMode.ElideRight, max(0, width - 8))
        painter.drawText(pill, Qt.AlignmentFlag.AlignCenter, visible)
        painter.restore()
