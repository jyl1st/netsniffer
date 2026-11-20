from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox, QColorDialog, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout,
    QPushButton, QVBoxLayout, QWidget,
)

DEFAULT_COLORS = {
    "TCP": "#eaf2fc",
    "UDP": "#f2ecfc",
    "DNS": "#e5f5f8",
    "HTTP": "#e5f4e8",
    "TLS": "#ecedff",
    "ARP": "#fff1d6",
    "ICMP": "#e4f4ed",
    "错误包": "#ffdadf",
}


def readable_text(background: QColor) -> QColor:
    brightness = (299 * background.red() + 587 * background.green() + 114 * background.blue()) / 1000
    return QColor("#171b22" if brightness >= 145 else "#ffffff")


class PacketColorsDialog(QDialog):
    def __init__(self, colors: dict[str, str | None], parent=None):
        super().__init__(parent)
        self.setWindowTitle("数据包着色规则")
        self._checks: dict[str, QCheckBox] = {}
        self._buttons: dict[str, QPushButton] = {}
        self._swatches: dict[str, str] = {}
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setHorizontalSpacing(20)
        layout.addLayout(form)
        for name, default in DEFAULT_COLORS.items():
            line = QWidget()
            controls = QHBoxLayout(line)
            controls.setContentsMargins(0, 0, 0, 0)
            check = QCheckBox("启用")
            check.setChecked(colors.get(name) is not None)
            button = QPushButton()
            button.setMinimumWidth(100)
            button.setEnabled(check.isChecked())
            self._checks[name] = check
            self._buttons[name] = button
            self._set_color(name, colors.get(name) or default)
            check.toggled.connect(button.setEnabled)
            button.clicked.connect(lambda _checked=False, rule=name: self._choose_color(rule))
            controls.addWidget(check)
            controls.addWidget(button)
            form.addRow(name, line)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        reset = buttons.addButton("恢复默认", QDialogButtonBox.ButtonRole.ResetRole)
        reset.clicked.connect(self._reset)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def colors(self) -> dict[str, str | None]:
        return {name: self._swatches[name] if checkbox.isChecked() else None for name, checkbox in self._checks.items()}

    def _choose_color(self, name: str) -> None:
        new_color = QColorDialog.getColor(QColor(self._swatches[name]), self, f"{name} 行背景")
        if new_color.isValid():
            self._set_color(name, new_color.name())

    def _set_color(self, name: str, value: str) -> None:
        self._swatches[name] = value
        button = self._buttons[name]
        button.setText(value.upper())
        text = readable_text(QColor(value)).name()
        button.setStyleSheet(f"QPushButton {{ background-color: {value}; color: {text}; }}")

    def _reset(self) -> None:
        for name, value in DEFAULT_COLORS.items():
            self._checks[name].setChecked(True)
            self._set_color(name, value)
