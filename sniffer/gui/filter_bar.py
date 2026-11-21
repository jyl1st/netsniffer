import json
import re

from PySide6.QtCore import QSettings, Qt, Signal
from PySide6.QtWidgets import QCompleter, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QToolButton, QWidget

from sniffer.dissect.field import FieldValue
from sniffer.filter.evaluator import FilterProgram, compile_filter
from sniffer.filter.fields import SUGGESTIONS, known_field
from sniffer.filter.lexer import MAX_EXPRESSION, FilterError

IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
TOKEN_LEFT = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*$")
TOKEN_RIGHT = re.compile(r"[A-Za-z0-9_.]*")
HISTORY_LIMIT = 20


def field_expression(name: str, value: FieldValue) -> str | None:
    if not IDENTIFIER.fullmatch(name) or not known_field(name):
        return None
    if value is None:
        return name
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    if isinstance(value, str):
        literal = json.dumps(value, ensure_ascii=False)
    elif isinstance(value, bool):
        literal = "true" if value else "false"
    else:
        literal = str(value)
    return f"{name} == {literal}"


class DisplayFilterBar(QWidget):
    submitted = Signal(object)

    def __init__(self, parent=None, *, settings: QSettings | None = None):
        super().__init__(parent)
        self._settings = settings if settings is not None else QSettings("NetSniffer", "NetSniffer")
        self._history = self._read_expressions("history")
        self._bookmarks = self._read_expressions("bookmarks")
        self._program: FilterProgram | None = None
        self._error: FilterError | None = None
        self._applied = ""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(7, 5, 7, 5)
        layout.setSpacing(6)

        title = QLabel("显示过滤")
        self.editor = QLineEdit()
        self.editor.setMaxLength(MAX_EXPRESSION)
        self.editor.setPlaceholderText('例如 tcp.flags.syn && !tcp.flags.ack')
        self.editor.setAccessibleName("显示过滤表达式")
        title.setBuddy(self.editor)
        layout.addWidget(title)
        layout.addWidget(self.editor, 1)

        self.validation = QLabel()
        self.validation.setMaximumWidth(250)
        layout.addWidget(self.validation)
        self._progress = QLabel()
        self._progress.hide()
        layout.addWidget(self._progress)
        self.apply_button = QPushButton("应用")
        self.clear_button = QPushButton("清除")
        layout.addWidget(self.apply_button)
        layout.addWidget(self.clear_button)
        layout.addWidget(self._menu_button("历史", self._history_menu))
        layout.addWidget(self._menu_button("书签", self._bookmark_menu))

        self._completion = QCompleter(list(SUGGESTIONS), self)
        self._completion.setWidget(self.editor)
        self._completion.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completion.setMaxVisibleItems(8)
        self._completion.activated[str].connect(self._complete)
        self.editor.textChanged.connect(self._validate)
        self.editor.textEdited.connect(self._suggest)
        self.editor.returnPressed.connect(self._submit_from_edit)
        self.apply_button.clicked.connect(self.apply)
        self.clear_button.clicked.connect(self.clear)
        self._validate("")

    @property
    def applied_text(self) -> str:
        return self._applied

    def _read_expressions(self, key: str) -> list[str]:
        values = self._settings.value(f"display_filter/{key}", [])
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, (tuple, list)):
            return []
        return list(dict.fromkeys(value for value in values if isinstance(value, str) and value.strip()))

    def _menu_button(self, label, populate):
        button = QToolButton()
        button.setText(label)
        menu = QMenu(button)
        menu.aboutToShow.connect(lambda: populate(menu))
        button.setMenu(menu)
        button.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        return button

    def _validate(self, text: str) -> None:
        try:
            self._program = compile_filter(text)
        except FilterError as error:
            self._program = None
            self._error = error
            message = f"第 {error.position + 1} 列 · {error}"
            self._feedback(message, "#bd3434")
        else:
            self._error = None
            self._feedback("有效" if self._program else "", "#27854b" if self._program else "")
        self.apply_button.setEnabled(self._error is None and (bool(text.strip()) or bool(self._applied)))
        self.clear_button.setEnabled(bool(text) or bool(self._applied))

    def _feedback(self, message: str, border: str) -> None:
        self.validation.setToolTip(message)
        self.validation.setText(self.validation.fontMetrics().elidedText(message, Qt.TextElideMode.ElideRight, 245))
        self.editor.setToolTip(message)
        self.editor.setAccessibleDescription(message)
        self.editor.setStyleSheet(f"QLineEdit {{ border: 1px solid {border}; }}" if border else "")

    def _submit_from_edit(self) -> None:
        if not self._completion.popup().isVisible():
            self.apply()

    def apply(self) -> None:
        if self._error is not None:
            self.editor.setCursorPosition(min(self._error.position, len(self.editor.text())))
            return
        expression = self.editor.text().strip()
        if expression:
            self._history = [expression] + [value for value in self._history if value != expression]
            self._history = self._history[:HISTORY_LIMIT]
            self._settings.setValue("display_filter/history", self._history)
        self._applied = expression
        self.apply_button.setEnabled(bool(expression))
        self.clear_button.setEnabled(bool(expression))
        self.submitted.emit(self._program)

    def clear(self) -> None:
        self.editor.clear()
        self.apply()

    def apply_expression(self, expression: str) -> None:
        self.editor.setText(expression)
        self.apply()

    def prepare_expression(self, expression: str) -> None:
        self.editor.setText(expression)
        self.editor.setFocus()

    def show_progress(self, evaluated: int, total: int) -> None:
        self._progress.setText(f"过滤中 {evaluated:,}/{total:,}" if evaluated < total else "")
        self._progress.setVisible(evaluated < total)

    def show_failure(self, message: str) -> None:
        self._applied = ""
        self._feedback(message, "#bd3434")

    def _history_menu(self, menu: QMenu) -> None:
        menu.clear()
        if not self._history:
            menu.addAction("暂无历史").setEnabled(False)
        for expression in self._history:
            menu.addAction(expression, lambda _checked=False, value=expression: self.apply_expression(value))

    def _bookmark_menu(self, menu: QMenu) -> None:
        menu.clear()
        add = menu.addAction("保存当前表达式", self._save_bookmark)
        add.setEnabled(bool(self._program))
        if self._bookmarks:
            menu.addSeparator()
            for expression in self._bookmarks:
                menu.addAction(expression, lambda _checked=False, value=expression: self.apply_expression(value))
            delete = menu.addMenu("移除书签")
            for expression in self._bookmarks:
                delete.addAction(expression, lambda _checked=False, value=expression: self._remove_bookmark(value))

    def _save_bookmark(self) -> None:
        if not self._program:
            return
        expression = self.editor.text().strip()
        if expression not in self._bookmarks:
            self._bookmarks.append(expression)
            self._settings.setValue("display_filter/bookmarks", self._bookmarks)

    def _remove_bookmark(self, expression: str) -> None:
        if expression in self._bookmarks:
            self._bookmarks.remove(expression)
            self._settings.setValue("display_filter/bookmarks", self._bookmarks)

    def _suggest(self, text: str) -> None:
        prefix = text[:self.editor.cursorPosition()]
        token = TOKEN_LEFT.search(prefix)
        if token is None or _inside_quotes(prefix):
            self._completion.popup().hide()
            return
        self._completion.setCompletionPrefix(token.group())
        if self._completion.completionCount() and not (
            self._completion.completionCount() == 1 and self._completion.currentCompletion() == token.group()
        ):
            self._completion.complete()
        else:
            self._completion.popup().hide()

    def _complete(self, name: str) -> None:
        text = self.editor.text()
        cursor = self.editor.cursorPosition()
        token = TOKEN_LEFT.search(text[:cursor])
        if token is not None:
            end = TOKEN_RIGHT.match(text, cursor).end()
            self.editor.setText(text[:token.start()] + name + text[end:])
            self.editor.setCursorPosition(token.start() + len(name))

    def field_menu(self, name: str, value: FieldValue, position) -> None:
        menu = QMenu(self)
        self.add_field_actions(menu, name, value)
        if not menu.isEmpty():
            menu.exec(position)
        menu.deleteLater()

    def add_field_actions(self, menu: QMenu, name: str, value: FieldValue) -> None:
        expression = field_expression(name, value)
        if expression is None:
            return
        for title, action, base in (
            ("作为过滤器应用", self.apply_expression, self._applied),
            ("准备过滤器", self.prepare_expression, self.editor.text().strip()),
        ):
            options = menu.addMenu(title)
            use_and = f"({base}) && ({expression})" if base else expression
            use_or = f"({base}) || ({expression})" if base else expression
            for label, result in (("选中", expression), ("非选中", f"!({expression})"), ("与", use_and), ("或", use_or)):
                options.addAction(label, lambda _checked=False, text=result, run=action: run(text))


def _inside_quotes(source: str) -> bool:
    quote = ""
    escaped = False
    for character in source:
        if escaped:
            escaped = False
        elif quote and character == "\\":
            escaped = True
        elif quote and character == quote:
            quote = ""
        elif not quote and character in "\"'":
            quote = character
    return bool(quote)
