from bisect import bisect_right
from collections.abc import Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import replace
from itertools import accumulate, groupby
from pathlib import Path

from PySide6.QtCore import QIODevice, QSaveFile, QTimer, Qt
from PySide6.QtGui import QColor, QFontDatabase, QTextCharFormat
from PySide6.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel, QPlainTextEdit,
    QPushButton, QVBoxLayout,
)

from sniffer.analysis.follow import FollowStream, StreamChunk, assemble_stream, endpoint_label
from sniffer.analysis.streams import TransportProtocol
from sniffer.gui.dialogs.packet_colors import readable_text
from sniffer.model.packet import PacketRecord

PAGE_BYTES = 16 * 1024
DIRECTION_COLORS = ("#eaf2fc", "#fff1d6")
_PRINTABLE = bytes(value if 32 <= value < 127 else 46 for value in range(256))
_ASCII = bytes(value if value in (9, 10, 13) else _PRINTABLE[value] for value in range(256))
_ESCAPED = tuple(repr(bytes((value,)))[2:-1] for value in range(256))


def _format_chunk(chunk: StreamChunk, mode: str) -> str:
    if chunk.missing:
        return f"\n[缺少 {chunk.missing:,} 字节，偏移 0x{chunk.offset:X}]\n"
    data = bytes(chunk.data)
    if mode == "ascii":
        return data.translate(_ASCII).decode("ascii")
    if mode == "raw":
        return "".join(_ESCAPED[value] for value in data)

    lines = []
    for start in range(0, len(data), 16):
        row = data[start:start + 16]
        lines.append(f"{chunk.offset + start:08X}  {row.hex(' ').upper():47}  {row.translate(_PRINTABLE).decode('ascii')}\n")
    return "".join(lines)


def _save_stream(path: Path, chunks: tuple[StreamChunk, ...], labels: tuple[str, str], mode: str) -> Path:
    output = QSaveFile(str(path))
    if not output.open(QIODevice.OpenModeFlag.WriteOnly):
        raise OSError(output.errorString())
    try:
        for direction, group in groupby(chunks, key=lambda chunk: chunk.direction):
            if mode != "raw":
                _write(output, f"\n[{labels[direction]}]\n".encode("utf-8"))
            for chunk in group:
                data = bytes(chunk.data) if mode == "raw" else _format_chunk(chunk, mode).encode("utf-8")
                _write(output, data)
        if not output.commit():
            raise OSError(output.errorString())
    except OSError:
        if output.isOpen():
            output.cancelWriting()
        raise
    return path


def _write(output: QSaveFile, data: bytes) -> None:
    if data and output.write(data) != len(data):
        raise OSError(output.errorString())


class FollowStreamDialog(QDialog):
    def __init__(self, records: tuple[PacketRecord, ...], protocol: TransportProtocol, number: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"追踪 {protocol.upper()} 流 {number}")
        self.resize(920, 600)
        self.requested_flow_graph = False
        self._filename = f"{protocol}-stream-{number}"
        self._stream: FollowStream | None = None
        self._labels = ("", "")
        self._active: tuple[StreamChunk, ...] = ()
        self._ends: list[int] = []
        self._page = 0
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer follow stream")
        self._job: Future[FollowStream] | Future[Path] | None = self._worker.submit(
            assemble_stream, records, protocol, number,
        )

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        self.direction = QComboBox()
        self.direction.addItem("双向", None)
        self.direction.setEnabled(False)
        self.mode = QComboBox()
        for label, value in (("ASCII", "ascii"), ("十六进制", "hex"), ("原始字节", "raw")):
            self.mode.addItem(label, value)
        for text, widget in (("方向", self.direction), ("显示格式", self.mode)):
            label = QLabel(text)
            label.setBuddy(widget)
            controls.addWidget(label)
            controls.addWidget(widget)
        controls.addStretch(1)
        layout.addLayout(controls)

        legend = QHBoxLayout()
        self._swatches: list[QLabel] = []
        self._formats: list[QTextCharFormat] = []
        for color in DIRECTION_COLORS:
            foreground = readable_text(QColor(color))
            chip = QLabel()
            chip.setTextFormat(Qt.TextFormat.PlainText)
            chip.setStyleSheet(f"background-color: {color}; color: {foreground.name()}; padding: 4px 8px;")
            chip.hide()
            legend.addWidget(chip)
            self._swatches.append(chip)
            fmt = QTextCharFormat()
            fmt.setForeground(foreground)
            fmt.setBackground(QColor(color))
            self._formats.append(fmt)
        legend.addStretch(1)
        layout.addLayout(legend)

        self._hint = QLabel("非打印字节在预览中转义。保存时写入捕获的二进制字节。")
        self._hint.hide()
        layout.addWidget(self._hint)
        self.preview = QPlainTextEdit()
        self.preview.setAccessibleName("流负载")
        self.preview.setReadOnly(True)
        self.preview.setFont(QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont))
        self.preview.setUndoRedoEnabled(False)
        layout.addWidget(self.preview, 1)

        self._status = QLabel("正在整理已捕获的流…")
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self._status)
        actions = QHBoxLayout()
        self.previous = QPushButton("上一页")
        self.next = QPushButton("下一页")
        self._pages = QLabel()
        for widget in (self.previous, self._pages, self.next):
            actions.addWidget(widget)
        actions.addStretch(1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        if protocol == "tcp":
            self._flow_graph = buttons.addButton("时序图", QDialogButtonBox.ButtonRole.ActionRole)
            self._flow_graph.clicked.connect(self._open_flow_graph)
        self._save = buttons.addButton("保存为…", QDialogButtonBox.ButtonRole.ActionRole)
        self._save.setEnabled(False)
        buttons.rejected.connect(self.reject)
        actions.addWidget(buttons)
        layout.addLayout(actions)

        self.direction.currentIndexChanged.connect(self._select_direction)
        self.mode.currentIndexChanged.connect(self._render_page)
        self.previous.clicked.connect(lambda: self._show_page(self._page - 1))
        self.next.clicked.connect(lambda: self._show_page(self._page + 1))
        self._save.clicked.connect(self._choose_save)
        self._render_page()
        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._poll)
        self._timer.start()

    def _open_flow_graph(self) -> None:
        self.requested_flow_graph = True
        self.accept()

    def done(self, result: int) -> None:
        self._timer.stop()
        self._worker.shutdown(wait=False, cancel_futures=True)
        super().done(result)

    def _poll(self) -> None:
        job = self._job
        if job is None or not job.done():
            return
        self._timer.stop()
        self._job = None
        try:
            result = job.result()
        except Exception as error:
            self._status.setText(str(error))
            self._save.setEnabled(bool(self._active))
            return
        if isinstance(result, FollowStream):
            self._show_stream(result)
        else:
            self._status.setText(f"已保存 {result.name}")
            self._save.setEnabled(bool(self._active))

    def _show_stream(self, stream: FollowStream) -> None:
        self._stream = stream
        first, second = (endpoint_label(endpoint) for endpoint in stream.endpoints)
        self._labels = f"{first} → {second}", f"{second} → {first}"
        for direction, (chip, text) in enumerate(zip(self._swatches, self._labels)):
            self.direction.addItem(text, direction)
            chip.setText(text)
            chip.show()
        self.direction.setEnabled(True)
        self._select_direction()

    def _select_direction(self) -> None:
        if self._stream is None:
            return
        direction = self.direction.currentData()
        self._active = tuple(chunk for chunk in self._stream.chunks if direction is None or chunk.direction == direction)
        self._ends = list(accumulate(len(chunk.data) or 1 for chunk in self._active))
        count = sum(len(chunk.data) for chunk in self._active)
        self._status.setText(f"已捕获负载 {count:,} 字节" if count else "此方向没有已捕获的负载。")
        self._save.setEnabled(bool(count) and self._job is None)
        self._show_page(0)

    def _show_page(self, page: int) -> None:
        self._page = page
        self._render_page()

    def _page_chunks(self) -> Iterator[StreamChunk]:
        start = self._page * PAGE_BYTES
        stop = start + PAGE_BYTES
        for index in range(bisect_right(self._ends, start), len(self._active)):
            left = self._ends[index - 1] if index else 0
            if left >= stop:
                break
            chunk = self._active[index]
            skip = max(0, start - left)
            if chunk.missing:
                yield chunk
            else:
                yield replace(chunk, offset=chunk.offset + skip, data=chunk.data[skip:stop - left])

    def _render_page(self) -> None:
        mode = self.mode.currentData()
        self._hint.setVisible(mode == "raw")
        size = self._ends[-1] if self._ends else 0
        pages = max(1, (size + PAGE_BYTES - 1) // PAGE_BYTES)
        self.previous.setEnabled(self._page > 0)
        self.next.setEnabled(self._page + 1 < pages)
        self._pages.setText(f"{self._page + 1} / {pages}" if pages > 1 else "")
        self.preview.clear()
        cursor = self.preview.textCursor()
        cursor.beginEditBlock()
        for direction, group in groupby(self._page_chunks(), key=lambda chunk: chunk.direction):
            if not cursor.atBlockStart():
                cursor.insertBlock()
            cursor.insertText("".join(_format_chunk(chunk, mode) for chunk in group), self._formats[direction])
        cursor.endEditBlock()
        self.preview.verticalScrollBar().setValue(0)

    def _choose_save(self) -> None:
        mode = self.mode.currentData()
        suffix, name_filter = (".bin", "二进制 (*.bin)") if mode == "raw" else (".txt", "文本 (*.txt)")
        filename, _ = QFileDialog.getSaveFileName(self, "保存流负载", self._filename + suffix, name_filter)
        if not filename:
            return
        path = Path(filename)
        self._save.setEnabled(False)
        self._status.setText("正在保存流负载…")
        self._job = self._worker.submit(_save_stream, path, self._active, self._labels, mode)
        self._timer.start()
