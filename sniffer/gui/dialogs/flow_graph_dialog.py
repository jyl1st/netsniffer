from collections.abc import Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from math import ceil, floor
from pathlib import Path

from PySide6.QtCore import QIODevice, QLineF, QPointF, QRectF, QSaveFile, QTimer, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontDatabase, QFontMetrics, QImage, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QGraphicsScene, QGraphicsView, QHBoxLayout, QLabel,
    QPushButton, QSpinBox, QVBoxLayout,
)

from sniffer.analysis.flow_graph import FIN, MAX_GRAPH_PACKETS, FlowGraph, FlowPhaseKind, build_flow_graph
from sniffer.analysis.follow import endpoint_label
from sniffer.analysis.tcp import RST, SYN
from sniffer.model.packet import MAX_PACKETS, PacketRecord

_PAGE_SIZE = 100
_WIDTH = 980
_HEADER = 61
_ROW = 36
_A, _B = 225, 754
_INK = QColor("#24354a")
_MUTED = QColor("#52647a")
_ACCENT = QColor("#087369")
_RESET = QColor("#b42d3b")
_CENTER = Qt.AlignmentFlag.AlignCenter
_LEFT = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter


class _FlowScene(QGraphicsScene):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.graph: FlowGraph | None = None
        self.start = self.stop = 0
        self.stream_number = 0
        self._font = QFont(self.font())
        self._font.setPixelSize(14)
        self._title_font = QFont(self._font)
        self._title_font.setBold(True)
        self._mono = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        self._mono.setPixelSize(13)
        self.set_page(None, 0, 0)

    def set_page(self, graph: FlowGraph | None, stream_number: int, page: int) -> None:
        self.graph = graph
        self.stream_number = stream_number
        self.start = page * _PAGE_SIZE
        self.stop = min(self.start + _PAGE_SIZE, len(graph.events)) if graph else 0
        self.setSceneRect(0, 0, _WIDTH, _HEADER + (self.stop - self.start) * _ROW + 12)
        self.update()

    def drawBackground(self, painter: QPainter, exposed: QRectF) -> None:
        painter.fillRect(exposed, QColor("#ffffff"))
        if self.graph is None or self.graph.endpoints is None:
            return
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QPen(QColor("#b6c4d1"), 1))
        for x in (_A, _B):
            painter.drawLine(QLineF(x, _HEADER, x, self.sceneRect().bottom() - 12))
        first = max(self.start, self.start + floor((exposed.top() - _HEADER) / _ROW))
        last = min(self.stop, self.start + ceil((exposed.bottom() - _HEADER) / _ROW))
        for index in range(first, last):
            self._draw_event(painter, index)
        self._draw_phases(painter)
        if exposed.top() <= _HEADER:
            self._draw_header(painter)

    def _draw_header(self, painter: QPainter) -> None:
        painter.fillRect(QRectF(0, 0, _WIDTH, _HEADER), QColor("#eef3f7"))
        painter.setFont(self._font)
        painter.setPen(_MUTED)
        painter.drawText(QRectF(16, 23, 120, 18), _LEFT, f"TCP 流 {self.stream_number}")
        painter.drawText(QRectF(16, 40, 120, 18), _LEFT, "帧号 / 相对时间")
        painter.drawText(QRectF(846, 36, 120, 18), _LEFT, "连接阶段")
        for x, name, endpoint, owners in zip((_A, _B), "AB", self.graph.endpoints, self.graph.owners):
            painter.setPen(_INK)
            painter.setFont(self._title_font)
            painter.drawText(QRectF(x - 180, 6, 360, 20), _CENTER, f"{name}  {endpoint_label(endpoint)}")
            painter.setPen(_MUTED)
            painter.setFont(self._font)
            width = 174 if x == _A else 168
            labels = "、".join(owner.label for owner in owners)
            labels = QFontMetrics(self._font).elidedText(labels, Qt.TextElideMode.ElideRight, width)
            painter.drawText(QRectF(x - width / 2, 31, width, 20), _CENTER, labels)

    def _draw_event(self, painter: QPainter, index: int) -> None:
        event = self.graph.events[index]
        top = _HEADER + (index - self.start) * _ROW
        y = top + 26
        painter.setFont(self._mono)
        painter.setPen(_MUTED)
        time = f"{event.time:.6f} s" if event.time is not None else "—"
        painter.drawText(QRectF(16, top + 7, 194, 24), _LEFT, f"#{event.frame}  {time}")
        color = _RESET if event.flags & RST else _ACCENT if event.flags & (SYN | FIN) else _INK
        painter.setPen(color)
        ack = event.ack if event.ack is not None else "—"
        label = f"{event.flag_text}  Seq={event.seq}  Ack={ack}  Len={event.length}  Win={event.window}"
        painter.drawText(QRectF(_A + 2, top + 2, _B - _A - 4, 20), _CENTER, label)
        source, target = (_B, _A) if event.direction else (_A, _B)
        base = target - 9 if event.direction == 0 else target + 9
        painter.setPen(QPen(color, 1.5))
        painter.drawLine(QLineF(source, y, target, y))
        painter.setBrush(color)
        painter.drawPolygon(QPolygonF([QPointF(target, y), QPointF(base, y - 4), QPointF(base, y + 4)]))
        painter.setBrush(Qt.BrushStyle.NoBrush)

    def _draw_phases(self, painter: QPainter) -> None:
        painter.setFont(self._title_font)
        for phase in self.graph.phases:
            first, last = max(phase.first, self.start), min(phase.last, self.stop - 1)
            if first > last:
                continue
            color = _RESET if phase.kind == FlowPhaseKind.RESET else _ACCENT
            top = _HEADER + (first - self.start) * _ROW + 3
            bottom = _HEADER + (last - self.start + 1) * _ROW - 3
            painter.setPen(QPen(color, 1.5))
            painter.drawLines([QLineF(824, top, 834, top), QLineF(834, top, 834, bottom), QLineF(824, bottom, 834, bottom)])
            painter.drawText(QRectF(846, top, 118, bottom - top), _LEFT, phase.kind.value)


class _FlowView(QGraphicsView):
    frame_clicked = Signal(int)

    def _frame_at(self, event) -> int | None:
        scene = self.scene()
        point = self.mapToScene(event.position().toPoint())
        index = scene.start + floor((point.y() - _HEADER) / _ROW)
        if scene.start <= index < scene.stop and _A - 5 <= point.x() <= _B + 5:
            return scene.graph.events[index].frame
        return None

    def mouseMoveEvent(self, event) -> None:
        shape = Qt.CursorShape.PointingHandCursor if self._frame_at(event) is not None else Qt.CursorShape.ArrowCursor
        self.viewport().setCursor(shape)
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        frame = self._frame_at(event)
        if event.button() == Qt.MouseButton.LeftButton and frame is not None:
            self.frame_clicked.emit(frame)
            event.accept()
            return
        super().mouseReleaseEvent(event)


class FlowGraphDialog(QDialog):
    def __init__(self, records: Sequence[PacketRecord], stream_number: int, parent=None):
        super().__init__(parent)
        self.setWindowTitle("TCP 时序图")
        self.resize(1040, 552)
        self.frame_number: int | None = None
        self._records = records
        self._worker = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer flow graph")
        self._job: Future[FlowGraph] | None = None
        self._graph: FlowGraph | None = None
        self._number = stream_number
        self._page = 0

        layout = QVBoxLayout(self)
        controls = QHBoxLayout()
        label = QLabel("TCP 流编号")
        self.stream_input = QSpinBox()
        self.stream_input.setRange(0, MAX_PACKETS - 1)
        self.stream_input.setValue(stream_number)
        label.setBuddy(self.stream_input)
        load = QPushButton("显示")
        load.setAutoDefault(True)
        load.setDefault(True)
        load.clicked.connect(self._load_stream)
        self.export = QPushButton("导出 PNG")
        self.export.setToolTip("导出时序图当前页的全部箭头。")
        self.export.clicked.connect(self._choose_export)
        for widget in (label, self.stream_input, load):
            controls.addWidget(widget)
        controls.addStretch(1)
        controls.addWidget(self.export)
        layout.addLayout(controls)

        self.scene = _FlowScene(self)
        self.view = _FlowView(self.scene)
        self.view.setAlignment(Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop)
        self.view.setMouseTracking(True)
        self.view.setAccessibleName("TCP 流时序图")
        self.view.frame_clicked.connect(self._jump_to_frame)
        layout.addWidget(self.view, 1)

        footer = QHBoxLayout()
        self._status = QLabel()
        self._status.setTextFormat(Qt.TextFormat.PlainText)
        self._status.setWordWrap(True)
        footer.addWidget(self._status, 1)
        self._previous = QPushButton("上一页")
        self._next = QPushButton("下一页")
        self._pages = QLabel()
        self._previous.clicked.connect(lambda: self._show_page(self._page - 1))
        self._next.clicked.connect(lambda: self._show_page(self._page + 1))
        for widget in (self._previous, self._pages, self._next):
            footer.addWidget(widget)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.button(QDialogButtonBox.StandardButton.Close).setText("关闭")
        close.rejected.connect(self.reject)
        footer.addWidget(close)
        layout.addLayout(footer)

        self._timer = QTimer(self)
        self._timer.setInterval(25)
        self._timer.timeout.connect(self._poll)
        self._load_stream()

    def done(self, result: int) -> None:
        self._timer.stop()
        self._worker.shutdown(wait=False, cancel_futures=True)
        super().done(result)

    def _load_stream(self) -> None:
        if self._job is not None:
            self._job.cancel()
        self._number = self.stream_input.value()
        self._graph = None
        self._show_page(0)
        self._status.setText(f"正在整理 TCP 流 {self._number}…")
        self._job = self._worker.submit(build_flow_graph, self._records, self._number)
        self._timer.start()

    def _poll(self) -> None:
        if self._job is None or not self._job.done():
            return
        self._timer.stop()
        try:
            self._graph = self._job.result()
        except Exception as error:
            self._status.setText(f"无法生成时序图。{error}")
            return
        finally:
            self._job = None
        self._show_page(0)
        self._status.setText(self._describe_graph())

    def _describe_graph(self) -> str:
        graph = self._graph
        if not graph.events:
            return f"TCP 流 {self._number} 没有可绘制的帧。"
        details = [f"{graph.total:,} 帧"]
        if not graph.has_syn:
            details.append("无握手")
        elif not any(phase.kind == FlowPhaseKind.HANDSHAKE for phase in graph.phases):
            details.append("图中无完整握手")
        if graph.total > MAX_GRAPH_PACKETS:
            details.append(f"仅绘制前 {MAX_GRAPH_PACKETS:,} 帧")
        details.append("单击箭头定位到包")
        return " · ".join(details)

    def _show_page(self, page: int) -> None:
        count = len(self._graph.events) if self._graph else 0
        pages = (count + _PAGE_SIZE - 1) // _PAGE_SIZE
        self._page = page
        self.scene.set_page(self._graph if count else None, self._number, page)
        self.view.verticalScrollBar().setValue(0)
        self._pages.setText(f"{page + 1} / {pages}" if pages else "")
        self._previous.setEnabled(page > 0)
        self._next.setEnabled(page + 1 < pages)
        for widget in (self._previous, self._pages, self._next):
            widget.setVisible(pages > 1)
        self.export.setEnabled(bool(count))

    def _jump_to_frame(self, frame_number: int) -> None:
        self.frame_number = frame_number
        self.accept()

    def _choose_export(self) -> None:
        filename, _ = QFileDialog.getSaveFileName(
            self, "导出当前页时序图", f"tcp-stream-{self._number}-{self._page + 1}.png", "PNG 图片 (*.png)",
        )
        if not filename:
            return
        path = Path(filename)
        if not path.suffix:
            path = path.with_suffix(".png")
        if self.export_png(path):
            result = f"已导出第 {self._page + 1} 页至 {path.name}"
        else:
            result = f"无法导出 {path.name}"
        self._status.setText(f"{self._describe_graph()} · {result}")

    def export_png(self, path: Path) -> bool:
        image = QImage(self.scene.sceneRect().size().toSize(), QImage.Format.Format_RGB32)
        painter = QPainter(image)
        try:
            self.scene.render(painter)
        finally:
            painter.end()
        output = QSaveFile(str(path))
        return output.open(QIODevice.OpenModeFlag.WriteOnly) and image.save(output, "PNG") and output.commit()
