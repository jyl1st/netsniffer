from concurrent.futures import Future, ThreadPoolExecutor

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QComboBox, QLabel

from sniffer.capture.bpf import FILTER_PRESETS, CaptureFilterError, check_capture_filter


class CaptureFilterBox(QComboBox):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.addItem("")
        self.addItems(FILTER_PRESETS)
        self.setMinimumWidth(170)
        self.lineEdit().setPlaceholderText("BPF 表达式")

        self.feedback = QLabel()
        self.feedback.setMinimumWidth(self.feedback.fontMetrics().horizontalAdvance("无法校验") + 8)
        self._device: str | None = None
        self._job: tuple[tuple[str, str], Future] | None = None
        self._workers = ThreadPoolExecutor(max_workers=1, thread_name_prefix="NetSniffer BPF")
        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.timeout.connect(self._check)
        self._poll = QTimer(self)
        self._poll.setInterval(50)
        self._poll.timeout.connect(self._finish)
        self.currentTextChanged.connect(self._schedule)

    def set_validation_device(self, device: str | None) -> None:
        if self._device != device:
            self._device = device
            self._schedule()

    def close_validator(self) -> None:
        self._debounce.stop()
        self._poll.stop()
        self._workers.shutdown(wait=False, cancel_futures=True)

    def validate(self, device: str, expression: str) -> Future[None]:
        return self._workers.submit(check_capture_filter, device, expression)

    def _request(self) -> tuple[str, str] | None:
        text = self.currentText().strip()
        return (self._device, text) if self._device and text else None

    def _schedule(self, *_) -> None:
        self._debounce.stop()
        if self._request() is None:
            self._show_feedback("")
        else:
            self._show_feedback("校验中")
            self._debounce.start(300)

    def _check(self) -> None:
        if self._job is not None:
            self._debounce.start(50)
            return
        request = self._request()
        if request is not None:
            self._job = request, self.validate(*request)
            self._poll.start()

    def _finish(self) -> None:
        if self._job is None:
            self._poll.stop()
            return
        request, job = self._job
        if not job.done():
            return
        self._job = None
        self._poll.stop()
        # 快速输入或换网卡时，旧校验结果不能覆盖当前表达式。
        if request != self._request():
            return
        self._debounce.stop()
        try:
            job.result()
        except CaptureFilterError as error:
            self._show_feedback("无效", str(error), "#bd3434")
        except Exception as error:
            self._show_feedback("无法校验", str(error))
        else:
            self._show_feedback("有效", "表达式可在当前网卡上编译。", "#27854b")

    def _show_feedback(self, state: str, details: str = "", border: str = "") -> None:
        self.feedback.setText(state)
        self.feedback.setToolTip(details)
        edit = self.lineEdit()
        edit.setToolTip(details)
        edit.setAccessibleDescription(details or state)
        edit.setStyleSheet(f"QLineEdit {{ border: 1px solid {border}; }}" if border else "")
