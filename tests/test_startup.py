from concurrent.futures import Future
from threading import Event

import pytest
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

import main
from sniffer.capture.bpf import CaptureFilterError
from sniffer.capture.interfaces import Adapter
from sniffer.gui import main_window


def test_main_starts_window_and_runs_event_loop(monkeypatch):
    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    visible_titles = []

    def verify_window():
        visible_titles.extend(
            window.windowTitle()
            for window in QApplication.topLevelWidgets()
            if window.isVisible()
        )
        QApplication.quit()

    def create_window():
        window = create_main_window()
        QTimer.singleShot(0, verify_window)
        return window

    create_main_window = main.create_main_window
    monkeypatch.setattr(main, "create_main_window", create_window)

    assert main.main() == 0
    assert "NetSniffer" in visible_titles


@pytest.fixture
def capture_window(monkeypatch):
    class Session:
        def __init__(self, settings):
            self.settings = settings
            self.ready = Event()
            self.done = Event()
            self.error = None

        def start(self):
            self.ready.set()

        def stop(self):
            self.done.set()

        def drain(self):
            return []

        def counts(self):
            return 0, 0

    monkeypatch.setenv("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    adapter = Adapter("test", "test", "test", "有线", ("192.0.2.10",), (), "—")
    monkeypatch.setattr(main_window, "startup_status", lambda: (True, ""))
    monkeypatch.setattr(main_window, "list_adapters", lambda: [adapter])
    monkeypatch.setattr(main_window, "CaptureSession", Session)
    window = main_window.MainWindow()
    window.start_capture()
    window._poll_capture()
    yield window
    window.stop_capture()
    window._poll_capture()
    window.close()
    app.processEvents()


def test_restart_uses_current_capture_filter(capture_window, monkeypatch):
    window = capture_window
    old = window._session
    validated = Future()

    def validate(device, expression):
        assert (device, expression) == ("test", "tcp port 443")
        return validated

    monkeypatch.setattr(window.capture_filter, "validate", validate)
    assert window.capture_filter.isEnabled()
    window.capture_filter.setEditText(" tcp port 443 ")
    window._restart_action.trigger()
    assert window._session is old and not old.done.is_set()
    validated.set_result(None)
    window._poll_capture()
    assert old.done.is_set()
    assert window._session.settings.expression == "tcp port 443"
    window._poll_capture()
    assert window._active_filter.text() == "抓包过滤：tcp port 443"


@pytest.mark.parametrize("active", [True, False])
def test_restart_rejects_invalid_capture_filter(capture_window, monkeypatch, active):
    window = capture_window
    if not active:
        window.stop_capture()
        window._poll_capture()
    old = window._session
    validated = Future()
    validated.set_exception(CaptureFilterError("BPF 编译失败"))
    monkeypatch.setattr(window.capture_filter, "validate", lambda *_: validated)
    window.capture_filter.setEditText("tcp port")
    window._restart_action.trigger()
    window._poll_capture()
    assert window._session is old
    assert old is None or not old.done.is_set()
    assert "BPF 编译失败" in window.statusBar().currentMessage()
