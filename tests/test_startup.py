from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

import main


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
