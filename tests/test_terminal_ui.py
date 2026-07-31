import os

from core.terminal_ui import border, display_width, frame_line, truncate_display


def test_terminal_ui_width_handles_ansi_and_wide_chars():
    assert display_width("\033[96mABC\033[0m") == 3
    assert display_width("⚔️  TEST") >= len(" TEST")
    line = frame_line("\033[96mABC\033[0m", 10)
    assert line.count("║") == 2


def test_terminal_ui_ascii_fallback(monkeypatch):
    monkeypatch.setenv("PENLABS_ASCII_UI", "1")
    assert border("top", 4) == "+----+"
    assert frame_line("x", 4).startswith("|")
    assert truncate_display("abcdef", 5).endswith("...")
