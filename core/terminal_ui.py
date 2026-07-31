#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Terminal rendering helpers with ANSI-aware width and ASCII fallback."""

from __future__ import annotations

import os
import re
import unicodedata

ANSI_RE = re.compile(r"\x1B\[[0-9;]*[mK]")


def ascii_ui() -> bool:
    return str(os.getenv("PENLABS_ASCII_UI", "")).strip().lower() in {"1", "true", "yes", "on"}


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", str(text))


def display_width(text: str) -> int:
    width = 0
    for ch in strip_ansi(text):
        width += 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
    return width


def truncate_display(text: str, max_width: int) -> str:
    plain = strip_ansi(text)
    if display_width(plain) <= max_width:
        return plain
    out = []
    width = 0
    suffix = "..." if ascii_ui() else "…"
    suffix_width = len(suffix)
    for ch in plain:
        ch_width = 2 if unicodedata.east_asian_width(ch) in ("W", "F") else 1
        if width + ch_width + suffix_width > max_width:
            break
        out.append(ch)
        width += ch_width
    return "".join(out).rstrip() + suffix


def frame_line(content: str, width: int = 86, color: str = "", reset: str = "") -> str:
    left, right = ("|", "|") if ascii_ui() else ("║", "║")
    pad = max(0, width + 2 - display_width(content))
    return f"{color}{left}{reset}{content}{' ' * pad}{color}{right}{reset}"


def border(kind: str, width: int = 86, color: str = "", reset: str = "") -> str:
    if ascii_ui():
        chars = {
            "top": ("+", "-", "+"),
            "mid": ("+", "=", "+"),
            "sep": ("+", "-", "+"),
            "bottom": ("+", "-", "+"),
        }
    else:
        chars = {
            "top": ("╔", "═", "╗"),
            "mid": ("╠", "═", "╣"),
            "sep": ("╠", "─", "╣"),
            "bottom": ("╚", "═", "╝"),
        }
    left, fill, right = chars.get(kind, chars["sep"])
    return f"{color}{left}{fill * width}{right}{reset}"
