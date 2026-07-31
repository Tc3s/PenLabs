#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small helpers for keeping raw tool artifacts inspectable."""

import json
import os
import re
import shlex
from datetime import datetime


def ensure_raw_dir(out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    return out_dir


_CONDITIONAL_SENSITIVE_VALUE_FLAGS = {"-H", "--headers"}
_ALWAYS_SENSITIVE_VALUE_FLAGS = {"--cookie", "--api-token", "--proxy"}


def _redact_command(cmd: list) -> list[str]:
    redacted: list[str] = []
    redact_next = ""
    for part in [str(c) for c in cmd]:
        if redact_next:
            if redact_next == "always" or re.search(r"(authorization|cookie|api[-_]?token|bearer|session|proxy)", part, re.I):
                redacted.append("<redacted>")
            else:
                redacted.append(part)
            redact_next = ""
            continue
        if part in _ALWAYS_SENSITIVE_VALUE_FLAGS:
            redacted.append(part)
            redact_next = "always"
            continue
        if part in _CONDITIONAL_SENSITIVE_VALUE_FLAGS:
            redacted.append(part)
            redact_next = "conditional"
            continue
        part = re.sub(r"(?i)(Authorization:\s*Bearer\s+)[^\s'\"]+", r"\1<redacted>", part)
        part = re.sub(r"(?i)(Cookie:\s*)[^'\"]+", r"\1<redacted>", part)
        part = re.sub(r"(?i)(api[_-]?token=)[^&\s]+", r"\1<redacted>", part)
        part = re.sub(r"(https?://)[^:/\s]+:[^@\s]+@", r"\1<redacted>@", part)
        redacted.append(part)
    return redacted


def write_command(out_dir: str, filename: str, cmd: list) -> None:
    ensure_raw_dir(out_dir)
    path = os.path.join(out_dir, filename)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(shlex.join(_redact_command(cmd)))
            fh.write("\n")
    except Exception:
        pass


def write_text(out_dir: str, filename: str, data: str | bytes) -> None:
    ensure_raw_dir(out_dir)
    path = os.path.join(out_dir, filename)
    try:
        text = data.decode(errors="replace") if isinstance(data, bytes) else str(data or "")
        with open(path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write(text)
    except Exception:
        pass


def write_json(out_dir: str, filename: str, data) -> None:
    ensure_raw_dir(out_dir)
    path = os.path.join(out_dir, filename)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, ensure_ascii=True, default=str)
    except Exception:
        pass


def append_manifest(out_dir: str, tool: str, files: list[str], note: str = "") -> None:
    ensure_raw_dir(out_dir)
    path = os.path.join(out_dir, "_artifact_manifest.jsonl")
    payload = {
        "timestamp": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "tool": tool,
        "files": files,
        "note": note,
    }
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")
    except Exception:
        pass
