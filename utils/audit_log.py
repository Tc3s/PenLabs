#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Immutable Audit Log
Ghi lại mọi hành động exploit/scan với SHA256 chaining.
Mỗi entry được ký hash chaining để phát hiện tampering.
"""

import os
import hashlib
import threading
import socket
import json
import logging
from datetime import datetime, timezone
from typing import Optional


class AuditLog:
    """
    Immutable audit log với SHA256 hash chaining.
    Mỗi entry chứa hash của entry trước → phát hiện nếu bị sửa.
    """

    DEFAULT_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "output", "audit.log"
    )

    def __init__(self, log_path: Optional[str] = None):
        self.log_path = log_path or self.DEFAULT_PATH
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._get_last_hash()

    def _get_last_hash(self) -> str:
        """Đọc hash của entry cuối cùng để chain."""
        if not os.path.exists(self.log_path):
            return "GENESIS"
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip()]
            if lines:
                last = lines[-1]
                # Format: timestamp|actor|action|target|result|prev_hash|entry_hash
                parts = last.split("|")
                if len(parts) >= 7:
                    return parts[-1]
        except Exception:
            pass
        return "GENESIS"

    def log(self, actor: str, action: str, target: str, result: str = ""):
        """
        Ghi một audit entry.

        Args:
            actor:  Định danh người thực hiện (vd: username, "CLI")
            action: Hành động (vd: "scan", "exploit", "list_sessions")
            target: Mục tiêu (vd: IP/domain)
            result: Kết quả ngắn (vd: "success", "failed", "timeout")
        """
        ts = datetime.now(timezone.utc).isoformat()
        # Sanitize pipe characters để tránh làm hỏng format
        actor  = str(actor).replace("|", "/")
        action = str(action).replace("|", "/")
        target = str(target).replace("|", "/")
        result = str(result).replace("|", "/")

        with self._lock:
            prev_hash = self._last_hash
            data = f"{ts}|{actor}|{action}|{target}|{result}|{prev_hash}"
            entry_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()
            line = f"{data}|{entry_hash}\n"

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(line)

            self._last_hash = entry_hash

            # [V1.0] Optional remote syslog forwarding
            self._forward_syslog(actor, action, target, result, ts)

    def _forward_syslog(self, actor: str, action: str, target: str, result: str, ts: str):
        """[V1.0] Forward audit entry to remote syslog server (UDP)."""
        try:
            from config import Config
            host = Config.AUDIT_SYSLOG_HOST
            port = Config.AUDIT_SYSLOG_PORT
            if not host:
                return
            # RFC5424 syslog format
            msg = f"<134>1 {ts} PenLabs audit - - - actor={actor} action={action} target={target} result={result}"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(msg.encode('utf-8'), (host, port))
            sock.close()
        except Exception:
            pass  # Non-blocking, don't break audit logging

    def export_json(self, out_path: str = None) -> str:
        """[V1.0] Export audit log as JSON for SIEM ingestion."""
        out_path = out_path or self.log_path.replace('.log', '.json')
        entries = []
        if os.path.exists(self.log_path):
            with open(self.log_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split('|')
                    if len(parts) >= 7:
                        entries.append({
                            "timestamp": parts[0],
                            "actor": parts[1],
                            "action": parts[2],
                            "target": parts[3],
                            "result": parts[4],
                            "prev_hash": parts[5],
                            "entry_hash": parts[6],
                        })
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(entries, f, indent=2)
        return out_path

    def verify_integrity(self) -> tuple[bool, list[int]]:
        """
        Kiểm tra tính toàn vẹn của toàn bộ audit log.
        [SECURITY-FIX] Verify CẢ hash correctness VÀ chain linkage.
        Trả về (is_valid, [danh sách line bị tamper]).
        """
        if not os.path.exists(self.log_path):
            return True, []

        tampered_lines = []
        prev_hash = "GENESIS"

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("|")
                    if len(parts) < 7:
                        tampered_lines.append(lineno)
                        prev_hash = "CORRUPTED"
                        continue

                    stored_hash = parts[-1]
                    # Tái tạo data string (bỏ entry_hash)
                    data = "|".join(parts[:-1])
                    expected_hash = hashlib.sha256(data.encode("utf-8")).hexdigest()

                    # [SECURITY-FIX] Check 1: Hash của entry data phải đúng
                    if stored_hash != expected_hash:
                        tampered_lines.append(lineno)

                    # [SECURITY-FIX] Check 2: prev_hash trong entry phải khớp với entry_hash trước đó
                    # Format: ts|actor|action|target|result|prev_hash|entry_hash
                    # parts[-2] là prev_hash field trong entry hiện tại
                    entry_prev_hash = parts[-2]
                    if entry_prev_hash != prev_hash:
                        if lineno not in tampered_lines:
                            tampered_lines.append(lineno)

                    # Cập nhật prev_hash cho entry tiếp theo
                    prev_hash = stored_hash
        except Exception as e:
            return False, []

        return len(tampered_lines) == 0, tampered_lines


# Singleton instance
_audit = None
_audit_lock = threading.Lock()


def get_audit_log(log_path: Optional[str] = None) -> AuditLog:
    """
    Trả về singleton AuditLog instance.
    
    [SECURITY-FIX][HIGH-05] Cảnh báo nếu được gọi với log_path khác sau khi
    singleton đã khởi tạo — tránh việc audit entries bị ghi nhầm file.
    """
    global _audit
    with _audit_lock:
        if _audit is None:
            _audit = AuditLog(log_path)
        elif log_path is not None and _audit.log_path != log_path:
            logging.warning(
                f"[AuditLog][HIGH-05] get_audit_log() called with log_path='{log_path}' "
                f"but singleton already exists with log_path='{_audit.log_path}'. "
                f"Using existing instance. This may cause audit entries to be written "
                f"to an unexpected file."
            )
    return _audit
