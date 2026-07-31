#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Scope Enforcement Engine
Đảm bảo chỉ quét các target đã được authorize.
Quan trọng cho pentest chuyên nghiệp và Bug Bounty compliance.
"""

import os
import re
import ipaddress
import logging
from typing import Optional


class ScopeEngine:
    """
    Enforce legal scan perimeter.
    Load danh sách authorized IPs, CIDRs, domains từ scope file.
    
    Format scope file (mỗi dòng 1 rule):
        # Comment
        192.168.1.0/24          # CIDR range
        10.10.10.5              # Single IP
        example.com             # Exact domain
        *.example.com           # Wildcard subdomain
        *                       # Wildcard — cho phép mọi target (Bug Bounty mode)
    """

    # ═══════════════════════════════════════════════════════════════════
    # V1.0-FIX: SINGLETON PATTERN (TASK 7)
    # Allows ScopeEngine.instance() from anywhere without re-loading.
    # ═══════════════════════════════════════════════════════════════════
    _instance: Optional['ScopeEngine'] = None

    @classmethod
    def instance(cls) -> 'ScopeEngine':
        """
        Get or create the global ScopeEngine singleton.
        Auto-loads scope.txt from standard locations on first call.
        
        Returns:
            ScopeEngine: The singleton instance (permissive if no scope.txt found)
        """
        if cls._instance is None:
            cls._instance = cls.auto_load()
        return cls._instance

    @classmethod
    def auto_load(cls) -> 'ScopeEngine':
        """
        Search for scope.txt in standard locations and create a ScopeEngine.
        
        Search order:
            1. ./scope.txt (current working directory)
            2. ./config/scope.txt
            3. {project_root}/scope.txt (PenLabs root)
        
        If no scope file found, returns a permissive ScopeEngine
        (backward compatible: scan everything discovered under root target).
        
        Returns:
            ScopeEngine: Loaded from scope.txt or permissive fallback
        """
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        
        search_paths = [
            os.path.join(os.getcwd(), "scope.txt"),
            os.path.join(os.getcwd(), "config", "scope.txt"),
            os.path.join(project_root, "scope.txt"),
            os.path.join(project_root, "config", "scope.txt"),
        ]
        
        for path in search_paths:
            if os.path.exists(path):
                logging.info(f"[ScopeEngine] Auto-loaded scope from: {path}")
                return cls(scope_file=path)
        
        # V1.0-FIX: FAIL-CLOSED — No scope file means BLOCK ALL
        # Permissive mode must be explicitly requested via --permissive CLI flag.
        logging.warning(
            "[ScopeEngine] No scope.txt found in standard locations. "
            "Running in STRICT mode (all targets BLOCKED). "
            "Use --permissive flag or provide a scope.txt to allow scanning."
        )
        return cls(permissive=False)

    @classmethod
    def reset_instance(cls):
        """Reset singleton (useful for testing)."""
        cls._instance = None

    def __init__(self, scope_file: Optional[str] = None, permissive: bool = False, confirm_permissive: bool = False):
        """
        Args:
            scope_file:  Đường dẫn file scope. Nếu None → dùng permissive mode.
            permissive:  Nếu True và không có scope_file → cho phép mọi target (nguy hiểm!).
            confirm_permissive: Must be True to actually allow permissive mode.
        """
        if permissive and not confirm_permissive:
            msg = (
                "[ScopeEngine] CRITICAL WARNING: permissive=True used without confirm_permissive=True! "
                "This allows scanning ANY TARGET on the internet. "
                "Safely reverting to Strict Mode."
            )
            logging.critical(msg)
            print(f"\033[91m[!] {msg}\033[0m")
            self.permissive = False
        else:
            self.permissive = permissive
            
        self.scope_file = scope_file
        self._rules: list[str] = []
        self._wildcard_all = False

        if scope_file and os.path.exists(scope_file):
            self._load_scope(scope_file)
        elif not permissive and not scope_file:
            logging.warning(
                "[ScopeEngine] Không có scope file. Tất cả targets đều BLOCKED. "
                "Hãy tạo file scope hoặc dùng --permissive để override."
            )

    def _load_scope(self, filepath: str):
        """Load và parse scope rules từ file."""
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.split("#")[0].strip()  # Xoá comment
                if not line:
                    continue
                if line == "*":
                    self._wildcard_all = True
                    logging.warning("[ScopeEngine] Wildcard '*' detected — ALL targets are in scope!")
                    break
                self._rules.append(line)
        # V1.0-FIX: Auto-register as singleton so scanner_router gets the same instance
        ScopeEngine._instance = self
        logging.info(f"[ScopeEngine] Loaded {len(self._rules)} scope rules from {filepath}")

    def is_in_scope(self, target: str) -> bool:
        """
        Kiểm tra target có trong scope được authorize không.
        
        Returns:
            True nếu trong scope, False nếu ngoài scope.
        """
        if self._wildcard_all or self.permissive:
            return True

        if not self._rules:
            return False  # Strict: không có rule → không cho phép

        target = target.strip().lower()

        for rule in self._rules:
            rule = rule.lower()

            # CIDR check
            if "/" in rule:
                try:
                    target_ip = ipaddress.ip_address(target)
                    network = ipaddress.ip_network(rule, strict=False)
                    if target_ip in network:
                        return True
                except ValueError:
                    pass

            # Wildcard subdomain: *.example.com
            elif rule.startswith("*."):
                base = rule[len("*."):]  # example.com
                if target == base or target.endswith("." + base):
                    return True

            # Exact match (IP hoặc domain)
            elif target == rule:
                return True

        return False

    def check_or_exit(self, target: str):
        """
        Kiểm tra scope và raise ValueError nếu ngoài scope.
        Dùng trong pipeline để dừng sớm.
        """
        if not self.is_in_scope(target):
            raise ValueError(
                f"[ScopeEngine] ❌ Target '{target}' NGOÀI SCOPE! "
                f"Vui lòng kiểm tra file scope hoặc nhận authorization trước khi scan."
            )

    def add_rule(self, rule: str):
        """Thêm rule vào scope runtime (không lưu file)."""
        self._rules.append(rule.strip())

    def summary(self) -> str:
        """Trả về tóm tắt scope hiện tại."""
        if self._wildcard_all:
            return "⚠️  WILDCARD — Mọi target đều trong scope"
        if self.permissive:
            return "⚠️  PERMISSIVE — Mọi target đều trong scope (no scope file)"
        if not self._rules:
            return "🚫 STRICT — Không có rule nào, mọi target đều bị block"
        return f"✅ {len(self._rules)} scope rules từ {self.scope_file}"

    def __repr__(self) -> str:
        return f"<ScopeEngine rules={len(self._rules)} permissive={self.permissive} wildcard={self._wildcard_all}>"

