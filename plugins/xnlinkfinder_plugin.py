#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — xnLinkFinder Plugin
=====================================
JavaScript & HTML link/endpoint extraction engine.
Replaces basic LinkFinder with multi-source support:
  - JS files, HTML pages, Wayback Machine, CommonCrawl
  - Outputs clean API endpoints, parameters, secrets

Covers the reconnaissance GAP vs reconFTW's JS-focused extraction.
"""

import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin


class XnLinkFinderPlugin(BasePlugin):
    """xnLinkFinder — Deep JS/HTML endpoint extraction."""

    def name(self) -> str:
        return "XnLinkFinder"

    def description(self) -> str:
        return "xnLinkFinder — Extract endpoints, parameters, and secrets from JS/HTML sources."

    def _executable(self) -> str | None:
        import sys
        venv_bin = os.path.join(os.path.dirname(sys.executable), "xnLinkFinder")
        repo_venv = "/home/tcus/Desktop/PenLabs/venv/bin/xnLinkFinder"
        if shutil.which("xnLinkFinder"):
            return shutil.which("xnLinkFinder")
        if os.path.exists(venv_bin):
            return venv_bin
        if os.path.exists(repo_venv):
            return repo_venv
        return None

    def check_installed(self) -> bool:
        return self._executable() is not None

    def run(self, target: str, out_dir: str = "/tmp",
            depth: int = 3, scope_filter: str = "",
            timeout: int = 300, cookies: str = "",
            headers: dict = None) -> dict:
        """
        Run xnLinkFinder against a target.
        """
        exe = self._executable()
        if not exe:
            logging.warning("[xnLinkFinder] Not installed. Install: pip3 install xnLinkFinder")
            return {"endpoints": [], "parameters": [], "js_files": [], "secrets": [], "total": 0}

        os.makedirs(out_dir, exist_ok=True)
        output_file = os.path.join(out_dir, "xnlinkfinder_output.txt")
        params_file = os.path.join(out_dir, "xnlinkfinder_params.txt")

        from urllib.parse import urlparse
        target_hostname = urlparse(target).hostname or target
        effective_scope = scope_filter or target_hostname

        cmd = [
            exe,
            "-i", target,
            "-o", output_file,
            "-op", params_file,
            "-d", str(depth),
            "-sf", effective_scope,
            "-v",  # Verbose
        ]

        if cookies:
            cmd.extend(["-c", cookies])

        if headers:
            SAFE_HEADERS = {"user-agent", "cookie", "authorization", "referer", "x-forwarded-for", "accept", "accept-language"}
            for k, v in headers.items():
                if k.lower() in SAFE_HEADERS:
                    clean_v = str(v).replace('"', '')
                    cmd.extend(["-H", f"{k}: {clean_v}"])

        try:
            logging.info(f"[xnLinkFinder] Extracting endpoints from {target}...")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )

            if result.returncode != 0:
                logging.warning(f"[xnLinkFinder] Non-zero exit: {result.stderr[:200]}")

        except subprocess.TimeoutExpired:
            logging.warning(f"[xnLinkFinder] Timeout after {timeout}s")
        except Exception as e:
            logging.error(f"[xnLinkFinder] Execution error: {e}")
            return {"endpoints": [], "parameters": [], "js_files": [], "secrets": [], "total": 0}

        # Parse outputs
        endpoints = self._parse_output(output_file)
        parameters = self._parse_output(params_file)

        # Classify results
        js_files = [e for e in endpoints if e.endswith(('.js', '.mjs', '.jsx'))]
        api_endpoints = [e for e in endpoints if not e.endswith(('.js', '.mjs', '.jsx', '.css', '.png', '.jpg'))]
        secrets = self._detect_secrets(endpoints + parameters)

        total = len(endpoints) + len(parameters)
        logging.info(f"[xnLinkFinder] Found {len(api_endpoints)} endpoints, "
                     f"{len(parameters)} params, {len(js_files)} JS files, "
                     f"{len(secrets)} potential secrets")

        return {
            "endpoints": api_endpoints,
            "parameters": parameters,
            "js_files": js_files,
            "secrets": secrets,
            "total": total,
        }

    @staticmethod
    def _parse_output(filepath: str) -> list:
        """Parse xnLinkFinder text output (one URL per line)."""
        results = []
        if not os.path.exists(filepath):
            return results
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        results.append(line)
        except Exception:
            pass
        return results

    @staticmethod
    def _detect_secrets(items: list) -> list:
        """Quick scan for potential secrets/tokens in extracted content."""
        import re
        secret_patterns = [
            (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{16,})', "API_KEY"),
            (r'(?i)(secret|token|password|passwd)\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{8,})', "SECRET_TOKEN"),
            (r'(?i)(aws[_-]?access[_-]?key[_-]?id)\s*[:=]\s*[\'"]?(AKIA[A-Z0-9]{16})', "AWS_KEY"),
            (r'ghp_[a-zA-Z0-9]{36}', "GITHUB_PAT"),
            (r'(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}', "BEARER_TOKEN"),
        ]
        secrets = []
        for item in items:
            for pattern, secret_type in secret_patterns:
                if re.search(pattern, item):
                    secrets.append({"type": secret_type, "source": item[:200]})
                    break
        return secrets
