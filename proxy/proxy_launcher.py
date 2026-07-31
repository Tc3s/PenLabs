#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Subprocess launchers for PenLabs JA3 tooling."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class JA3ProxyLauncher:
    listen_host: str = "127.0.0.1"
    listen_port: int = 1080
    profile: str = "chrome120"
    profiles_path: Optional[str] = None
    ca_dir: Optional[str] = None
    process: Optional[subprocess.Popen] = None

    def build_command(self) -> List[str]:
        cmd = [
            sys.executable,
            "-m",
            "proxy.ja3_proxy",
            "--listen",
            f"{self.listen_host}:{int(self.listen_port)}",
            "--profile",
            self.profile,
        ]
        if self.profiles_path:
            cmd.extend(["--profiles", self.profiles_path])
        if self.ca_dir:
            cmd.extend(["--ca-dir", self.ca_dir])
        return cmd

    def build_env(self) -> Dict[str, str]:
        proxy_url = f"socks5h://{self.listen_host}:{int(self.listen_port)}"
        return {
            "ALL_PROXY": proxy_url,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NMAP_PROXY_SOCKS5": "yes",
        }

    def start(self) -> subprocess.Popen:
        if self.process and self.process.poll() is None:
            return self.process
        self.process = subprocess.Popen(
            self.build_command(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        )
        return self.process

    def stop(self) -> None:
        if not self.process or self.process.poll() is not None:
            return
        self.process.send_signal(signal.SIGTERM)
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)

    def status(self) -> Dict[str, object]:
        running = bool(self.process and self.process.poll() is None)
        return {
            "running": running,
            "pid": self.process.pid if running and self.process else None,
            "listen": f"{self.listen_host}:{int(self.listen_port)}",
            "profile": self.profile,
            "ca_dir": self.ca_dir,
        }


@dataclass
class JA3ProbeLauncher:
    profile: str = "chrome120"
    url: str = "https://ja3er.com/json"
    timeout: int = 20

    @property
    def workdir(self) -> Path:
        return Path(__file__).resolve().parent / "cmd" / "ja3probe"

    def build_command(self) -> List[str]:
        return [
            "go",
            "run",
            ".",
            "--profile",
            self.profile,
            "--url",
            self.url,
            "--timeout",
            str(int(self.timeout)),
        ]

    def run(self) -> subprocess.CompletedProcess:
        return subprocess.run(
            self.build_command(),
            cwd=str(self.workdir),
            capture_output=True,
            text=True,
            timeout=int(self.timeout) + 10,
        )
