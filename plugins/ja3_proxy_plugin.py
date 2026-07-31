#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JA3 proxy plugin wrapper."""

from __future__ import annotations

from core.base_plugin import BasePlugin
from proxy.proxy_launcher import JA3ProbeLauncher, JA3ProxyLauncher


class JA3ProxyPlugin(BasePlugin):
    def __init__(self):
        self.launcher = None

    def name(self) -> str:
        return "JA3Proxy"

    def description(self) -> str:
        return "Local SOCKS5 proxy launcher for routing Go tools through browser-like JA3 profiles."

    def check_installed(self) -> bool:
        # The Python relay works without optional utls; utls only controls custom
        # ClientHello construction.  ScannerRouter can still route through it.
        return True

    def run(self, *args, **kwargs):
        action = kwargs.get("action") or (args[0] if args else "status")
        host = kwargs.get("host", "127.0.0.1")
        port = int(kwargs.get("port", 1080))
        profile = kwargs.get("profile", "chrome120")
        profiles_path = kwargs.get("profiles_path")

        if action == "env":
            return JA3ProxyLauncher(host, port, profile, profiles_path).build_env()

        if self.launcher is None:
            self.launcher = JA3ProxyLauncher(host, port, profile, profiles_path)

        if action == "start":
            proc = self.launcher.start()
            return {"started": True, "pid": proc.pid, **self.launcher.status()}
        if action == "stop":
            self.launcher.stop()
            return {"stopped": True, **self.launcher.status()}
        if action == "command":
            return self.launcher.build_command()
        if action == "verify":
            probe = JA3ProbeLauncher(
                profile=profile,
                url=kwargs.get("url", "https://ja3er.com/json"),
                timeout=int(kwargs.get("timeout", 20)),
            )
            proc = probe.run()
            return {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "command": probe.build_command(),
            }
        return self.launcher.status()
