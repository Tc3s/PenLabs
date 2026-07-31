#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-2 FIX] Shodan Hostname Plugin — Wrapper cho Shodan Host API.

Uses SHODAN_KEY (paid API) to lookup host info by IP or hostname.
DIFFERENT FROM shodan_internetdb_plugin.py which uses InternetDB (free, no key).

Endpoint: https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}

This file was previously a stub/duplicate of shodan_internetdb_plugin.py
(class name was ShodanInternetDBPlugin causing confusion with the canonical
InternetDBPlugin in shodan_internetdb_plugin.py).

After P0-2 fix:
- class ShodanHostnamePlugin: uses api.shodan.io with API key
- backward compat alias: ShodanInternetDBPlugin = InternetDBPlugin
"""

import os
import logging
import time
from typing import Optional, Dict, Any
import requests as _requests
from core.base_plugin import BasePlugin

log = logging.getLogger("ShodanHostname")


class ShodanHostnamePlugin(BasePlugin):
    """
    Plugin truy vấn Shodan Host API cho IP/hostname.

    Yêu cầu: SHODAN_KEY env var hoặc Config.SHODAN_KEY.
    Không giống InternetDBPlugin (free) — đây dùng paid API, có rate limit.
    """

    BASE_URL = "https://api.shodan.io"
    TIMEOUT = 15  # seconds
    # Shodan Host API rate limits: 1 req/sec for free tier, varies for paid
    MIN_REQUEST_INTERVAL = 1.1  # seconds between requests

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        if not self._api_key:
            try:
                from config import Config
                self._api_key = Config.SHODAN_KEY
            except ImportError:
                pass
        self._last_request_time = 0.0
        self._request_count = 0

    def name(self) -> str:
        return "ShodanHostname"

    def description(self) -> str:
        return "Shodan Host API — Lookup IP/hostname với API key (richer data than InternetDB)."

    def check_installed(self) -> bool:
        return bool(self._api_key)

    def _rate_limit(self):
        """Enforce minimum interval giữa các requests để tránh bị Shodan rate-limit."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.MIN_REQUEST_INTERVAL:
            time.sleep(self.MIN_REQUEST_INTERVAL - elapsed)
        self._last_request_time = time.time()

    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Lookup host info. Accepts positional IP/hostname string hoặc kwarg.

        Returns:
            dict with keys: ip, hostnames, ports, os, org, asn, vulns, tags, error
        """
        target = ""
        if args:
            target = str(args[0])
        else:
            target = kwargs.get("ip", "") or kwargs.get("target", "") or kwargs.get("hostname", "")

        if not target:
            return {"error": "no_target", "ip": "", "ports": [], "hostnames": []}

        return self.lookup(target)

    def lookup(self, target: str) -> Dict[str, Any]:
        """
        Truy vấn Shodan Host API cho IP hoặc hostname.

        Args:
            target: IP address (vd: "1.2.3.4") hoặc hostname (vd: "example.com")

        Returns:
            {
                "ip": str,
                "hostnames": [str],
                "ports": [int],
                "os": str,
                "org": str,
                "asn": str,
                "vulns": [str],  # CVE list
                "tags": [str],
                "services": [dict],
                "error": str | None,
            }
        """
        result = {
            "ip": target,
            "hostnames": [],
            "ports": [],
            "os": "",
            "org": "",
            "asn": "",
            "vulns": [],
            "tags": [],
            "services": [],
            "error": None,
        }

        if not self._api_key:
            result["error"] = "no_api_key"
            log.warning("[ShodanHostname] SHODAN_KEY not set — skipping lookup.")
            return result

        self._rate_limit()

        url = f"{self.BASE_URL}/shodan/host/{target}"
        params = {"key": self._api_key, "minify": True}

        try:
            r = _requests.get(url, params=params, timeout=self.TIMEOUT, verify=False)
            self._request_count += 1

            if r.status_code == 200:
                data = r.json()
                result["ip"] = data.get("ip_str", target)
                result["hostnames"] = data.get("hostnames", [])
                result["ports"] = data.get("ports", [])
                result["os"] = data.get("os", "")
                result["org"] = data.get("org", "")
                result["asn"] = data.get("asn", "")
                result["vulns"] = data.get("vulns", [])
                result["tags"] = data.get("tags", [])
                # services (banner data)
                for svc in data.get("data", []):
                    result["services"].append({
                        "port": svc.get("port"),
                        "transport": svc.get("transport", "tcp"),
                        "product": svc.get("product", ""),
                        "version": svc.get("version", ""),
                    })
                log.info(f"[ShodanHostname] {target}: {len(result['ports'])} ports, "
                         f"{len(result['vulns'])} vulns, org={result['org']}")
            elif r.status_code == 401:
                result["error"] = "invalid_api_key"
                log.error("[ShodanHostname] Invalid API key (401)")
            elif r.status_code == 404:
                result["error"] = "no_data"
                log.info(f"[ShodanHostname] {target}: No data (404)")
            elif r.status_code == 429:
                result["error"] = "rate_limited"
                log.warning("[ShodanHostname] Rate limited (429)")
            else:
                result["error"] = f"HTTP {r.status_code}"
                log.warning(f"[ShodanHostname] {target}: HTTP {r.status_code}")
        except _requests.exceptions.Timeout:
            result["error"] = "timeout"
            log.warning(f"[ShodanHostname] {target}: timeout after {self.TIMEOUT}s")
        except Exception as e:
            result["error"] = str(e)
            log.error(f"[ShodanHostname] {target}: {e}")

        return result

    def has_web_ports(self, lookup_result: Dict) -> bool:
        """Check IP có mở port web (80/443) không."""
        web_ports = {80, 443, 8080, 8443}
        return bool(set(lookup_result.get("ports", [])) & web_ports)

    def get_vulns_by_severity(self, lookup_result: Dict, min_severity: str = "HIGH") -> list:
        """
        Lấy CVE list từ kết quả. min_severity filter (best-effort — Shodan không trả CVSS score).
        Trả về list of CVE IDs.
        """
        return lookup_result.get("vulns", [])


# === [P0-2 FIX] Backward compatibility alias ===
# Old code/plugins may have imported ShodanInternetDBPlugin from this file.
# Now that shodan_plugin.py is properly ShodanHostname, alias to the InternetDB plugin
# to avoid breaking existing imports.
try:
    from plugins.shodan_internetdb_plugin import InternetDBPlugin
    ShodanInternetDBPlugin = InternetDBPlugin
except ImportError:
    # If shodan_internetdb_plugin can't be imported, create a stub
    class ShodanInternetDBPlugin(BasePlugin):
        def name(self): return "ShodanInternetDB"
        def description(self): return "Alias stub (shodan_internetdb_plugin not available)"
        def check_installed(self): return False
        def run(self, *args, **kwargs): return {}
