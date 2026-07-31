#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shodan InternetDB Plugin — Passive Intelligence (No API Key).
Truy vấn https://internetdb.shodan.io/{ip} để lấy ports, hostnames, vulns, tags.
"""

import logging
from typing import Optional, Dict, List
from core.base_plugin import BasePlugin

log = logging.getLogger("InternetDB")


class InternetDBPlugin(BasePlugin):
    """
    Plugin truy vấn Shodan InternetDB — nguồn tình báo passive miễn phí.
    Không cần API Key. Trả về ports, hostnames, tags, vulns cho một IP.
    """

    def __init__(self):
        self._http = None
        try:
            from plugins.stealth_net_plugin import StealthNetPlugin
            self._http = StealthNetPlugin()
            self._http.run()
        except ImportError:
            pass

    def name(self) -> str:
        return "ShodanInternetDB"

    def description(self) -> str:
        return "Shodan InternetDB — Passive port/hostname/vuln lookup (No API Key)."

    def check_installed(self) -> bool:
        return self._http is not None

    def run(self, *args, **kwargs):
        """Alias cho lookup()."""
        if args:
            return self.lookup(str(args[0]))
        ip = kwargs.get("ip", "")
        if ip:
            return self.lookup(ip)
        return {}

    def lookup(self, ip: str) -> Dict:
        """
        Truy vấn InternetDB cho một IP.

        Returns:
            {
                "ip": str,
                "ports": [int],
                "hostnames": [str],
                "tags": [str],
                "vulns": [str],
                "cpes": [str],
                "error": str | None,
            }
        """
        result = {
            "ip": ip,
            "ports": [],
            "hostnames": [],
            "tags": [],
            "vulns": [],
            "cpes": [],
            "error": None,
        }

        url = f"https://internetdb.shodan.io/{ip}"
        log.info(f"[InternetDB] Querying {url}")

        if not self._http:
            # Fallback nếu StealthNet không có
            try:
                import requests
                r = requests.get(url, timeout=10, verify=False)
                if r.status_code == 200:
                    data = r.json()
                elif r.status_code == 404:
                    log.info(f"[InternetDB] {ip}: No data available (404).")
                    result["error"] = "no_data"
                    return result
                else:
                    result["error"] = f"HTTP {r.status_code}"
                    return result
            except Exception as e:
                result["error"] = str(e)
                return result
        else:
            resp = self._http.get(url, timeout=10)
            if not resp or resp.error:
                result["error"] = resp.error if resp else "request_failed"
                return result
            if resp.status_code == 404:
                log.info(f"[InternetDB] {ip}: No data available (404).")
                result["error"] = "no_data"
                return result
            if resp.status_code != 200:
                result["error"] = f"HTTP {resp.status_code}"
                return result
            data = resp.json()

        # Parse response
        result["ports"] = data.get("ports", [])
        result["hostnames"] = data.get("hostnames", [])
        result["tags"] = data.get("tags", [])
        result["vulns"] = data.get("vulns", [])
        result["cpes"] = data.get("cpes", [])

        log.info(f"[InternetDB] {ip}: {len(result['ports'])} ports, "
                 f"{len(result['hostnames'])} hostnames, "
                 f"{len(result['vulns'])} vulns")

        return result

    def has_web_ports(self, lookup_result: Dict) -> bool:
        """Kiểm tra IP có mở port web (80/443) không."""
        web_ports = {80, 443, 8080, 8443}
        return bool(set(lookup_result.get("ports", [])) & web_ports)

    def hostname_matches(self, lookup_result: Dict, domain: str) -> bool:
        """Kiểm tra domain có trong danh sách hostnames không."""
        hostnames = lookup_result.get("hostnames", [])
        for h in hostnames:
            if domain in h or h.endswith(f".{domain}"):
                return True
        return False
