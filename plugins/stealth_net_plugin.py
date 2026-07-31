#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
STEALTH NETWORK PLUGIN (V1.0 — PROXY ROTATION)
Lớp mạng stealth với WAF bypass bằng curl_cffi, Proxy Rotation qua ProxyManager.
"""

import os
import time
import socket
import random
import hashlib
import json
import logging
from urllib.parse import urlparse

from core.base_plugin import BasePlugin
from utils.rate_limiter import OutboundRateLimiter
from utils.proxy_manager import ProxyManager

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    import requests as curl_requests
    HAS_CURL_CFFI = False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class SafeResp:
    """Response wrapper an toàn — không bao giờ throw."""
    def __init__(self, status_code=0, text="", content=b"", headers=None, cookies=None, error=None):
        self.status_code = status_code
        self.text = text or ""
        self.content = content or b""
        self.headers = headers or {}
        self.cookies = cookies or {}
        self.error = error

    def __bool__(self):
        return 200 <= self.status_code < 400 and not self.error

    def json(self):
        try:
            return json.loads(self.text)
        except Exception:
            return {}


class StealthNetPlugin(BasePlugin):
    """
    Plugin cung cấp lớp mạng stealth sử dụng curl_cffi để bypass WAF.
    V1.0: Tích hợp ProxyManager tập trung để xoay IP và quản lý sticky sessions.
    """

    def __init__(self, scan_mode: str = "sniper"):
        self._proxy_enabled = False
        self._is_isolated = (scan_mode == "probe") 

        #  Load routing config from Config.PROXY_ROUTING
        try:
            from config import Config
            self._routing = Config.PROXY_ROUTING.get(
                scan_mode, {"mode": "fast-proxy", "delay": 0.5, "pool_size": 10}
            )
            # [FIX] Kết nối Config.JA3_SPOOF_ENABLED vào logic JA3
            # Chỉ bật JA3 khi CẢ HAI điều kiện thỏa: curl_cffi có sẵn VÀ user bật trong TUI
            self._ja3_enabled = HAS_CURL_CFFI and getattr(Config, 'JA3_SPOOF_ENABLED', True)
        except ImportError:
            self._routing = {"mode": "fast-proxy", "delay": 0.5, "pool_size": 10}
            self._ja3_enabled = HAS_CURL_CFFI
        self._scan_mode = scan_mode

        # Centralized Proxy Manager
        self.proxy_mgr = ProxyManager()

        #  Connection pooling — reuse TCP connections
        self._session = None
        self._init_session()

    def _init_session(self):
        """Initialize HTTP session with connection pooling."""
        pool_size = self._routing.get("pool_size", 10)

        if self._ja3_enabled:
            try:
                self._session = curl_requests.Session()
            except Exception:
                self._session = None
        else:
            try:
                import requests
                from requests.adapters import HTTPAdapter
                self._session = requests.Session()
                adapter = HTTPAdapter(
                    pool_connections=pool_size,
                    pool_maxsize=pool_size,
                    max_retries=0,
                )
                self._session.mount("http://", adapter)
                self._session.mount("https://", adapter)
                self._session.verify = False
            except Exception:
                self._session = None

    def name(self) -> str:
        return "StealthNet"

    def description(self) -> str:
        return "Stealth HTTP client với JA3 spoofing và Proxy Rotation tập trung."

    def check_installed(self) -> bool:
        return self._session is not None

    def check_waf(self, target_url: str) -> tuple[bool, str]:
        """
        [V1.0-FIX] Bridge method to call WAFAnalyzerEngine.
        """
        try:
            from core.waf_analyzer import WAFAnalyzerEngine
            analyzer = WAFAnalyzerEngine(proxy_mode="probe")
            strategy = analyzer.analyze(target_url)
            return strategy.waf_detected, strategy.waf_name
        except Exception as e:
            logging.error(f"[StealthNet] Error during WAF detection: {e}")
            return False, "None"

    def get_tls_fp(self, target_host: str) -> str:
        """
        [P1-1] Return the configured JA3 profile metadata for curl_cffi
        impersonation. curl_cffi does not expose the live ClientHello hash, so
        PenLabs records the expected profile hash used by the matching request
        path (`impersonate=chrome120`).
        """
        if self._ja3_enabled:
            try:
                from config import Config
                from proxy.ja3_proxy import JA3ProfileStore
                profile_name = getattr(Config, "JA3_PROFILE", "chrome120") or "chrome120"
                profile = JA3ProfileStore().get(profile_name) or JA3ProfileStore().get("chrome120")
                ja3_hash = profile.get("ja3_hash", "cd08e31494f9531f560d64c695473da9")
                return f"ja3:impersonate=chrome120,profile={profile_name},hash={ja3_hash},target={target_host}"
            except Exception as e:
                logging.debug(f"[StealthNet] get_tls_fp error: {e}")
                return "ja3:unknown"
        if HAS_CURL_CFFI and not self._ja3_enabled:
            return "JA3 Spoof DISABLED by user (curl_cffi available but toggled OFF)"
        return "Generic Python Requests (No JA3 Spoof)"

    def run(self, *args, **kwargs):
        """Khởi tạo engine."""
        self._proxy_enabled = kwargs.get("proxy", False)
        if args and isinstance(args[0], bool):
            self._proxy_enabled = args[0]
            
        routing_mode = self._routing.get("mode", "direct")
        if routing_mode == "tor" and not self._proxy_enabled:
            self._proxy_enabled = True
                        
        if not self._ja3_enabled:
            if HAS_CURL_CFFI:
                logging.info("[StealthNet] JA3 spoofing DISABLED by user toggle. Dùng requests thường.")
            else:
                logging.warning("[StealthNet] curl_cffi chưa được cài đặt. Đang dùng requests thường.")

    def get(self, url, timeout=15, headers=None, allow_redirects=True):
        return self._request("GET", url, timeout, headers, allow_redirects=allow_redirects)

    def smart_get(self, url, timeout=15, headers=None, max_hops=3):
        current_url = url
        hops = 0
        while hops < max_hops:
            resp = self.get(current_url, timeout=timeout, headers=headers, allow_redirects=False)
            if resp.status_code == 200:
                return resp
            if resp.status_code in [301, 302, 303, 307, 308]:
                new_loc = resp.headers.get("Location", "")
                if not new_loc: return resp
                if new_loc.startswith("/"):
                    from urllib.parse import urljoin
                    new_loc = urljoin(current_url, new_loc)
                loc_lower = new_loc.lower()
                block_keywords = ["login", "signin", "auth", "sso", "identity", "account/index", "verify"]
                if any(k in loc_lower for k in block_keywords):
                    return resp
                current_url = new_loc
                hops += 1
                continue
            return resp
        return SafeResp(error=f"Smart-Follow: Max hops reached")

    def post(self, url, timeout=15, headers=None, json_data=None):
        return self._request("POST", url, timeout, headers, json_data)

    def _get_proxy_dict(self, target_host: str):
        if not self._proxy_enabled:
            return None
            
        sticky_key = target_host
        if self._is_isolated:
            sticky_key = f"isolated_{target_host}"

        p = self.proxy_mgr.get_proxy(sticky_key=sticky_key)
        if not p:
            if self._routing.get("mode") == "tor":
                p = "socks5h://127.0.0.1:9050"
            else:
                return None
        return {"http": p, "https": p}

    def _request(self, method, url, timeout=15, headers=None, json_data=None, allow_redirects=True):
        try:
            target_host = urlparse(url).netloc
        except Exception:
            target_host = "unknown"
            
        proxies = self._get_proxy_dict(target_host)
        current_proxy = proxies["http"] if proxies else None
        
        from utils.ua_rotator import get_random_headers
        final_headers = get_random_headers()
        if headers:
            final_headers.update(headers)
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                time.sleep(random.uniform(0.1, 0.5))
                if attempt > 0:
                    time.sleep((2 ** attempt) + random.uniform(0, 1))

                kwargs = {
                    "timeout": timeout,
                    "proxies": proxies,
                    "headers": final_headers,
                    "verify": False,
                    "allow_redirects": allow_redirects
                }
                
                #  Support raw data (bytes) or JSON
                if json_data is not None:
                    if isinstance(json_data, (bytes, str)):
                        kwargs["data"] = json_data
                    else:
                        kwargs["json"] = json_data
                    
                if self._ja3_enabled:
                    kwargs["impersonate"] = "chrome120"
                    kwargs["http_version"] = 3
                
                OutboundRateLimiter().wait()
                mode_delay = self._routing.get("delay", 0.5)
                if mode_delay > 0: time.sleep(mode_delay)
                
                if self._session is not None:
                    r = self._session.request(method, url, **kwargs)
                else:
                    r = curl_requests.request(method, url, **kwargs)
                
                if r.status_code == 407:
                    logging.warning(f"[StealthNet] Proxy Auth Failed for {current_proxy}. Evicting...")
                    if current_proxy: self.proxy_mgr.report_dead(current_proxy)
                    proxies = self._get_proxy_dict(target_host)
                    current_proxy = proxies["http"] if proxies else None
                    continue

                if r.status_code not in [429, 403, 503]:
                    return SafeResp(
                        status_code=r.status_code, text=r.text, content=r.content, 
                        headers=dict(r.headers), cookies=dict(r.cookies)
                    )
                else:
                    backoff_delay = 2.0 * (attempt + 1) + random.uniform(0.5, 1.5)
                    logging.warning(f"[StealthNet] Adaptive Evasion: Received HTTP {r.status_code} for {url}. Sleeping {backoff_delay:.1f}s...")
                    time.sleep(backoff_delay)

            except Exception as e:
                logging.debug(f"Request failed for {url}: {e}")

        return SafeResp(error="Max retries reached")
