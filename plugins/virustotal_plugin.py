#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-2 FIX] VirusTotal Plugin — Lookup IP/file/URL/domain reputation.

Uses VT_API_KEY (paid API). Free tier: 4 req/min, 500 req/day.
Production keys: 4 req/sec, varies by plan.

Why this rewrite:
- Original (25 lines) had no retry, no rate limit, no cache.
- 429 responses silently returned {} → false negatives.
- This rewrite: rate limit tracking, exponential backoff retry, simple cache.

Usage:
    from plugins.virustotal_plugin import VirusTotalPlugin
    vt = VirusTotalPlugin(api_key="xxx")
    result = vt.lookup_ip("8.8.8.8")
    result = vt.lookup_hash("d41d8cd98f00b204e9800998ecf8427e")
    result = vt.lookup_url("http://example.com/malware.exe")
"""

import os
import time
import json
import logging
import hashlib
from typing import Optional, Dict, Any
from urllib.parse import quote
from datetime import datetime, timedelta
import requests as _requests
from core.base_plugin import BasePlugin

log = logging.getLogger("VirusTotal")


class VirusTotalPlugin(BasePlugin):
    """
    Plugin truy vấn VirusTotal API v3 cho IP/file/URL/domain reputation.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"
    # Free tier: 4 req/min. Production: 4 req/sec or higher.
    # Use conservative 16s interval = ~4 req/min for safety.
    DEFAULT_RATE_LIMIT_SECONDS = 16.0
    MAX_RETRIES = 4
    CACHE_TTL_HOURS = 24

    # Simple in-memory cache (per-process). Key: query_hash, Value: (result, expires_at)
    _cache: Dict[str, tuple] = {}

    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key
        if not self._api_key:
            try:
                from config import Config
                self._api_key = Config.VT_API_KEY
            except ImportError:
                pass
        self._last_request_time = 0.0
        self._session = _requests.Session()

    def name(self) -> str:
        return "VirusTotal"

    def description(self) -> str:
        return "OSINT Plugin truy vấn VirusTotal API v3 — IP/Hash/URL/Domain reputation."

    def check_installed(self) -> bool:
        return bool(self._api_key)

    def _rate_limit(self):
        """Enforce minimum interval giữa các requests để tránh bị VT rate-limit."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self.DEFAULT_RATE_LIMIT_SECONDS:
            wait = self.DEFAULT_RATE_LIMIT_SECONDS - elapsed
            log.debug(f"[VirusTotal] Rate limit: sleeping {wait:.1f}s")
            time.sleep(wait)
        self._last_request_time = time.time()

    def _cache_key(self, endpoint: str, identifier: str) -> str:
        """Generate cache key."""
        raw = f"{endpoint}:{identifier}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _cache_get(self, key: str) -> Optional[Dict]:
        """Get cached result nếu chưa expire."""
        if key not in self._cache:
            return None
        result, expires_at = self._cache[key]
        if datetime.now() > expires_at:
            del self._cache[key]
            return None
        return result

    def _cache_set(self, key: str, result: Dict, ttl_hours: float = CACHE_TTL_HOURS):
        """Cache result với TTL (default 24h, configurable per-call)."""
        expires_at = datetime.now() + timedelta(hours=ttl_hours)
        self._cache[key] = (result, expires_at)

    def _request_with_retry(self, url: str, headers: Dict, timeout: int = 15) -> Optional[Dict]:
        """
        Make API request với exponential backoff retry.

        Handles:
        - 200: return JSON
        - 204: No content (legit but no data)
        - 429: Rate limited → check Retry-After header → backoff
        - 401: Invalid API key → fail immediately
        - 404: Not found → return None
        - Timeout/Network errors: retry with backoff
        """
        if not self._api_key:
            log.warning("[VirusTotal] VT_API_KEY not set — skipping lookup.")
            return None

        for attempt in range(self.MAX_RETRIES):
            self._rate_limit()

            try:
                resp = self._session.get(url, headers=headers, timeout=timeout, verify=False)

                if resp.status_code == 200:
                    return resp.json()
                elif resp.status_code == 204:
                    log.debug(f"[VirusTotal] {url}: 204 No Content")
                    return {"_no_content": True}
                elif resp.status_code == 401:
                    log.error("[VirusTotal] Invalid API key (401)")
                    return None
                elif resp.status_code == 404:
                    log.debug(f"[VirusTotal] {url}: 404 Not Found")
                    return None
                elif resp.status_code == 429:
                    # Rate limited — check Retry-After
                    retry_after = resp.headers.get("Retry-After", "60")
                    try:
                        wait_seconds = int(retry_after)
                    except (ValueError, TypeError):
                        wait_seconds = 60
                    wait_seconds = min(wait_seconds, 300)  # Cap at 5 min
                    log.warning(f"[VirusTotal] Rate limited (429). Sleeping {wait_seconds}s "
                              f"(attempt {attempt + 1}/{self.MAX_RETRIES})")
                    time.sleep(wait_seconds)
                    continue  # retry
                elif resp.status_code >= 500:
                    # Server error — retry with backoff
                    backoff = 2 ** attempt + (attempt * 0.5)
                    log.warning(f"[VirusTotal] Server error {resp.status_code}. "
                              f"Retry in {backoff:.1f}s (attempt {attempt + 1}/{self.MAX_RETRIES})")
                    time.sleep(backoff)
                    continue
                else:
                    log.warning(f"[VirusTotal] Unexpected HTTP {resp.status_code}")
                    return None

            except _requests.exceptions.Timeout:
                backoff = 2 ** attempt + (attempt * 0.5)
                log.warning(f"[VirusTotal] Timeout. Retry in {backoff:.1f}s "
                          f"(attempt {attempt + 1}/{self.MAX_RETRIES})")
                time.sleep(backoff)
            except _requests.exceptions.ConnectionError as e:
                backoff = 2 ** attempt + (attempt * 0.5)
                log.warning(f"[VirusTotal] Connection error: {e}. Retry in {backoff:.1f}s")
                time.sleep(backoff)
            except Exception as e:
                log.error(f"[VirusTotal] Unexpected error: {e}")
                return None

        log.error(f"[VirusTotal] Max retries ({self.MAX_RETRIES}) exhausted for {url}")
        return None

    def run(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Lookup VT data. Accepts:
        - positional: ip, hash, url, domain (detect by format)
        - kwargs: ip=, hash=, url=, domain=

        Returns:
            dict with keys: found, malicious, suspicious, harmless, undetected,
                            reputation (for IP), detected_urls (for hash),
                            country, asn, as_owner (for IP), etc.
        """
        target = ""
        if args:
            target = str(args[0])
        else:
            for key in ["ip", "hash", "url", "domain"]:
                if kwargs.get(key):
                    target = kwargs[key]
                    break

        if not target:
            return {"_error": "no_target"}

        # Auto-detect type
        if self._is_valid_ip(target):
            return self.lookup_ip(target)
        elif self._is_valid_hash(target):
            return self.lookup_hash(target)
        elif target.startswith("http://") or target.startswith("https://"):
            return self.lookup_url(target)
        else:
            return self.lookup_domain(target)

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """
        Lookup IP address reputation.

        Returns:
            {
                "found": bool,
                "malicious": int,  # count of malicious detections
                "suspicious": int,
                "harmless": int,
                "undetected": int,
                "country": str,
                "asn": int,
                "as_owner": str,
                "reputation": int,
                "_error": str (nếu có),
            }
        """
        cache_key = self._cache_key("ip", ip)
        cached = self._cache_get(cache_key)
        if cached is not None:
            log.debug(f"[VirusTotal] Cache HIT for IP {ip}")
            return cached

        if not self._api_key:
            return {"_error": "no_api_key", "found": False}

        url = f"{self.BASE_URL}/ip_addresses/{ip}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        data = self._request_with_retry(url, headers)

        if data is None:
            result = {"_error": "request_failed", "found": False, "ip": ip}
        elif data.get("_no_content"):
            result = {"_error": "no_content", "found": False, "ip": ip}
        else:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "found": True,
                "ip": ip,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "country": attrs.get("country", ""),
                "asn": attrs.get("asn", 0),
                "as_owner": attrs.get("as_owner", ""),
                "reputation": attrs.get("reputation", 0),
                "network": attrs.get("network", ""),
            }

        # [P0-2.1 FIX] Only cache SUCCESSFUL lookups (found=True) or ERRORs with short TTL
        # Old bug: cached negative results (found=False, malicious=0) for 24h, missing new detections
        if result.get("found"):
            self._cache_set(cache_key, result, ttl_hours=self.CACHE_TTL_HOURS)
        elif result.get("_error"):
            self._cache_set(cache_key, result, ttl_hours=5/60)  # 5 minutes for errors
        return result

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Lookup file hash (MD5/SHA1/SHA256).

        Returns:
            {
                "found": bool,
                "malicious": int,
                "suspicious": int,
                "harmless": int,
                "undetected": int,
                "name": str,
                "type_description": str,
                "size": int,
                "detection_engines": [str],  # List of engines that flagged as malicious
                "_error": str,
            }
        """
        file_hash = file_hash.strip().lower()
        if not self._is_valid_hash(file_hash):
            return {"_error": "invalid_hash_format", "found": False, "hash": file_hash}

        cache_key = self._cache_key("hash", file_hash)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        if not self._api_key:
            return {"_error": "no_api_key", "found": False}

        url = f"{self.BASE_URL}/files/{file_hash}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        data = self._request_with_retry(url, headers)

        if data is None:
            result = {"_error": "request_failed", "found": False, "hash": file_hash}
        elif data.get("_no_content"):
            result = {"_error": "no_content", "found": False, "hash": file_hash}
        else:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            # Collect engines that flagged malicious
            engines = [
                engine for engine, result_info in attrs.get("last_analysis_results", {}).items()
                if result_info.get("category") == "malicious"
            ]
            result = {
                "found": True,
                "hash": file_hash,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "name": attrs.get("name", ""),
                "type_description": attrs.get("type_description", ""),
                "size": attrs.get("size", 0),
                "detection_engines": engines[:20],  # Top 20
                "popular_threat_label": attrs.get("popular_threat_classification", {}).get(
                    "suggested_threat_label", ""
                ),
            }

        # [P0-2.1 FIX] Only cache SUCCESSFUL lookups or ERRORs with short TTL
        if result.get("found"):
            self._cache_set(cache_key, result, ttl_hours=self.CACHE_TTL_HOURS)
        elif result.get("_error"):
            self._cache_set(cache_key, result, ttl_hours=5/60)
        return result

    def lookup_url(self, url: str) -> Dict[str, Any]:
        """
        Lookup URL reputation. Note: VT v3 URL API uses SHA256 hex of URL as identifier
        (NOT base64 — that was v2 API).

        Returns:
            {
                "found": bool,
                "malicious": int,
                "suspicious": int,
                "harmless": int,
                "undetected": int,
                "_error": str,
            }
        """
        if not self._api_key:
            return {"_error": "no_api_key", "found": False, "url": url}

        # VT URL identifier = SHA256 hex of URL (NOT base64)
        url_id = hashlib.sha256(url.encode("utf-8")).hexdigest()
        cache_key = self._cache_key("url", url_id)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        api_url = f"{self.BASE_URL}/urls/{url_id}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        data = self._request_with_retry(api_url, headers)

        if data is None or data.get("_no_content"):
            result = {"_error": "not_found", "found": False, "url": url}
        else:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "found": True,
                "url": url,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            }

        # [P0-2.1 FIX] Only cache SUCCESSFUL lookups (found=True) or ERRORs with short TTL
        # Old bug: cached negative results (found=False, malicious=0) for 24h, missing new detections
        if result.get("found"):
            self._cache_set(cache_key, result, ttl_hours=self.CACHE_TTL_HOURS)
        elif result.get("_error"):
            self._cache_set(cache_key, result, ttl_hours=5/60)  # 5 minutes for errors
        return result

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Lookup domain reputation."""
        domain = domain.strip().lower()
        if not self._api_key:
            return {"_error": "no_api_key", "found": False, "domain": domain}

        cache_key = self._cache_key("domain", domain)
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        url = f"{self.BASE_URL}/domains/{domain}"
        headers = {"x-apikey": self._api_key, "Accept": "application/json"}
        data = self._request_with_retry(url, headers)

        if data is None or data.get("_no_content"):
            result = {"_error": "not_found", "found": False, "domain": domain}
        else:
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            result = {
                "found": True,
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "reputation": attrs.get("reputation", 0),
                "categories": attrs.get("categories", {}),
            }

        # [P0-2.1 FIX] Only cache SUCCESSFUL lookups or ERRORs with short TTL
        if result.get("found"):
            self._cache_set(cache_key, result, ttl_hours=self.CACHE_TTL_HOURS)
        elif result.get("_error"):
            self._cache_set(cache_key, result, ttl_hours=5/60)
        return result

    @staticmethod
    def _is_valid_ip(s: str) -> bool:
        """Check if string is valid IPv4 or IPv6."""
        import ipaddress
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _is_valid_hash(s: str) -> bool:
        """Check if string is MD5/SHA1/SHA256 hash."""
        s = s.strip().lower()
        return len(s) in (32, 40, 64) and all(c in "0123456789abcdef" for c in s)
