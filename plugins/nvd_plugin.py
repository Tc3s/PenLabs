#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NVD Plugin — NIST National Vulnerability Database API 2.0
Tra cứu CVSS v3.1 scores, vectors, severity cho CVE.
Batch lookup + 24h local cache.
"""

import os
import json
import time
import logging
from typing import Optional

from core.base_plugin import BasePlugin

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class NVDPlugin(BasePlugin):
    """Plugin tra cứu CVSS scores từ NVD API 2.0 (NIST)."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'nvd_cache')
    CACHE_TTL = 86400  # 24 giờ

    def name(self) -> str:
        return "NVD"

    def description(self) -> str:
        return "Tra cứu CVSS v3.1 scores, vectors, severity từ NIST NVD API 2.0"

    def check_installed(self) -> bool:
        return _HAS_REQUESTS

    def run(self, cve_id: str, **kwargs) -> dict:
        """
        Tra cứu CVSS cho một CVE.

        Returns:
            dict: {"cve": str, "cvss_score": float, "cvss_vector": str, "cvss_severity": str}
        """
        results = self.batch_lookup([cve_id])
        return results.get(cve_id, self._empty_result(cve_id))

    def batch_lookup(self, cve_list: list) -> dict:
        """
        Batch lookup CVSS scores cho nhiều CVE.
        NVD API rate limit: 5 req/30s (no key) hoặc 50 req/30s (with key).

        Args:
            cve_list: Danh sách CVE IDs

        Returns:
            dict: {cve_id: {"cve": str, "cvss_score": float, "cvss_vector": str, "cvss_severity": str}}
        """
        if not _HAS_REQUESTS or not cve_list:
            return {}

        # Lọc chỉ CVE hợp lệ
        valid_cves = [c for c in cve_list if c.startswith("CVE-")]
        if not valid_cves:
            return {}

        results = {}

        # Check cache trước
        uncached = []
        for cve in valid_cves:
            cached = self._load_cache(cve)
            if cached is not None:
                results[cve] = cached
            else:
                uncached.append(cve)

        if not uncached:
            return results

        # Load API key từ Config
        api_key = ""
        try:
            from config import Config
            api_key = Config.NVD_API_KEY
        except (ImportError, AttributeError):
            pass

        # NVD API: 1 CVE per request (API 2.0 hỗ trợ cveId parameter)
        headers = {}
        if api_key:
            headers["apiKey"] = api_key

        # Base delay: 6s/req (no key, ~5 req/30s) or 0.6s/req (with key, ~50 req/30s)
        base_delay = 6.0 if not api_key else 0.6
        max_retries = 3

        # [FIX-1] Process in chunks of 10 with inter-batch cooldown
        chunk_size = 10
        for chunk_start in range(0, len(uncached), chunk_size):
            chunk = uncached[chunk_start:chunk_start + chunk_size]

            for cve_id in chunk:
                entry = self._fetch_single_cve(cve_id, headers, base_delay, max_retries)
                if entry:
                    results[cve_id] = entry
                    self._save_cache(cve_id, entry)

            # Inter-batch cooldown (longer pause between chunks to avoid 429)
            if chunk_start + chunk_size < len(uncached):
                cooldown = 10.0 if not api_key else 2.0
                logging.info(f"[NVD] Batch cooldown {cooldown}s before next {chunk_size} CVEs...")
                time.sleep(cooldown)

        # Gán empty result cho CVE không tìm thấy
        for cve in valid_cves:
            if cve not in results:
                results[cve] = self._empty_result(cve)

        return results

    def _fetch_single_cve(self, cve_id: str, headers: dict,
                          base_delay: float, max_retries: int) -> dict:
        """
        [FIX-1] Fetch a single CVE with exponential backoff retry on 429/403.
        Returns parsed entry dict or None.
        """
        for attempt in range(1, max_retries + 1):
            try:
                params = {"cveId": cve_id}
                resp = requests.get(self.NVD_API_URL, params=params,
                                    headers=headers, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    entry = self._parse_cvss(cve_id, data)
                    time.sleep(base_delay)
                    return entry

                elif resp.status_code == 404:
                    entry = self._empty_result(cve_id)
                    time.sleep(base_delay)
                    return entry

                elif resp.status_code in (429, 403):
                    # Exponential backoff: 2s → 4s → 8s
                    backoff = (2 ** attempt)
                    logging.warning(
                        f"[NVD] Rate-limited ({resp.status_code}) for {cve_id}. "
                        f"Retry {attempt}/{max_retries} in {backoff}s..."
                    )
                    time.sleep(backoff)
                    continue  # retry

                else:
                    logging.warning(f"[NVD] API returned {resp.status_code} for {cve_id}")
                    time.sleep(base_delay)
                    return self._empty_result(cve_id)

            except requests.exceptions.Timeout:
                logging.warning(f"[NVD] Timeout for {cve_id} (attempt {attempt}/{max_retries})")
                time.sleep(2 ** attempt)
            except Exception as e:
                logging.warning(f"[NVD] Error for {cve_id}: {e}")
                return self._empty_result(cve_id)

        logging.warning(f"[NVD] All {max_retries} retries exhausted for {cve_id}")
        return self._empty_result(cve_id)

    def _parse_cvss(self, cve_id: str, data: dict) -> dict:
        """Parse CVSS data từ NVD API 2.0 response."""
        try:
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return self._empty_result(cve_id)

            cve_data = vulns[0].get("cve", {})
            metrics = cve_data.get("metrics", {})

            # Ưu tiên CVSS v3.1, fallback v3.0, v2.0
            cvss_data = None
            for key in ["cvssMetricV31", "cvssMetricV30"]:
                if key in metrics and metrics[key]:
                    cvss_data = metrics[key][0].get("cvssData", {})
                    break

            if cvss_data:
                return {
                    "cve": cve_id,
                    "cvss_score": float(cvss_data.get("baseScore", 0.0)),
                    "cvss_vector": cvss_data.get("vectorString", ""),
                    "cvss_severity": cvss_data.get("baseSeverity", "UNKNOWN"),
                }

            # Fallback CVSS v2.0
            if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                v2_data = metrics["cvssMetricV2"][0].get("cvssData", {})
                return {
                    "cve": cve_id,
                    "cvss_score": float(v2_data.get("baseScore", 0.0)),
                    "cvss_vector": v2_data.get("vectorString", ""),
                    "cvss_severity": "MEDIUM",  # V1.0 doesn't have baseSeverity
                }

        except Exception as e:
            logging.debug(f"[NVD] Parse error for {cve_id}: {e}")

        return self._empty_result(cve_id)

    @staticmethod
    def _empty_result(cve_id: str) -> dict:
        return {"cve": cve_id, "cvss_score": 0.0, "cvss_vector": "", "cvss_severity": "UNKNOWN"}

    # --- Cache helpers ---

    def _cache_key(self, cve_id: str) -> str:
        return f"{cve_id.replace(':', '_').replace('-', '_')}.json"

    def _load_cache(self, cve_id: str) -> Optional[dict]:
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        cache_file = os.path.join(self.CACHE_DIR, self._cache_key(cve_id))
        if os.path.exists(cache_file):
            try:
                if time.time() - os.path.getmtime(cache_file) < self.CACHE_TTL:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
            except Exception:
                pass
        return None

    def _save_cache(self, cve_id: str, data: dict):
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        cache_file = os.path.join(self.CACHE_DIR, self._cache_key(cve_id))
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f)
        except Exception:
            pass
