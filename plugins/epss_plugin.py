#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EPSS Plugin — Exploit Prediction Scoring System (FIRST.org)
Truy vấn xác suất khai thác thực tế của CVE từ API miễn phí FIRST.org.
Hỗ trợ batch lookup (tối đa 100 CVE/request) + Cache local 24h.
"""

import os
import json
import time
import logging

from core.base_plugin import BasePlugin

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class EPSSPlugin(BasePlugin):
    """Plugin tra cứu EPSS Score cho CVE từ FIRST.org API (miễn phí)."""

    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'epss_cache')
    CACHE_TTL = 86400  # 24 giờ

    def name(self) -> str:
        return "EPSS"

    def description(self) -> str:
        return "Tra cứu EPSS Score (xác suất bị khai thác) cho CVE từ FIRST.org API"

    def check_installed(self) -> bool:
        return _HAS_REQUESTS

    def run(self, cve_id: str, **kwargs) -> dict:
        """
        Tra cứu EPSS cho một CVE.

        Returns:
            dict: {"cve": "CVE-...", "epss": float, "percentile": float}
        """
        results = self.batch_lookup([cve_id])
        return results.get(cve_id, {"cve": cve_id, "epss": 0.0, "percentile": 0.0})

    def batch_lookup(self, cve_list: list) -> dict:
        """
        Batch lookup EPSS scores cho nhiều CVE cùng lúc.

        Args:
            cve_list: Danh sách CVE IDs (tối đa 100)

        Returns:
            dict: {cve_id: {"cve": str, "epss": float, "percentile": float}}
        """
        if not _HAS_REQUESTS or not cve_list:
            return {}

        # Lọc chỉ giữ CVE ID hợp lệ (bỏ NUCLEI-*, CLOUD-*, DEVOPS-*, etc.)
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

        # Batch API call (chunks of 100)
        for i in range(0, len(uncached), 100):
            chunk = uncached[i:i + 100]
            try:
                params = {"cve": ",".join(chunk)}
                resp = requests.get(self.EPSS_API_URL, params=params, timeout=15)

                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("data", []):
                        cve_id = item.get("cve", "")
                        entry = {
                            "cve": cve_id,
                            "epss": float(item.get("epss", 0.0)),
                            "percentile": float(item.get("percentile", 0.0)),
                        }
                        results[cve_id] = entry
                        self._save_cache(cve_id, entry)
                elif resp.status_code == 429:
                    logging.warning("[EPSS] Rate-limited. Sử dụng cache hoặc thử lại sau.")
                    break
                else:
                    logging.warning(f"[EPSS] API returned {resp.status_code}")
            except requests.exceptions.Timeout:
                logging.warning("[EPSS] API timeout")
            except Exception as e:
                logging.warning(f"[EPSS] Error: {e}")

        # Gán score 0.0 cho CVE không tìm thấy
        for cve in valid_cves:
            if cve not in results:
                results[cve] = {"cve": cve, "epss": 0.0, "percentile": 0.0}

        return results

    # --- Cache helpers ---

    def _cache_key(self, cve_id: str) -> str:
        return f"{cve_id.replace(':', '_').replace('-', '_')}.json"

    def _load_cache(self, cve_id: str):
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
