#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NVD CPE Lookup Plugin — Enrichment CVE data từ NVD (National Vulnerability Database).
Sử dụng NVD API 2.0 để tra cứu CVE theo CPE name.
Có cache local để giảm API calls.
"""

import os
import sys
import json
import time
import logging

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.base_plugin import BasePlugin

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


class NvdCpePlugin(BasePlugin):
    """Plugin tra cứu CVE từ NVD API 2.0 qua CPE name."""

    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'nvd_cache')
    CACHE_TTL = 86400 * 7  # 7 ngày

    def name(self) -> str:
        return "NvdCPE"

    def description(self) -> str:
        return "Tra cứu CVE từ NVD API 2.0 theo CPE name, có cache local"

    def check_installed(self) -> bool:
        return _HAS_REQUESTS

    def run(self, cpe_name: str, max_results: int = 10, **kwargs) -> list:
        """
        Tra cứu CVE cho một CPE name.
        
        Args:
            cpe_name: CPE 2.3 string (VD: cpe:2.3:a:apache:http_server:2.4.49:*)
            max_results: Số CVE tối đa trả về
            
        Returns:
            List of dict: [{"cve_id": "CVE-...", "description": "...", "severity": "...", "score": float}]
        """
        if not _HAS_REQUESTS:
            logging.warning("[NvdCPE] requests library not available")
            return []

        # Check cache trước
        cached = self._load_cache(cpe_name)
        if cached is not None:
            return cached[:max_results]

        # Gọi NVD API
        try:
            params = {
                "cpeName": cpe_name,
                "resultsPerPage": min(max_results, 50),
            }
            headers = {"Accept": "application/json"}
            
            resp = requests.get(self.NVD_API_URL, params=params, headers=headers, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                results = self._parse_nvd_response(data)
                self._save_cache(cpe_name, results)
                return results[:max_results]
            elif resp.status_code == 403:
                logging.warning("[NvdCPE] NVD API rate-limited (403). Dùng cache hoặc thử lại sau.")
                return []
            else:
                logging.warning(f"[NvdCPE] NVD API returned {resp.status_code}")
                return []
        except requests.exceptions.Timeout:
            logging.warning("[NvdCPE] NVD API timeout")
            return []
        except Exception as e:
            logging.warning(f"[NvdCPE] Error querying NVD: {e}")
            return []

    def _parse_nvd_response(self, data: dict) -> list:
        """Parse NVD API 2.0 response."""
        results = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            
            # Description
            desc = ""
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            
            # CVSS Score
            score = 0.0
            severity = "UNKNOWN"
            metrics = cve_data.get("metrics", {})
            
            # Try CVSS 3.1 first, then 3.0, then 2.0
            for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                metric_list = metrics.get(metric_key, [])
                if metric_list:
                    cvss = metric_list[0].get("cvssData", {})
                    score = cvss.get("baseScore", 0.0)
                    severity = cvss.get("baseSeverity", "UNKNOWN")
                    break
            
            results.append({
                "cve_id": cve_id,
                "description": desc[:200],  # Truncate
                "severity": severity,
                "score": score,
            })
        
        return results

    def _cache_key(self, cpe_name: str) -> str:
        """Tạo filename an toàn từ CPE name."""
        safe = cpe_name.replace(":", "_").replace("*", "star").replace("/", "_")
        return f"{safe}.json"

    def _load_cache(self, cpe_name: str) -> list | None:
        """Load kết quả từ cache nếu còn hạn."""
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        cache_file = os.path.join(self.CACHE_DIR, self._cache_key(cpe_name))
        
        if os.path.exists(cache_file):
            try:
                mtime = os.path.getmtime(cache_file)
                if time.time() - mtime < self.CACHE_TTL:
                    with open(cache_file, 'r') as f:
                        return json.load(f)
            except Exception:
                pass
        return None

    def _save_cache(self, cpe_name: str, results: list):
        """Lưu kết quả vào cache."""
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        cache_file = os.path.join(self.CACHE_DIR, self._cache_key(cpe_name))
        try:
            with open(cache_file, 'w') as f:
                json.dump(results, f, indent=2)
        except Exception:
            pass
