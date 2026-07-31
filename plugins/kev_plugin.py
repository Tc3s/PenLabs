#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CISA KEV Plugin — Known Exploited Vulnerabilities Catalog
Kiểm tra CVE có đang bị khai thác trong thực tế hay không (CISA KEV).
Download catalog 1 lần, cache local 7 ngày.
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


class CISAKEVPlugin(BasePlugin):
    """Plugin kiểm tra CVE trong CISA Known Exploited Vulnerabilities catalog."""

    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    CACHE_DIR = os.path.join(os.path.dirname(__file__), '..', 'data', 'kev_cache')
    CACHE_FILE = "kev_catalog.json"
    CACHE_TTL = 86400 * 7  # 7 ngày

    def name(self) -> str:
        return "CISAKEV"

    def description(self) -> str:
        return "Kiểm tra CVE trong CISA Known Exploited Vulnerabilities catalog (đang bị khai thác thực tế)"

    def check_installed(self) -> bool:
        return _HAS_REQUESTS

    def run(self, cve_id: str, **kwargs) -> dict:
        """
        Kiểm tra 1 CVE có nằm trong KEV catalog không.

        Returns:
            dict: {"cve": str, "is_kev": bool, "kev_due_date": str, "kev_notes": str}
        """
        result = self.batch_check([cve_id])
        return result.get(cve_id, {"cve": cve_id, "is_kev": False, "kev_due_date": "", "kev_notes": ""})

    def batch_check(self, cve_list: list) -> dict:
        """
        Batch check nhiều CVE trong KEV catalog.

        Args:
            cve_list: Danh sách CVE IDs

        Returns:
            dict: {cve_id: {"cve": str, "is_kev": bool, "kev_due_date": str, "kev_notes": str}}
        """
        if not _HAS_REQUESTS or not cve_list:
            return {}

        # Lọc chỉ CVE hợp lệ
        valid_cves = [c for c in cve_list if c.startswith("CVE-")]
        if not valid_cves:
            return {}

        # Load KEV catalog (từ cache hoặc download mới)
        kev_map = self._load_kev_catalog()

        results = {}
        for cve in valid_cves:
            if cve in kev_map:
                entry = kev_map[cve]
                results[cve] = {
                    "cve": cve,
                    "is_kev": True,
                    "kev_due_date": entry.get("dueDate", ""),
                    "kev_notes": entry.get("notes", ""),
                    "kev_vendor": entry.get("vendorProject", ""),
                    "kev_product": entry.get("product", ""),
                    "kev_name": entry.get("vulnerabilityName", ""),
                }
            else:
                results[cve] = {
                    "cve": cve,
                    "is_kev": False,
                    "kev_due_date": "",
                    "kev_notes": "",
                }

        return results

    def _load_kev_catalog(self) -> dict:
        """
        Load KEV catalog, cache 7 ngày.
        [P0-1 FIX] Wrap json.load with safe loader to handle empty/corrupt cache.
        [P0-1.1 FIX] Atomic write to cache (write to .tmp + os.replace).
        """
        os.makedirs(self.CACHE_DIR, exist_ok=True)
        cache_path = os.path.join(self.CACHE_DIR, self.CACHE_FILE)

        # Thử load từ cache (an toàn với file rỗng)
        if os.path.exists(cache_path):
            try:
                if time.time() - os.path.getmtime(cache_path) < self.CACHE_TTL:
                    # [P0-1 FIX] Use kev_loader for safe parsing (handles empty file)
                    from core.kev_loader import load_kev_catalog
                    catalog = load_kev_catalog(cache_path)
                    vulns = catalog.get("vulnerabilities", [])
                    if vulns:
                        kev_map = {v["cveID"]: v for v in vulns if v.get("cveID")}
                        logging.debug(f"[CISAKEV] Cache hit: {len(kev_map)} CVEs")
                        return kev_map
            except Exception as e:
                logging.debug(f"[CISAKEV] Cache load failed (will re-download): {e}")

        # Download mới từ CISA
        kev_map = {}
        try:
            logging.info("[CISAKEV] Downloading CISA KEV catalog...")
            resp = requests.get(self.KEV_URL, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve_id = vuln.get("cveID", "")
                    if cve_id:
                        kev_map[cve_id] = vuln

                # [P0-1.1 FIX] Atomic write to cache (write to .tmp + os.replace)
                tmp_path = cache_path + ".tmp"
                try:
                    with open(tmp_path, 'w', encoding='utf-8') as f:
                        json.dump(data, f)
                        f.flush()
                        os.fsync(f.fileno())
                    os.replace(tmp_path, cache_path)
                except OSError as e:
                    logging.warning(f"[CISAKEV] Cache write failed: {e}")
                    # Cleanup tmp file if exists
                    if os.path.exists(tmp_path):
                        try:
                            os.remove(tmp_path)
                        except OSError:
                            pass

                logging.info(f"[CISAKEV] Loaded {len(kev_map)} CVEs from KEV catalog.")
            else:
                logging.warning(f"[CISAKEV] Download failed: HTTP {resp.status_code}")
        except requests.exceptions.Timeout:
            logging.warning("[CISAKEV] Download timeout")
        except Exception as e:
            logging.warning(f"[CISAKEV] Error: {e}")

        return kev_map
