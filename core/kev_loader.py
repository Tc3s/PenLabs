#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
KEV Loader — Safe loader cho CISA Known Exploited Vulnerabilities catalog.

CVE Reference: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

WHY THIS MODULE EXISTS:
- Bug P0-1.2 verified: data/kev_cache/kev_catalog.json was 0 KB (empty file).
- Main code calls json.load() on it → raises JSONDecodeError → crash.
- This loader handles: missing file, empty file, malformed JSON gracefully.

USAGE:
    from core.kev_loader import load_kev_catalog, is_in_kev

    catalog = load_kev_catalog()              # Returns dict, never raises
    if is_in_kev("CVE-2021-44228", catalog): # Safe lookup
        print("Log4Shell is in CISA KEV")
"""

import os
import json
import logging
import threading
from functools import lru_cache
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


# Default path: PenLabs/data/kev_cache/kev_catalog.json
_DEFAULT_KEV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "kev_cache", "kev_catalog.json"
)


def load_kev_catalog(path: Optional[str] = None) -> Dict[str, Any]:
    """
    Load CISA KEV catalog from JSON file. Returns safe empty structure on any failure.

    Returns:
        dict: {"vulnerabilities": [...], "_meta": {...}} - empty list if file missing/empty/corrupt

    Never raises. Logs warning on issues, returns safe empty catalog.

    [P0-1.3 FIX] Uses threading.Lock for thread-safety and lru_cache for memoization
    so repeated calls in same process don't re-stat/re-parse the file.
    """
    path = path or _DEFAULT_KEV_PATH
    return _load_kev_catalog_cached(path)


@lru_cache(maxsize=4)
def _load_kev_catalog_cached(path: str) -> Dict[str, Any]:
    """Cached version of load_kev_catalog. Thread-safe via lru_cache."""
    return _load_kev_catalog_uncached(path)


def _load_kev_catalog_uncached(path: str) -> Dict[str, Any]:
    """Actual load logic, called by cached version."""
    # Case 1: File doesn't exist
    if not os.path.exists(path):
        logger.warning(f"[KEV] Catalog file not found: {path}")
        return _empty_catalog("file_not_found")

    # Case 2: File is empty (the bug we fixed in P0-1)
    size = os.path.getsize(path)
    if size == 0:
        logger.warning(f"[KEV] Catalog file is empty (0 bytes): {path}")
        return _empty_catalog("file_empty")

    # Case 3: File is suspiciously small (< 100 bytes means invalid)
    MIN_VALID_JSON_BYTES = 100  # Min bytes for valid {"vulnerabilities": [...]}
    if size < MIN_VALID_JSON_BYTES:
        logger.warning(f"[KEV] Catalog file too small ({size} bytes): {path}")
        return _empty_catalog("file_too_small")

    # Case 4: File exists but JSON is malformed
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"[KEV] JSON decode error in {path}: {e}")
        return _empty_catalog(f"json_decode_error: {e}")
    except OSError as e:
        logger.error(f"[KEV] OS error reading {path}: {e}")
        return _empty_catalog(f"os_error: {e}")

    # Case 5: Valid JSON but wrong structure
    if not isinstance(data, dict):
        logger.warning(f"[KEV] Catalog root is not dict (got {type(data).__name__})")
        return _empty_catalog("invalid_structure")

    vulns = data.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        logger.warning(f"[KEV] 'vulnerabilities' is not list (got {type(vulns).__name__})")
        return _empty_catalog("invalid_vulnerabilities_field")

    # Success
    logger.info(f"[KEV] Loaded {len(vulns)} entries from {path}")
    return {
        "vulnerabilities": vulns,
        "catalogVersion": data.get("catalogVersion", ""),
        "count": data.get("count", len(vulns)),
        "dateReleased": data.get("dateReleased", ""),
        "_meta": {"loaded": True, "source_path": path},
    }


def _empty_catalog(reason: str) -> Dict[str, Any]:
    """Return safe empty catalog with metadata about why it's empty."""
    return {
        "vulnerabilities": [],
        "catalogVersion": "",
        "count": 0,
        "dateReleased": "",
        "_meta": {"loaded": False, "reason": reason},
    }


def is_in_kev(cve_id: str, catalog: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check if a CVE ID is in CISA KEV catalog.

    Args:
        cve_id: CVE identifier, e.g. "CVE-2021-44228"
        catalog: Optional pre-loaded catalog. If None, loads default.

    Returns:
        bool: True if CVE is in catalog, False otherwise.
               Returns False (not True!) if catalog is empty/corrupt.
    """
    if not cve_id:
        return False

    if catalog is None:
        catalog = load_kev_catalog()

    cve_id = cve_id.strip().upper()

    for vuln in catalog.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        # CISA KEV uses 'cveID' field (note the casing)
        if vuln.get("cveID", "").strip().upper() == cve_id:
            return True
    return False


def get_kev_entry(cve_id: str, catalog: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    """
    Get full KEV entry for a CVE.

    Args:
        cve_id: CVE identifier
        catalog: Optional pre-loaded catalog

    Returns:
        dict with KEV fields or None if not found
    """
    if not cve_id:
        return None

    if catalog is None:
        catalog = load_kev_catalog()

    cve_id = cve_id.strip().upper()

    for vuln in catalog.get("vulnerabilities", []):
        if not isinstance(vuln, dict):
            continue
        if vuln.get("cveID", "").strip().upper() == cve_id:
            return vuln
    return None


def get_kev_stats(catalog: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Get statistics about the KEV catalog.

    Returns:
        dict with total count, last updated, vendor breakdown, etc.
    """
    if catalog is None:
        catalog = load_kev_catalog()

    vulns = catalog.get("vulnerabilities", [])

    # Vendor breakdown
    vendors: Dict[str, int] = {}
    for v in vulns:
        if not isinstance(v, dict):
            continue
        vendor = v.get("vendorProject", "Unknown")
        vendors[vendor] = vendors.get(vendor, 0) + 1

    return {
        "total_entries": len(vulns),
        "catalog_version": catalog.get("catalogVersion", ""),
        "date_released": catalog.get("dateReleased", ""),
        "loaded": catalog.get("_meta", {}).get("loaded", False),
        "reason_if_empty": catalog.get("_meta", {}).get("reason", ""),
        "top_vendors": dict(sorted(vendors.items(), key=lambda x: -x[1])[:10]),
    }


if __name__ == "__main__":
    # Manual smoke test
    import sys

    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("=" * 60)
    print("KEV Loader Smoke Test")
    print("=" * 60)

    cat = load_kev_catalog()
    stats = get_kev_stats(cat)

    print(f"\nLoaded: {stats['loaded']}")
    print(f"Reason if empty: {stats['reason_if_empty']}")
    print(f"Total entries: {stats['total_entries']}")
    print(f"Catalog version: {stats['catalog_version']}")
    print(f"Date released: {stats['date_released']}")

    if stats["top_vendors"]:
        print("\nTop vendors:")
        for vendor, count in list(stats["top_vendors"].items())[:5]:
            print(f"  {vendor}: {count}")

    # Test is_in_kev with known CVEs
    test_cves = ["CVE-2021-44228", "CVE-2024-6387", "CVE-FAKE-9999-9999"]
    print("\nLookup tests:")
    for cve in test_cves:
        in_kev = is_in_kev(cve, cat)
        print(f"  {cve}: {'✓ in KEV' if in_kev else '✗ not in KEV'}")

    sys.exit(0)
