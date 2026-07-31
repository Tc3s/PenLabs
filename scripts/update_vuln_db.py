#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Automated VulnDB Updater (CISA KEV Edition)

Fetches CISA Known Exploited Vulnerabilities catalog, generates heuristic
CPE patterns, and merges into data/vuln_db.json without destroying
custom rules.

Usage:
    python3 scripts/update_vuln_db.py              # One-shot update
    python3 scripts/update_vuln_db.py --dry-run     # Preview without writing
    python3 scripts/update_vuln_db.py --stats        # Print DB stats only

Crontab example (daily at 03:00 UTC):
    0 3 * * * cd /path/to/PenLabs && python3 scripts/update_vuln_db.py >> logs/vulndb_update.log 2>&1

NO NVD API CALLS — uses CISA static JSON feed only.
"""

import os
import sys
import json
import re
import hashlib
import logging
import argparse
import subprocess
import shutil
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_KEV_MIRRORS = [
    "https://raw.githubusercontent.com/EugenMayer/cisa-known-exploited-mirror/refs/heads/main/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/aboutcode-org/aboutcode-mirror-kev/refs/heads/main/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/refs/heads/main/known_exploited_vulnerabilities.json",
]
VULN_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "vuln_db.json")
BACKUP_DIR = os.path.join(os.path.dirname(VULN_DB_PATH), "backups")
KEV_CACHE_PATH = os.path.join(os.path.dirname(VULN_DB_PATH), "cisa_kev_cache.json")

# Auto-generated rules have lower confidence since CPE is heuristic
AUTO_CONFIDENCE_PENALTY = 0.3
AUTO_SOURCE_TAG = "CISA-KEV"

# Colors
_G = "\033[92m"
_Y = "\033[93m"
_R = "\033[91m"
_C = "\033[96m"
_M = "\033[95m"
_X = "\033[0m"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("VulnDB-Updater")


# ═══════════════════════════════════════════════════════════
# STEP 1: FETCH CISA KEV FEED (Multi-Source Resilient)
# ═══════════════════════════════════════════════════════════

def _fetch_via_curl(url: str) -> bytes:
    """
    Fetch URL using curl subprocess.
    curl has a native TLS stack that passes WAF fingerprint checks
    where Python's urllib/requests often gets blocked (403).
    """
    if not shutil.which("curl"):
        log.debug("[Fetch] curl not available on this system")
        return b""

    log.info("[Fetch] Trying curl (best TLS fingerprint)...")
    try:
        result = subprocess.run(
            [
                "curl", "-sS", "-L", "--compressed",
                "--max-time", "60",
                "--retry", "2",
                "--retry-delay", "3",
                "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/125.0.0.0 Safari/537.36",
                "-H", "Accept: application/json, text/plain, */*",
                "-H", "Accept-Language: en-US,en;q=0.9",
                url,
            ],
            capture_output=True,
            timeout=90,
        )
        if result.returncode == 0 and len(result.stdout) > 1000:
            # Verify it's valid JSON
            json.loads(result.stdout)
            log.info(f"[Fetch] curl success: {len(result.stdout)} bytes")
            return result.stdout
        else:
            log.warning(f"[Fetch] curl returned {result.returncode}, "
                        f"body size={len(result.stdout)}")
    except subprocess.TimeoutExpired:
        log.warning("[Fetch] curl timed out")
    except json.JSONDecodeError:
        log.warning("[Fetch] curl response is not valid JSON (likely WAF block page)")
    except Exception as e:
        log.warning(f"[Fetch] curl error: {e}")
    return b""


def _fetch_via_urllib(url: str) -> bytes:
    """Fallback fetch using Python urllib."""
    log.info("[Fetch] Trying urllib (fallback)...")
    headers = {
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/125.0.0.0 Safari/537.36"),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
    }
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=60) as resp:
            raw = resp.read()
            if len(raw) > 1000:
                json.loads(raw)  # validate JSON
                log.info(f"[Fetch] urllib success: {len(raw)} bytes")
                return raw
    except HTTPError as e:
        log.warning(f"[Fetch] urllib HTTP {e.code} {e.reason}")
    except URLError as e:
        log.warning(f"[Fetch] urllib network error: {e.reason}")
    except json.JSONDecodeError:
        log.warning("[Fetch] urllib response is not valid JSON")
    except Exception as e:
        log.warning(f"[Fetch] urllib error: {e}")
    return b""


def fetch_cisa_kev(local_file: str = None) -> dict:
    """
    Fetch CISA KEV catalog with multi-source resilience.

    Priority:
      1. Local file (--kev-file) — always works, for offline/air-gapped use
      2. curl subprocess — best TLS fingerprint, passes most WAFs
      3. Python urllib — fallback
      4. Cached copy — last-resort if all network methods fail

    Returns parsed JSON dict.
    """
    # ── Priority 1: Local file ──
    if local_file:
        if not os.path.exists(local_file):
            log.error(f"Local KEV file not found: {local_file}")
            sys.exit(1)
        log.info(f"[Fetch] Loading local KEV file: {local_file}")
        with open(local_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        vuln_count = len(data.get("vulnerabilities", []))
        log.info(f"Loaded {vuln_count} vulnerabilities from local file")
        return data

    # ── Priority 2: CISA direct (curl) ──
    raw = _fetch_via_curl(CISA_KEV_URL)

    # ── Priority 3: CISA direct (urllib) ──
    if not raw:
        raw = _fetch_via_urllib(CISA_KEV_URL)

    # ── Priority 4: GitHub mirrors (curl then urllib for each) ──
    if not raw:
        log.info("[Fetch] CISA direct failed. Trying GitHub mirrors...")
        for mirror_url in CISA_KEV_MIRRORS:
            log.info(f"[Fetch] Mirror: {mirror_url[:70]}...")
            raw = _fetch_via_curl(mirror_url)
            if not raw:
                raw = _fetch_via_urllib(mirror_url)
            if raw and len(raw) > 1000:
                break
            raw = b""
    # ── Parse result ──
    if raw and len(raw) > 1000:
        data = json.loads(raw)
        vuln_count = len(data.get("vulnerabilities", []))
        log.info(f"Fetched {vuln_count} vulnerabilities from CISA KEV")
        # Cache for future offline use
        try:
            os.makedirs(os.path.dirname(KEV_CACHE_PATH), exist_ok=True)
            with open(KEV_CACHE_PATH, "wb") as f:
                f.write(raw)
            log.info(f"[Cache] Saved KEV cache: {KEV_CACHE_PATH}")
        except Exception as e:
            log.debug(f"[Cache] Failed to save cache: {e}")
        return data

    # ── Priority 4: Cached copy ──
    if os.path.exists(KEV_CACHE_PATH):
        log.warning(f"[Fetch] All network methods failed. Using cached copy: {KEV_CACHE_PATH}")
        with open(KEV_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        vuln_count = len(data.get("vulnerabilities", []))
        log.info(f"Loaded {vuln_count} vulnerabilities from cache")
        return data

    # ── All methods exhausted ──
    log.error("All fetch methods failed. CISA may be blocking your IP (WAF/geo-restriction).")
    log.error("Workaround: Download the file manually and use --kev-file:")
    log.error(f"  1. Open browser: {CISA_KEV_URL}")
    log.error("  2. Save JSON file to: data/cisa_kev_manual.json")
    log.error("  3. Run: python3 scripts/update_vuln_db.py --kev-file data/cisa_kev_manual.json")
    sys.exit(1)


# ═══════════════════════════════════════════════════════════
# STEP 2: HEURISTIC CPE + PATTERN GENERATION
# ═══════════════════════════════════════════════════════════

def _normalize(text: str) -> str:
    """Normalize vendor/product names for CPE: lowercase, spaces → underscores."""
    return re.sub(r'\s+', '_', text.strip().lower())


def _make_cpe(vendor: str, product: str) -> str:
    """Generate CPE 2.3 pattern: cpe:2.3:a:{vendor}:{product}:*"""
    v = _normalize(vendor)
    p = _normalize(product)
    return f"cpe:2.3:a:{v}:{p}:*"


def _make_pattern(vendor: str, product: str) -> str:
    """Generate text search pattern for banner/header matching."""
    v = vendor.strip().lower()
    p = product.strip().lower()
    # If vendor is part of product name, just use product
    if v in p:
        return p
    return f"{v} {p}"


def generate_rules_from_kev(kev_data: dict) -> list:
    """
    Convert CISA KEV entries into PenLabs tech_stack_rule format.

    Each rule has:
        - pattern: text match for banner/header
        - cpe_pattern: heuristic CPE 2.3 string
        - cve: CVE ID
        - description: short vulnerability description
        - source: "CISA-KEV"
        - confidence_penalty: 0.3 (heuristic CPE is approximate)
        - kev_date_added: when CISA added it
        - kev_due_date: remediation deadline
    """
    rules = []
    for vuln in kev_data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID", "").strip()
        vendor = vuln.get("vendorProject", "").strip()
        product = vuln.get("product", "").strip()
        description = vuln.get("vulnerabilityName", "").strip()
        date_added = vuln.get("dateAdded", "")
        due_date = vuln.get("dueDate", "")
        known_ransomware = vuln.get("knownRansomwareCampaignUse", "Unknown")

        if not cve_id or not vendor or not product:
            continue

        rule = {
            "pattern": _make_pattern(vendor, product),
            "cpe_pattern": _make_cpe(vendor, product),
            "cve": cve_id,
            "description": description or f"{vendor} {product} (CISA KEV)",
            "source": AUTO_SOURCE_TAG,
            "confidence_penalty": AUTO_CONFIDENCE_PENALTY,
            "kev_date_added": date_added,
            "kev_due_date": due_date,
        }

        # Flag ransomware-related vulns for priority handling
        if known_ransomware and known_ransomware.lower() == "known":
            rule["ransomware_linked"] = True
            rule["confidence_penalty"] = 0.1  # Higher confidence for known ransomware

        rules.append(rule)

    log.info(f"Generated {len(rules)} rules from CISA KEV data")
    return rules


# ═══════════════════════════════════════════════════════════
# STEP 3: SAFE MERGE INTO EXISTING VULN_DB
# ═══════════════════════════════════════════════════════════

def load_existing_db(db_path: str) -> dict:
    """Load existing vuln_db.json. Returns empty structure if file missing."""
    if not os.path.exists(db_path):
        log.warning(f"VulnDB not found at {db_path}, starting fresh.")
        return {
            "_meta": {
                "version": "2.0",
                "last_updated": "",
                "description": "PenLabs VulnDB V2 — CPE-aware mapping",
            },
            "tech_stack_rules": [],
            "port_rules": [],
        }
    with open(db_path, "r", encoding="utf-8") as f:
        return json.load(f)


def merge_rules(existing_db: dict, new_rules: list) -> dict:
    """
    Safe merge: preserve custom rules, add new CISA-KEV rules.

    Logic:
    1. Index existing rules by CVE ID
    2. Separate custom rules (no "source" or source != "CISA-KEV") from auto-generated
    3. For each new rule: skip if CVE already exists in tech_stack_rules
    4. Append new rules, update metadata
    """
    existing_rules = existing_db.get("tech_stack_rules", [])

    # Build set of existing CVEs for O(1) lookup
    existing_cves = set()
    for rule in existing_rules:
        cve = rule.get("cve", "")
        if cve:
            existing_cves.add(cve)

    # Count custom vs auto rules
    custom_count = sum(1 for r in existing_rules if r.get("source") != AUTO_SOURCE_TAG)
    auto_count = sum(1 for r in existing_rules if r.get("source") == AUTO_SOURCE_TAG)

    # Merge: add only new CVEs
    added = 0
    skipped = 0
    for rule in new_rules:
        if rule["cve"] in existing_cves:
            skipped += 1
            continue
        existing_rules.append(rule)
        existing_cves.add(rule["cve"])
        added += 1

    # Update metadata
    existing_db["tech_stack_rules"] = existing_rules
    existing_db["_meta"]["last_updated"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    existing_db["_meta"]["description"] = (
        "PenLabs VulnDB V2 — CPE-aware Service/Version to CVE mapping. "
        f"Custom: {custom_count}, CISA-KEV auto: {auto_count + added}."
    )

    log.info(f"Merge complete: +{added} new rules, {skipped} skipped (already exist)")
    log.info(f"Total rules: {len(existing_rules)} "
             f"(Custom: {custom_count}, Auto: {auto_count + added})")

    return existing_db


# ═══════════════════════════════════════════════════════════
# STEP 4: WRITE DB WITH BACKUP
# ═══════════════════════════════════════════════════════════

def backup_db(db_path: str) -> str:
    """Create timestamped backup before overwriting."""
    if not os.path.exists(db_path):
        return ""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"vuln_db_{ts}.json")
    with open(db_path, "r") as src, open(backup_path, "w") as dst:
        dst.write(src.read())
    log.info(f"Backup created: {backup_path}")
    return backup_path


def write_db(db: dict, db_path: str):
    """Write merged DB to disk with pretty JSON formatting."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=4, ensure_ascii=False)
    # Calculate file hash for integrity
    with open(db_path, "rb") as f:
        sha256 = hashlib.sha256(f.read()).hexdigest()
    size_kb = os.path.getsize(db_path) / 1024
    log.info(f"VulnDB written: {db_path} ({size_kb:.1f} KB, SHA256: {sha256[:16]}...)")


# ═══════════════════════════════════════════════════════════
# STEP 5: STATS & REPORTING
# ═══════════════════════════════════════════════════════════

def print_stats(db: dict):
    """Print human-readable DB statistics."""
    rules = db.get("tech_stack_rules", [])
    port_rules = db.get("port_rules", [])
    custom = [r for r in rules if r.get("source") != AUTO_SOURCE_TAG]
    auto = [r for r in rules if r.get("source") == AUTO_SOURCE_TAG]
    ransomware = [r for r in auto if r.get("ransomware_linked")]

    print(f"\n{_C}╔{'═'*60}╗{_X}")
    print(f"{_C}║  📊 PenLabs VulnDB Statistics                              ║{_X}")
    print(f"{_C}╠{'═'*60}╣{_X}")
    print(f"{_C}║{_X}  Last Updated    : {_G}{db.get('_meta', {}).get('last_updated', 'N/A')}{_X}")
    print(f"{_C}║{_X}  Tech Stack Rules: {_Y}{len(rules)}{_X}")
    print(f"{_C}║{_X}    ├─ Custom     : {_G}{len(custom)}{_X}")
    print(f"{_C}║{_X}    └─ CISA-KEV   : {_M}{len(auto)}{_X}")
    print(f"{_C}║{_X}  Port Rules      : {_Y}{len(port_rules)}{_X}")
    print(f"{_C}║{_X}  Ransomware-linked: {_R}{len(ransomware)}{_X}")
    print(f"{_C}╚{'═'*60}╝{_X}")

    # Top 5 vendors
    vendor_counts = {}
    for r in auto:
        vendor = r.get("pattern", "").split()[0] if r.get("pattern") else "unknown"
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
    if vendor_counts:
        top_vendors = sorted(vendor_counts.items(), key=lambda x: -x[1])[:5]
        print(f"\n{_Y}  Top 5 CISA-KEV Vendors:{_X}")
        for v, c in top_vendors:
            print(f"    {_C}►{_X} {v:<25} {c} CVEs")


# ═══════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="PenLabs VulnDB Updater — Auto-sync from CISA KEV catalog"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview changes without writing to disk")
    parser.add_argument("--stats", action="store_true",
                        help="Print current DB statistics and exit")
    parser.add_argument("--db-path", default=VULN_DB_PATH,
                        help=f"Path to vuln_db.json (default: {VULN_DB_PATH})")
    parser.add_argument("--kev-file", default=None,
                        help="Path to local CISA KEV JSON file (bypass network fetch)")
    parser.add_argument("--no-backup", action="store_true",
                        help="Skip backup before writing")
    args = parser.parse_args()

    print(f"\n{_C}  ╔══════════════════════════════════════════════╗{_X}")
    print(f"{_C}  ║  PenLabs VulnDB Updater (CISA-KEV Edition)  ║{_X}")
    print(f"{_C}  ╚══════════════════════════════════════════════╝{_X}\n")

    # Stats only mode
    if args.stats:
        db = load_existing_db(args.db_path)
        print_stats(db)
        return

    # Step 1: Fetch CISA KEV (with multi-source fallback)
    kev_data = fetch_cisa_kev(local_file=args.kev_file)

    # Step 2: Generate heuristic rules
    new_rules = generate_rules_from_kev(kev_data)

    # Step 3: Load existing DB
    existing_db = load_existing_db(args.db_path)

    # Step 4: Merge
    merged_db = merge_rules(existing_db, new_rules)

    # Step 5: Report
    print_stats(merged_db)

    if args.dry_run:
        print(f"\n{_Y}  [DRY-RUN] No changes written to disk.{_X}")
        print(f"{_Y}  Would add rules to: {args.db_path}{_X}")
        return

    # Step 6: Backup + Write
    if not args.no_backup:
        backup_db(args.db_path)
    write_db(merged_db, args.db_path)

    print(f"\n{_G}  [✓] VulnDB update complete!{_X}")
    print(f"{_G}  DB saved to: {args.db_path}{_X}\n")


if __name__ == "__main__":
    main()
