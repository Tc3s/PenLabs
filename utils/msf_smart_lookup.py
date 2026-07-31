#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FILE: utils/msf_smart_lookup.py
# CHỨC NĂNG: Multi-tier Smart Lookup Engine cho MSF Module Map V2.
#            Tra cứu tức thì (< 1ms) module Metasploit từ offline index.
#            Hỗ trợ tìm kiếm theo: CVE, Port, Service, Product, Nuclei Template, EDB ID.
#
# USAGE (standalone):
#   python3 utils/msf_smart_lookup.py --cve CVE-2011-2523
#   python3 utils/msf_smart_lookup.py --port 3632
#   python3 utils/msf_smart_lookup.py --service tomcat
#   python3 utils/msf_smart_lookup.py --nuclei tomcat-default-login
#   python3 utils/msf_smart_lookup.py --port 21 --service ftp

import os
import sys
import json
import re
import logging
import threading
from typing import List, Dict, Optional, Tuple

# Default map path
_DEFAULT_MAP_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "msf_module_map.json")

# Rank scoring for result sorting
RANK_SCORES = {
    "excellent": 100,
    "great": 90,
    "good": 80,
    "normal": 70,
    "average": 60,
    "low": 50,
    "manual": 10,
}


class MsfSmartLookup:
    """
    Multi-tier Smart Lookup Engine for Metasploit modules.
    
    Lookup priority:
    1. Exact CVE match       → by_cve["CVE-XXXX-YYYY"]
    2. Service + Port match  → by_port["3632"] ∩ by_service["distcc"]
    3. Port-only match       → by_port["21"]
    4. Service-only match    → by_service["tomcat"]
    5. Product fuzzy match   → by_product["vsftpd"]
    6. Nuclei template map   → template_id → service → by_service
    7. EDB ID match          → by_edb["17491"]
    """

    def __init__(self, map_path: str = None):
        self._map_path = map_path or _DEFAULT_MAP_PATH
        self._data = None
        self._loaded = False

    def _ensure_loaded(self):
        """Lazy-load the module map on first access."""
        if self._loaded:
            return
        
        if not os.path.exists(self._map_path):
            logging.warning(f"[MsfSmartLookup] Module map not found: {self._map_path}")
            logging.warning(f"[MsfSmartLookup] Run: python3 scripts/generate_msf_map_v2.py")
            self._data = {}
            self._loaded = True
            return
        
        try:
            with open(self._map_path, "r") as f:
                self._data = json.load(f)
            meta = self._data.get("_meta", {})
            logging.info(f"[MsfSmartLookup] Loaded {meta.get('total_modules', '?')} modules, "
                        f"{meta.get('total_cves', '?')} CVEs from map v{meta.get('version', '?')}")
        except Exception as e:
            logging.error(f"[MsfSmartLookup] Failed to load map: {e}")
            self._data = {}
        
        self._loaded = True

    def _sort_results(self, results: List[Dict], limit: int = 10) -> List[Dict]:
        """Sort results: exploit > auxiliary > post, then by rank_score desc."""
        type_order = {"exploit": 0, "auxiliary": 1, "post": 2}
        sorted_results = sorted(results, key=lambda x: (
            type_order.get(x.get("type", ""), 3),
            -x.get("rank_score", 0)
        ))
        return sorted_results[:limit]

    def _dedup_by_path(self, results: List[Dict]) -> List[Dict]:
        """Deduplicate results by module path."""
        seen = set()
        deduped = []
        for r in results:
            path = r.get("path", "")
            if path not in seen:
                seen.add(path)
                deduped.append(r)
        return deduped

    # ═══════════════════════════════════════
    # Tier 1: Exact CVE Match
    # ═══════════════════════════════════════
    def lookup_by_cve(self, cve_id: str, limit: int = 10) -> List[Dict]:
        """Lookup modules by exact CVE ID."""
        self._ensure_loaded()
        by_cve = self._data.get("by_cve", {})
        
        # Normalize CVE format
        cve_upper = cve_id.upper()
        if not cve_upper.startswith("CVE-"):
            cve_upper = f"CVE-{cve_upper}"
        
        results = by_cve.get(cve_upper, [])
        return self._sort_results(self._dedup_by_path(results), limit)

    # ═══════════════════════════════════════
    # Tier 2: Port + Service Intersection
    # ═══════════════════════════════════════
    def lookup_by_port(self, port: int, service: str = None, limit: int = 10) -> List[Dict]:
        """
        Lookup modules by port number, optionally filtered by service name.
        If service is provided, returns intersection of port and service matches.
        """
        self._ensure_loaded()
        by_port = self._data.get("by_port", {})
        by_service = self._data.get("by_service", {})
        
        port_results = by_port.get(str(port), [])
        
        if service:
            svc_lower = service.lower().strip()
            svc_results = by_service.get(svc_lower, [])
            
            # Intersection: modules that appear in both port AND service
            port_paths = {r["path"] for r in port_results}
            svc_paths = {r["path"] for r in svc_results}
            intersection_paths = port_paths & svc_paths
            
            if intersection_paths:
                # Return only modules in the intersection
                combined = [r for r in port_results if r["path"] in intersection_paths]
                return self._sort_results(self._dedup_by_path(combined), limit)
            else:
                # No intersection — return union (port results first, then service results)
                all_results = port_results + svc_results
                return self._sort_results(self._dedup_by_path(all_results), limit)
        
        return self._sort_results(self._dedup_by_path(port_results), limit)

    # ═══════════════════════════════════════
    # Tier 3: Service-only Match
    # ═══════════════════════════════════════
    def lookup_by_service(self, service: str, limit: int = 10) -> List[Dict]:
        """Lookup modules by service name (e.g. 'ftp', 'tomcat', 'smb')."""
        self._ensure_loaded()
        by_service = self._data.get("by_service", {})
        svc_lower = service.lower().strip()
        results = by_service.get(svc_lower, [])
        return self._sort_results(self._dedup_by_path(results), limit)

    # ═══════════════════════════════════════
    # Tier 4: Product Fuzzy Match
    # ═══════════════════════════════════════
    def lookup_by_product(self, product_name: str, limit: int = 10) -> List[Dict]:
        """
        Fuzzy match modules by product name keywords.
        Searches in the by_product index (tokens from module names).
        """
        self._ensure_loaded()
        by_product = self._data.get("by_product", {})
        
        # Tokenize the product name
        tokens = re.findall(r'\b[a-z0-9]{3,}\b', product_name.lower())
        
        if not tokens:
            return []
        
        # Score each module by how many tokens match
        module_scores = {}  # path → (score, entry)
        for token in tokens:
            matches = by_product.get(token, [])
            for m in matches:
                path = m["path"]
                if path not in module_scores:
                    module_scores[path] = {"score": 0, "entry": m}
                module_scores[path]["score"] += 1
        
        # Sort by match score desc, then rank_score desc
        scored = sorted(module_scores.values(), key=lambda x: (
            -x["score"],
            0 if x["entry"].get("type") == "exploit" else 1,
            -x["entry"].get("rank_score", 0)
        ))
        
        return [s["entry"] for s in scored[:limit]]

    # ═══════════════════════════════════════
    # Tier 5: Nuclei Template Mapping
    # ═══════════════════════════════════════
    def lookup_by_nuclei_template(self, template_id: str, limit: int = 10) -> List[Dict]:
        """
        Map Nuclei template IDs to MSF modules.
        
        Strategy:
        1. Extract CVE from template_id if present (e.g. 'CVE-2021-44228')
        2. Extract service name from template_id (e.g. 'tomcat-default-login' → 'tomcat')
        3. Look up via the corresponding index
        """
        self._ensure_loaded()
        nuclei_svc_map = self._data.get("nuclei_service_map", {})
        
        template_lower = template_id.lower().strip()
        
        # Strategy 1: Extract CVE from template
        cve_match = re.search(r'(cve-\d{4}-\d+)', template_lower, re.IGNORECASE)
        if cve_match:
            cve_results = self.lookup_by_cve(cve_match.group(1), limit)
            if cve_results:
                return cve_results
        
        # Strategy 2: Extract service name from template ID
        # Remove common prefixes/suffixes
        clean_id = template_lower
        for prefix in ("nuclei-", "nuclei_"):
            if clean_id.startswith(prefix):
                clean_id = clean_id[len(prefix):]
        
        # Check against nuclei_service_map
        for keyword, service in nuclei_svc_map.items():
            if keyword in clean_id:
                svc_results = self.lookup_by_service(service, limit)
                if svc_results:
                    return svc_results
        
        # Strategy 3: Fuzzy match the template ID tokens
        # [V1.0] Block generic noise terms from producing false MSF matches
        _NOISE_TOKENS = frozenset({
            'secrets', 'patterns', 'pii', 'rules', 'generic', 'tokens',
            'detect', 'info', 'exposure', 'version', 'header', 'missing',
            'finder', 'extractor', 'default', 'test', 'page', 'error',
        })
        clean_tokens = set(re.findall(r'\b[a-z0-9]{3,}\b', clean_id))
        # If ALL tokens are noise → return empty (no match)
        if clean_tokens and clean_tokens.issubset(_NOISE_TOKENS):
            return []
        # Remove noise tokens before fuzzy matching
        meaningful_id = " ".join(t for t in clean_id.split("-") if t.lower() not in _NOISE_TOKENS)
        if not meaningful_id.strip():
            return []
        return self.lookup_by_product(meaningful_id, limit)

    # ═══════════════════════════════════════
    # Tier 6: EDB ID Match
    # ═══════════════════════════════════════
    def lookup_by_edb(self, edb_id: str, limit: int = 10) -> List[Dict]:
        """Lookup modules by Exploit-DB ID."""
        self._ensure_loaded()
        by_edb = self._data.get("by_edb", {})
        results = by_edb.get(str(edb_id), [])
        return self._sort_results(self._dedup_by_path(results), limit)

    # ═══════════════════════════════════════
    # UNIFIED SMART SEARCH
    # ═══════════════════════════════════════
    def smart_search(self, cve: str = None, port: int = None, service: str = None,
                     product: str = None, nuclei_template: str = None,
                     edb_id: str = None, limit: int = 6) -> List[Dict]:
        """
        Unified smart search with multi-tier fallback.
        
        Lookup priority:
        1. CVE (exact)
        2. Port + Service (intersection)
        3. Nuclei template mapping
        4. Product fuzzy match
        5. EDB ID
        6. Port only
        7. Service only
        
        Returns up to `limit` best matching modules.
        """
        results = []
        
        # Tier 1: CVE exact match (highest priority)
        if cve:
            results = self.lookup_by_cve(cve, limit)
            if results:
                return results
        
        # Tier 2: Port + Service intersection
        if port and service:
            results = self.lookup_by_port(port, service, limit)
            if results:
                return results
        
        # Tier 3: Nuclei template
        if nuclei_template:
            results = self.lookup_by_nuclei_template(nuclei_template, limit)
            if results:
                return results
        
        # Tier 4: Product fuzzy match
        if product:
            results = self.lookup_by_product(product, limit)
            if results:
                return results
        
        # Tier 5: EDB ID
        if edb_id:
            results = self.lookup_by_edb(edb_id, limit)
            if results:
                return results
        
        # Tier 6: Port only
        if port:
            results = self.lookup_by_port(port, limit=limit)
            if results:
                return results
        
        # Tier 7: Service only
        if service:
            results = self.lookup_by_service(service, limit)
            if results:
                return results
        
        return []

    # ═══════════════════════════════════════
    # BACKWARD COMPATIBLE API
    # ═══════════════════════════════════════
    def search_for_cve(self, cve_id: str, cache_dir: str = None) -> List[Dict]:
        """
        Backward-compatible API matching msf_dynamic_search.search_msf_for_cve().
        Returns list of dicts with: path, type, rank, score
        """
        results = self.lookup_by_cve(cve_id, limit=6)
        
        # Convert to old format
        legacy_results = []
        for r in results:
            rank = r.get("rank", "normal")
            score = RANK_SCORES.get(rank, 70)
            if r.get("type") == "exploit":
                score += 500
            
            legacy_results.append({
                "path": r["path"],
                "type": r.get("type", "exploit"),
                "rank": rank,
                "score": score,
            })
        
        return legacy_results

    def get_stats(self) -> Dict:
        """Return statistics about the loaded module map."""
        self._ensure_loaded()
        meta = self._data.get("_meta", {})
        return meta.get("stats", {})


# ═══════════════════════════════════════════════
# SINGLETON INSTANCE for quick imports
# [SECURITY-FIX][CRIT-03] Thread-safe initialization with Lock
# ═══════════════════════════════════════════════
_instance = None
_instance_lock = threading.Lock()

def get_lookup() -> MsfSmartLookup:
    """Get or create singleton instance of MsfSmartLookup (thread-safe)."""
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = MsfSmartLookup()
    return _instance


def smart_search_msf(cve=None, port=None, service=None, product=None, 
                     nuclei_template=None, limit=6) -> List[Dict]:
    """Quick-access function for smart MSF module search."""
    return get_lookup().smart_search(cve=cve, port=port, service=service,
                                    product=product, nuclei_template=nuclei_template,
                                    limit=limit)


def search_msf_for_cve(cve_id: str, cache_dir: str = None) -> List[Dict]:
    """
    DROP-IN REPLACEMENT for msf_dynamic_search.search_msf_for_cve().
    Uses offline map instead of msfconsole query.
    Falls back to msfconsole if CVE not found in offline map.
    """
    lookup = get_lookup()
    results = lookup.search_for_cve(cve_id, cache_dir)
    
    if results:
        return results
    
    # Fallback: try msfconsole live query (old method)
    try:
        from utils.msf_dynamic_search import search_msf_for_cve as _legacy_search
        logging.info(f"[MsfSmartLookup] CVE {cve_id} not in offline map, falling back to msfconsole...")
        return _legacy_search(cve_id, cache_dir or "/tmp")
    except Exception:
        return []


# ═══════════════════════════════════════════════
# CLI INTERFACE
# ═══════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MSF Smart Lookup — Instant module search from offline index")
    parser.add_argument("--cve", help="Search by CVE ID (e.g. CVE-2011-2523)")
    parser.add_argument("--port", type=int, help="Search by port number (e.g. 3632)")
    parser.add_argument("--service", help="Search by service name (e.g. ftp, tomcat, smb)")
    parser.add_argument("--product", help="Search by product name (e.g. vsftpd, apache)")
    parser.add_argument("--nuclei", help="Search by Nuclei template ID (e.g. tomcat-default-login)")
    parser.add_argument("--edb", help="Search by Exploit-DB ID")
    parser.add_argument("--limit", type=int, default=10, help="Max results (default: 10)")
    parser.add_argument("--map-path", help="Path to msf_module_map.json")
    parser.add_argument("--stats", action="store_true", help="Show map statistics")
    
    args = parser.parse_args()
    
    lookup = MsfSmartLookup(args.map_path) if args.map_path else get_lookup()
    
    if args.stats:
        stats = lookup.get_stats()
        print(json.dumps(stats, indent=2))
        sys.exit(0)
    
    if not any([args.cve, args.port, args.service, args.product, args.nuclei, args.edb]):
        parser.print_help()
        sys.exit(1)
    
    results = lookup.smart_search(
        cve=args.cve,
        port=args.port,
        service=args.service,
        product=args.product,
        nuclei_template=args.nuclei,
        edb_id=args.edb,
        limit=args.limit,
    )
    
    if results:
        print(f"\n{'='*70}")
        query_parts = []
        if args.cve: query_parts.append(f"CVE={args.cve}")
        if args.port: query_parts.append(f"Port={args.port}")
        if args.service: query_parts.append(f"Service={args.service}")
        if args.product: query_parts.append(f"Product={args.product}")
        if args.nuclei: query_parts.append(f"Nuclei={args.nuclei}")
        if args.edb: query_parts.append(f"EDB={args.edb}")
        print(f"  Query: {', '.join(query_parts)}")
        print(f"  Found: {len(results)} modules")
        print(f"{'='*70}")
        
        for i, r in enumerate(results, 1):
            mtype = r.get("type", "?").upper()
            rank = r.get("rank", "?")
            path = r.get("path", "?")
            name = r.get("name", "")
            port = r.get("default_port", "")
            port_str = f" (Port {port})" if port else ""
            cves = r.get("cves", [])
            cve_str = f" [{', '.join(cves)}]" if cves else ""
            
            print(f"  {i:2d}. [{mtype:>9}] {path}")
            print(f"      Rank: {rank} | {name}{port_str}{cve_str}")
    else:
        print(f"\n  No modules found for the given query.")
