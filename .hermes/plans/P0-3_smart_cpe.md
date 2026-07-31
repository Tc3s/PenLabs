# P0-3 — Smart CPE Filter (Cross-Validated, Version-Range Aware, OS-Aware, EPSS-Prioritized)

> **Priority:** P0 (Critical — directly reduces false-positive CVE findings that pollute attack plans)
> **Owner:** Subagent Planner
> **Source file analyzed:** `/home/tcus/Desktop/PenLabs/scripts/Module2_VulnAnalysis.py` (lines 1–400)
> **Date:** 2026-06-24

---

## 1. Hiện trạng (Current State Analysis)

File `scripts/Module2_VulnAnalysis.py` đã có sẵn một số building blocks cho CPE filtering, nhưng chúng **nằm rải rác trong class `VulnAnalyzer`** và thiếu các tính năng quan trọng được yêu cầu bởi P0-3. Phân tích chi tiết:

### 1.1. Những gì ĐÃ CÓ (working baseline)

| Component | Vị trí (line) | Trạng thái |
|---|---|---|
| `CPEMatcher.parse_cpe()` | L88–99 | ✅ Parse CPE 2.3 string → dict |
| `CPEMatcher.match_cpe()` | L101–127 | ✅ Match CPE exact + wildcard (`*`, `prefix.*`) |
| `VersionMatcher.match()` | L135–146 | ✅ Regex matching với negative lookbehind/lookahead chống partial match (vd: `2.4` không match `12.40`) |
| `_CVE_VERSION_RANGES` | L73–78 | ✅ Hardcoded affected-version ranges cho 4 CVE high-FP (Apache 2.4.49/50, IIS 6, SMB1) |
| `VulnAnalyzer._match_tech_rule()` | L229–317 | ✅ Hỗ trợ 2 strategy: CPE matching (priority) + Substring fallback |
| `VulnAnalyzer._deduplicate_cpe()` | L321–358 | ✅ Phase 3 — Loại CPE trùng version, giữ version mới nhất |
| `VulnAnalyzer._smart_cpe_filter()` | L360+ | ✅ Cross-validate Nmap CPE ↔ HttpX tech-detect (web server + framework + CMS) |
| EPSS/KEV plugins | L194–195 | ✅ Đã load qua `PluginRegistry` (`self._epss_plugin`, `self._kev_plugin`) |
| `_INFRA_CVE_KEYWORDS` | L168–174 | ✅ Phân loại CVE infra vs web (origin-aware boost) |

### 1.2. Trích 5–10 dòng code THẬT minh họa logic hiện tại

**Code 1 — Version-range hardcode quá hẹp (L73–78):**
```python
_CVE_VERSION_RANGES = {
    "CVE-2021-41773": r"2\.4\.49",
    "CVE-2021-42013": r"2\.4\.50",
    "CVE-2017-7269": r"^6\.",
    "CVE-2017-0144": r"^(7|8\.1|10|2008|2012|2016)" # SMB1 Windows versions roughly
}
```
→ **Vấn đề:** Chỉ có 4 CVE. Mọi CVE khác (vd: Log4Shell `CVE-2021-44228`, Spring4Shell `CVE-2022-22965`) không được range-check.

**Code 2 — Version-mismatch gate trong `_match_tech_rule()` (L278–301):**
```python
# [CRIT-01 FIX] Chặn false positive chặn đứng nếu nằm ngoài affected version range
version_mismatch = False
if cve in _CVE_VERSION_RANGES:
    required_range = _CVE_VERSION_RANGES[cve]
    detected_version = None
    if cpe_pattern and cpe_list:
        for cpe in cpe_list:
            parsed = CPEMatcher.parse_cpe(cpe)
            if parsed["version"] and parsed["version"] != "*":
                detected_version = parsed["version"]
                break
    ...
    if detected_version:
        if not VersionMatcher.match(detected_version, required_range):
            version_mismatch = True
            confidence = 0.0
```
→ **Vấn đề:** Logic chỉ chạy khi `cve in _CVE_VERSION_RANGES` — tức là CVE ngoài whitelist sẽ KHÔNG BAO GIỜ bị filter dù version sai.

**Code 3 — Substring fallback quá "lỏng" (L264–275):**
```python
normalized = re.sub(r'[/_\-]', ' ', tech_string.lower())
if not matched and rule["pattern"] in normalized:
    matched = True
    ver_regex = rule.get("version_regex", "")
    if ver_regex:
        if VersionMatcher.match(tech_string, ver_regex):
            confidence = 0.9
        else:
            continue
    else:
        confidence = 0.6  # Substring match, không version verify
```
→ **Vấn đề:** Rule `"pattern": "windows"` + `"cve": "CVE-2017-0144"` sẽ match bất kỳ tech_string nào chứa "windows" (vd: `Windows 11 Pro` của client, header banner giả, v.v.) mà không filter theo OS family của target.

### 1.3. Các THIẾU SÓT so với yêu cầu P0-3

| # | Tính năng P0-3 yêu cầu | Hiện trạng | Gap |
|---|---|---|---|
| 1 | Cross-validate Nmap CPE vs httpx tech-detect (2 nguồn) | ⚠️ Có `_smart_cpe_filter()` nhưng chưa tích hợp vào pipeline chính (chỉ là helper) | Cần formalize thành module độc lập, callable từ `_match_tech_rule()` |
| 2 | Version range matching | ⚠️ Chỉ hardcode 4 CVE; rule-based không có | Cần load range từ VulnDB hoặc NVD JSON, hoặc hỗ trợ range syntax (`>=2.4.0,<2.4.50`) |
| 3 | OS-based filtering | ❌ Hoàn toàn vắng mặt | Cần thêm `target_os` param, check CVE/OS compatibility |
| 4 | EPSS score ranking | ⚠️ Plugin đã load (`self._epss_plugin`) nhưng chưa thấy dùng trong `_match_tech_rule()` để rank CVE trước khi output | Cần query EPSS, sort/score output |
| 5 | Modular (tách `core/cpe_filter.py`) | ❌ Logic nằm trong `VulnAnalyzer` class lớn | Cần tách thành module riêng để unit-test |

---

## 2. Đề xuất `core/cpe_filter.py` (mới)

> **Mục tiêu:** Tách toàn bộ CPE/version/OS/EPSS logic ra khỏi `VulnAnalyzer` thành một module chuyên trách, có thể unit-test độc lập và tái sử dụng.

### 2.1. Cấu trúc module

```
core/
└── cpe_filter.py          # NEW — Smart CPE Filter (P0-3)
    ├── class SmartCPEFilter        # Cross-validate CPE
    ├── class VersionRangeMatcher   # Range-aware matching
    ├── class OSGate                # OS-based CVE filtering
    ├── class EPSSRanker            # EPSS/KEV-based priority scoring
    └── class FilterPipeline        # Orchestrator (gọi 4 class trên theo thứ tự)
```

### 2.2. Code skeleton

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# core/cpe_filter.py — Smart CPE Filter (P0-3)
# Tách từ scripts/Module2_VulnAnalysis.py để:
#   1. Cross-validate Nmap CPE vs httpx tech-detect (2 nguồn độc lập)
#   2. Version range matching (vd: Apache 2.4.49 → check CVE affected range)
#   3. OS-based filtering (Windows CVE chỉ apply cho Windows target)
#   4. EPSS score ranking để ưu tiên CVE có khả năng exploit cao
#
# Acceptance: giảm false-positive ≥ 60% so với logic hiện tại.

import re
import logging
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

# Reuse from existing module — không duplicate
from scripts.Module2_VulnAnalysis import (
    CPEMatcher,
    VersionMatcher,
    _CVE_VERSION_RANGES,   # Backward-compat cho 4 CVE đã có
    _INFRA_CVE_KEYWORDS,
)


# === 1. Data classes ===

@dataclass
class CVEHit:
    """Một CVE match candidate trước khi qua filter pipeline."""
    cve: str
    confidence: float
    description: str = ""
    match_type: str = "unknown"      # "cpe" | "pattern" | "range"
    version_mismatch: bool = False
    source_rule: Optional[Dict] = None
    target_os: Optional[str] = None   # "windows" | "linux" | "*"
    epss_score: float = 0.0           # 0.0 - 1.0
    in_kev: bool = False              # CISA KEV catalog
    severity: str = "unknown"


@dataclass
class FilterResult:
    """Output cuối cùng sau khi qua pipeline."""
    kept: List[CVEHit] = field(default_factory=list)
    dropped: List[Tuple[CVEHit, str]] = field(default_factory=list)  # (hit, reason)
    stats: Dict[str, int] = field(default_factory=dict)


# === 2. Cross-validation Nmap CPE ↔ httpx tech-detect ===

class SmartCPEFilter:
    """
    Cross-validate CPE strings từ Nmap với tech names từ httpx.
    
    Nguyên tắc:
    - Nmap (port-scan, banner-grab) có thể bịa CPE do banner giả
    - httpx (active HTTP probe) phân tích response headers/body thực
    - Nếu 2 nguồn XUNG ĐỘT (vd: Nmap=Apache, httpx=Nginx) → drop CPE Nmap
    - Nếu httpx không detect được (missing data != wrong data) → giữ CPE Nmap
    """

    # Map httpx tech → CPE product keywords (mở rộng từ V1.0)
    TECH_TO_CPE_KEYWORDS = {
        # Web Servers
        'nginx': ['nginx'],
        'apache': ['apache', 'http_server', 'httpd'],
        'iis': ['iis', 'internet_information_services'],
        'tomcat': ['tomcat'],
        'lighttpd': ['lighttpd'],
        'caddy': ['caddy'],
        # Frameworks
        'laravel': ['laravel'],
        'django': ['django'],
        'flask': ['flask'],
        'spring': ['spring', 'springframework'],
        'express': ['express', 'node.js'],
        # CMS
        'wordpress': ['wordpress'],
        'drupal': ['drupal'],
        'joomla': ['joomla'],
    }

    @classmethod
    def cross_validate(cls, nmap_cpes: List[str], httpx_techs: List[str]) -> List[str]:
        """
        Trả về danh sách CPE đã được lọc.
        
        Args:
            nmap_cpes: CPE strings từ Nmap script `http-fingerprinthub-fingerprinthub`
            httpx_techs: Tech names từ httpx -tech-detect
        
        Returns:
            List CPE đã loại bỏ conflict.
        """
        if not httpx_techs or not nmap_cpes:
            return nmap_cpes  # Thiếu data → không filter (safe default)

        # Normalize httpx techs → lowercase
        httpx_lower = [t.lower() for t in httpx_techs if t]
        
        valid_cpes = []
        dropped = 0
        for cpe in nmap_cpes:
            parsed = CPEMatcher.parse_cpe(cpe)
            product = parsed.get("product", "")
            vendor = parsed.get("vendor", "")
            
            # Check if this CPE conflicts with ANY httpx tech
            conflict = False
            for tech in httpx_lower:
                # Tìm keywords expected cho tech này
                expected_keywords = cls.TECH_TO_CPE_KEYWORDS.get(tech, [tech])
                
                # Nếu CPE product KHÔNG match bất kỳ keyword nào của httpx tech
                # → có thể là conflict (vd: Nmap=apache:http_server, httpx=nginx)
                if not any(kw in product for kw in expected_keywords):
                    # Verify: httpx có detect 1 tech khác match CPE không?
                    for other_tech, other_kws in cls.TECH_TO_CPE_KEYWORDS.items():
                        if other_tech == tech:
                            continue
                        if any(kw in product for kw in other_kws):
                            # Conflict detected: httpx nói A, Nmap CPE thuộc về B
                            logging.info(
                                f"[SmartCPE] DROP conflict CPE: {cpe} "
                                f"(httpx says '{tech}' but CPE vendor:product={vendor}:{product})"
                            )
                            conflict = True
                            break
                if conflict:
                    break
            
            if not conflict:
                valid_cpes.append(cpe)
            else:
                dropped += 1
        
        if dropped:
            logging.info(f"[SmartCPE] Cross-validation: dropped {dropped}/{len(nmap_cpes)} conflicting CPEs")
        return valid_cpes


# === 3. Version Range Matching ===

class VersionRangeMatcher:
    """
    Match version string với CPE affected ranges.
    
    Hỗ trợ 2 format:
    - Simple regex: "2\\.4\\.49" (backward compat với _CVE_VERSION_RANGES)
    - Range syntax: ">=2.4.0,<2.4.50" hoặc "2.4.0-2.4.49"
    """

    @staticmethod
    def parse_range_spec(spec: str) -> Dict[str, Any]:
        """
        Parse range spec → structured query.
        
        VD:
            "2\\.4\\.49" → {"type": "regex", "pattern": "2\\.4\\.49"}
            ">=2.4.0,<2.4.50" → {"type": "compound", "constraints": [...]}
            "2.4.0-2.4.49" → {"type": "interval", "low": "2.4.0", "high": "2.4.49"}
        """
        if not spec:
            return {"type": "any"}
        
        spec = spec.strip()
        
        # Compound: comma-separated constraints (>=, <=, =, >, <)
        if any(op in spec for op in (">=", "<=", ">", "<", "=")):
            constraints = []
            for part in spec.split(","):
                part = part.strip()
                m = re.match(r'^(>=|<=|>|<|=)\s*(.+)$', part)
                if m:
                    constraints.append({"op": m.group(1), "ver": m.group(2)})
            return {"type": "compound", "constraints": constraints}
        
        # Interval: low-high (vd: "2.4.0-2.4.49")
        if "-" in spec and not spec.startswith("^"):
            parts = spec.split("-", 1)
            if len(parts) == 2 and "." in parts[0] and "." in parts[1]:
                return {"type": "interval", "low": parts[0], "high": parts[1]}
        
        # Default: regex
        return {"type": "regex", "pattern": spec}

    @staticmethod
    def match_range(version: str, spec: str) -> bool:
        """
        Check version có nằm trong range không.
        
        Returns:
            True nếu version MATCH range (affected), False nếu ngoài range.
        """
        parsed = VersionRangeMatcher.parse_range_spec(spec)
        
        if parsed["type"] == "any":
            return True
        
        if parsed["type"] == "regex":
            # Delegate to existing VersionMatcher
            return VersionMatcher.match(version, parsed["pattern"])
        
        if parsed["type"] == "interval":
            return VersionRangeMatcher._version_in_interval(version, parsed["low"], parsed["high"])
        
        if parsed["type"] == "compound":
            for c in parsed["constraints"]:
                if not VersionRangeMatcher._version_constraint(version, c):
                    return False
            return True
        
        return False

    @staticmethod
    def _version_tuple(v: str) -> Tuple[int, ...]:
        """Convert "2.4.49" → (2, 4, 49). Padding for comparison."""
        parts = re.split(r'[.\-_]', v)
        result = []
        for p in parts:
            m = re.match(r'(\d+)', p)
            if m:
                result.append(int(m.group(1)))
            else:
                result.append(0)
        return tuple(result) if result else (0,)

    @classmethod
    def _version_in_interval(cls, version: str, low: str, high: str) -> bool:
        v = cls._version_tuple(version)
        return cls._version_tuple(low) <= v <= cls._version_tuple(high)

    @classmethod
    def _version_constraint(cls, version: str, constraint: Dict) -> bool:
        op = constraint["op"]
        target = cls._version_tuple(constraint["ver"])
        v = cls._version_tuple(version)
        if op == ">=": return v >= target
        if op == "<=": return v <= target
        if op == ">":  return v >  target
        if op == "<":  return v <  target
        if op == "=":  return v == target
        return False


# === 4. OS-based Filtering ===

class OSGate:
    """
    Lọc CVE theo OS compatibility.
    
    Nguyên tắc:
    - CVE-2017-0144 (EternalBlue) chỉ áp dụng cho Windows (SMBv1)
    - CVE-2021-44228 (Log4Shell) chỉ áp dụng nếu target chạy Java app
    - Windows-only CVE không nên flag trên Linux target
    """

    # Map CVE → required OS family. "*" = any OS.
    # Có thể load từ VulnDB JSON sau, hardcode cho P0-3.
    _CVE_OS_REQUIREMENTS = {
        # Windows-only
        "CVE-2017-0144": {"windows"},       # EternalBlue (SMBv1)
        "CVE-2017-7269": {"windows"},       # IIS 6 WebDAV buffer overflow
        "CVE-2019-0708":  {"windows"},      # BlueKeep (RDP)
        "CVE-2020-0796":  {"windows"},      # SMBGhost
        "CVE-2021-31166": {"windows"},      # HTTP.sys
        "CVE-2021-34527": {"windows"},      # PrintNightmare
        # Linux-only
        "CVE-2014-6271":  {"linux"},        # Shellshock (bash)
        "CVE-2021-44228": {"linux", "any"}, # Log4Shell — Java multi-platform, treat carefully
        # Cross-platform (no entry needed)
        # "CVE-2021-41773": {"any"},  # Apache — works on any OS
    }

    @classmethod
    def is_compatible(cls, cve: str, target_os: Optional[str]) -> bool:
        """
        Check CVE có compatible với target OS không.
        
        Args:
            cve: CVE ID
            target_os: "windows" | "linux" | "macos" | None | "*"
        
        Returns:
            True nếu compatible (giữ CVE) hoặc không có requirement (safe default).
            False nếu OS mismatch (drop CVE).
        """
        if not target_os or target_os in ("*", "unknown"):
            return True  # Không biết OS → giữ CVE (safe)
        
        target_os_lower = target_os.lower()
        requirements = cls._CVE_OS_REQUIREMENTS.get(cve)
        
        if requirements is None:
            return True  # CVE không có OS requirement → giữ
        
        if "any" in requirements:
            return True
        
        return target_os_lower in requirements

    @classmethod
    def detect_target_os(cls, nmap_cpes: List[str], tech_stack: List[str]) -> str:
        """
        Heuristic: đoán OS target từ CPE/tech stack.
        
        Returns:
            "windows" | "linux" | "macos" | "unknown"
        """
        signals = " ".join(nmap_cpes + tech_stack).lower()
        win_count = sum(signals.count(k) for k in ["microsoft", "windows", "iis", "asp.net"])
        linux_count = sum(signals.count(k) for k in ["linux", "ubuntu", "debian", "centos", "redhat", "nginx", "apache"])
        
        if win_count > linux_count and win_count > 0:
            return "windows"
        if linux_count > win_count and linux_count > 0:
            return "linux"
        return "unknown"


# === 5. EPSS-based Ranking ===

class EPSSRanker:
    """
    Rank CVE theo EPSS (Exploit Prediction Scoring System) + KEV catalog.
    
    EPSS score: 0.0 - 1.0 (xác suất bị exploit trong 30 ngày tới)
    KEV: CISA Known Exploited Vulnerabilities — đã bị exploit thực tế
    
    Higher score → ưu tiên cao hơn trong attack plan.
    """

    # Cache EPSS scores trong session để tránh query lặp
    _cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, epss_plugin=None, kev_plugin=None):
        self.epss_plugin = epss_plugin
        self.kev_plugin = kev_plugin

    def enrich(self, hits: List[CVEHit]) -> List[CVEHit]:
        """
        Gắn EPSS score + KEV flag vào mỗi CVEHit.
        """
        for hit in hits:
            try:
                data = self._fetch_score(hit.cve)
                hit.epss_score = data.get("epss", 0.0)
                hit.in_kev = data.get("kev", False)
            except Exception as e:
                logging.warning(f"[EPSSRanker] Failed to fetch score for {hit.cve}: {e}")
        return hits

    def _fetch_score(self, cve: str) -> Dict[str, Any]:
        """Fetch EPSS + KEV từ plugins (có cache)."""
        if cve in self._cache:
            return self._cache[cve]
        
        result = {"epss": 0.0, "kev": False}
        if self.epss_plugin:
            try:
                result["epss"] = float(self.epss_plugin.get_score(cve) or 0.0)
            except Exception:
                pass
        if self.kev_plugin:
            try:
                result["kev"] = bool(self.kev_plugin.is_in_kev(cve))
            except Exception:
                pass
        
        self._cache[cve] = result
        return result

    @staticmethod
    def rank(hits: List[CVEHit], top_n: Optional[int] = None) -> List[CVEHit]:
        """
        Sort CVE theo priority: KEV > EPSS > Confidence > Severity.
        
        Args:
            hits: List CVEHit (đã enrich)
            top_n: Nếu set, chỉ trả về top N (vd: top 10)
        
        Returns:
            List sorted theo priority score giảm dần.
        """
        severity_value = {
            "critical": 1.0, "high": 0.8, "medium": 0.5,
            "low": 0.2, "info": 0.05, "unknown": 0.3,
        }
        
        def priority_score(h: CVEHit) -> float:
            kev_bonus = 1.0 if h.in_kev else 0.0
            return (
                kev_bonus * 100         # KEV đứng đầu tuyệt đối
                + h.epss_score * 10     # EPSS 0-10 điểm
                + h.confidence          # 0-1 điểm
                + severity_value.get(h.severity, 0.3)
            )
        
        ranked = sorted(hits, key=priority_score, reverse=True)
        return ranked[:top_n] if top_n else ranked


# === 6. Filter Pipeline (Orchestrator) ===

class FilterPipeline:
    """
    Gọi 4 filter theo thứ tự:
      1. SmartCPEFilter.cross_validate()  — loại CPE xung đột Nmap/httpx
      2. VersionRangeMatcher.match_range() — loại CVE ngoài version range
      3. OSGate.is_compatible()          — loại CVE không khớp OS
      4. EPSSRanker.enrich() + rank()    — gắn score và sort
    
    Đây là entry point duy nhất mà VulnAnalyzer sẽ gọi.
    """

    def __init__(self, epss_plugin=None, kev_plugin=None):
        self.epss_ranker = EPSSRanker(epss_plugin, kev_plugin)

    def run(
        self,
        raw_hits: List[CVEHit],
        nmap_cpes: List[str],
        httpx_techs: List[str],
        target_os: Optional[str] = None,
        top_n: Optional[int] = None,
    ) -> FilterResult:
        """
        Args:
            raw_hits: CVE candidates từ _match_tech_rule()
            nmap_cpes: CPE strings từ Nmap (input cho SmartCPEFilter)
            httpx_techs: Tech names từ httpx (input cho SmartCPEFilter)
            target_os: "windows" | "linux" | None (sẽ auto-detect nếu None)
            top_n: Giới hạn output (vd: top 20 CVE)
        
        Returns:
            FilterResult với kept/dropped/stats
        """
        result = FilterResult()
        result.stats["input_count"] = len(raw_hits)
        
        # Auto-detect OS nếu không có
        if not target_os:
            target_os = OSGate.detect_target_os(nmap_cpes, [])
            logging.debug(f"[FilterPipeline] Auto-detected target OS: {target_os}")
        
        # Step 1: Cross-validate CPE (filter theo NGUỒN dữ liệu)
        validated_cpes = SmartCPEFilter.cross_validate(nmap_cpes, httpx_techs)
        result.stats["cpes_after_xvalidation"] = len(validated_cpes)
        
        # Step 2-4: Filter từng CVE
        kept: List[CVEHit] = []
        for hit in raw_hits:
            # Step 2: Version range check
            range_spec = hit.source_rule.get("version_regex") if hit.source_rule else None
            if range_spec and hit.match_type == "cpe":
                # Nếu có version_regex từ rule và đã match CPE
                parsed_ver = None
                for cpe in validated_cpes:
                    parsed = CPEMatcher.parse_cpe(cpe)
                    if parsed["product"] == hit.source_rule.get("cpe_product"):
                        parsed_ver = parsed.get("version")
                        break
                if parsed_ver and parsed_ver != "*":
                    if not VersionRangeMatcher.match_range(parsed_ver, range_spec):
                        result.dropped.append((hit, "version_out_of_range"))
                        continue
            
            # Step 3: OS gate
            if not OSGate.is_compatible(hit.cve, target_os):
                result.dropped.append((hit, f"os_mismatch:{target_os}"))
                continue
            
            kept.append(hit)
        
        result.stats["after_version_filter"] = len(kept)
        
        # Step 4: EPSS enrichment + ranking
        kept = self.epss_ranker.enrich(kept)
        kept = EPSSRanker.rank(kept, top_n=top_n)
        
        result.kept = kept
        result.stats["final_count"] = len(kept)
        result.stats["dropped_count"] = len(result.dropped)
        
        # Tính false-positive reduction rate
        if raw_hits:
            fp_reduction = (len(result.dropped) / len(raw_hits)) * 100
            result.stats["fp_reduction_pct"] = round(fp_reduction, 1)
            logging.info(
                f"[FilterPipeline] {len(raw_hits)} → {len(kept)} CVE "
                f"(FP reduction: {fp_reduction:.1f}%)"
            )
        
        return result


# === Public API ===

def filter_cves(
    raw_hits: List[CVEHit],
    nmap_cpes: List[str],
    httpx_techs: List[str],
    target_os: Optional[str] = None,
    epss_plugin=None,
    kev_plugin=None,
    top_n: Optional[int] = 20,
) -> FilterResult:
    """
    Convenience function — entry point chính cho VulnAnalyzer.
    
    Usage trong Module2_VulnAnalysis.py:
        from core.cpe_filter import filter_cves, CVEHit
        ...
        hits = [CVEHit(...) for ... in matches]
        result = filter_cves(hits, cpe_list, httpx_tech, target_os,
                             self._epss_plugin, self._kev_plugin, top_n=20)
        return [h.__dict__ for h in result.kept]
    """
    pipeline = FilterPipeline(epss_plugin, kev_plugin)
    return pipeline.run(raw_hits, nmap_cpes, httpx_techs, target_os, top_n)
```

### 2.3. Luồng xử lý (data flow)

```
┌─────────────────────┐
│ VulnAnalyzer        │
│ ._match_tech_rule() │  → raw CVE candidates (CVEHit list)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────────┐
│ FilterPipeline.run()                             │
│                                                   │
│  ① SmartCPEFilter.cross_validate()               │
│     ├─ Input: nmap_cpes + httpx_techs            │
│     └─ Output: validated_cpes (loại conflict)    │
│                                                   │
│  ② VersionRangeMatcher.match_range()             │
│     ├─ Check version_regex vs CPE version        │
│     └─ DROP nếu ngoài affected range             │
│                                                   │
│  ③ OSGate.is_compatible()                        │
│     ├─ Check CVE OS requirement vs target_os     │
│     └─ DROP nếu mismatch                         │
│                                                   │
│  ④ EPSSRanker.enrich() + rank()                  │
│     ├─ Query EPSS score + KEV flag               │
│     ├─ Sort: KEV > EPSS > Confidence > Severity  │
│     └─ Truncate top_n                             │
└──────────┬──────────────────────────────────────┘
           │
           ▼
┌─────────────────────┐
│ FilterResult        │
│   .kept (ranked)    │  → return cho attack plan generator
│   .dropped (audit)  │
│   .stats (metrics)  │
└─────────────────────┘
```

---

## 3. Files cần sửa

| # | File | Action | Mô tả |
|---|---|---|---|
| 1 | `core/cpe_filter.py` | **NEW** | Tạo mới module Smart CPE Filter (skeleton ở §2.2) |
| 2 | `scripts/Module2_VulnAnalysis.py` | **MODIFY** | (a) Import `core.cpe_filter`; (b) Trong `VulnAnalyzer._match_tech_rule()` thay phần return bằng gọi `filter_cves()`; (c) Trong `VulnAnalyzer.__init__()` truyền `self._epss_plugin`, `self._kev_plugin` vào pipeline |
| 3 | `tests/test_cpe_filter.py` | **NEW** | Unit test cho 4 class (cross-validate, version range, OS gate, EPSS rank) — optional nhưng khuyến nghị cho acceptance criteria |
| 4 | `core/vuln_db.json` (nếu có) | **MODIFY (optional)** | Bổ sung field `os_requirement` và `version_range` cho mỗi rule (vd: `"cve": "CVE-2017-0144", "os_requirement": ["windows"]`) |

### 3.1. Patch chi tiết cho `scripts/Module2_VulnAnalysis.py`

**Vị trí 1 — Top of file (sau line 22):**
```python
# Thêm import
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.registry import PluginRegistry
from core.cpe_filter import filter_cves, CVEHit  # ← NEW
from config import Config
```

**Vị trí 2 — Cuối `VulnAnalyzer._match_tech_rule()` (khoảng line 317, trước `return matches`):**
```python
# OLD:
        return matches

# NEW:
        # P0-3: Convert sang CVEHit rồi qua FilterPipeline
        hits = [
            CVEHit(
                cve=m["cve"],
                confidence=m["confidence"],
                description=m["description"],
                match_type=m["match_type"],
                version_mismatch=m.get("version_mismatch", False),
                source_rule=rule,
                severity=rule.get("severity", "unknown"),
            )
            for m in matches
        ]
        
        # Lấy inputs cho pipeline
        nmap_cpes = cpe_list if cpe_list else []
        httpx_techs = getattr(self, "_last_httpx_tech", [])  # inject từ caller
        
        target_os = None  # Có thể detect từ nmap scan result nếu có
        
        result = filter_cves(
            raw_hits=hits,
            nmap_cpes=nmap_cpes,
            httpx_techs=httpx_techs,
            target_os=target_os,
            epss_plugin=self._epss_plugin,
            kev_plugin=self._kev_plugin,
            top_n=20,
        )
        
        # Convert ngược về dict format cũ (backward compat)
        return [
            {
                "cve": h.cve,
                "confidence": h.confidence,
                "description": h.description,
                "match_type": h.match_type,
                "version_mismatch": h.version_mismatch,
                "epss_score": h.epss_score,
                "in_kev": h.in_kev,
                "severity": h.severity,
            }
            for h in result.kept
        ]
```

**Vị trí 3 — Inject httpx_tech trước khi gọi `_match_tech_rule()` (trong hàm main analyze):**
```python
# Trong VulnAnalyzer.analyze() hoặc tương đương:
self._last_httpx_tech = target.get("httpx_tech", [])  # cache cho filter
```

---

## 4. Acceptance Criteria

### 4.1. Functional Requirements (PASS/FAIL)

- [ ] **AC-1:** Module `core/cpe_filter.py` được tạo với 4 class + 1 orchestrator
- [ ] **AC-2:** `SmartCPEFilter.cross_validate()` loại CPE conflict giữa Nmap và httpx (test case: Nmap=Apache, httpx=Nginx → drop Apache CPE)
- [ ] **AC-3:** `VersionRangeMatcher.match_range()` hỗ trợ cả 3 format: regex, interval (`2.4.0-2.4.49`), compound (`>=2.4.0,<2.4.50`)
- [ ] **AC-4:** `OSGate.is_compatible()` drop Windows-only CVE khi target OS = Linux (test case: CVE-2017-0144 + target_os="linux" → False)
- [ ] **AC-5:** `EPSSRanker.rank()` sort CVE có KEV=True lên đầu, sau đó EPSS giảm dần
- [ ] **AC-6:** `VulnAnalyzer._match_tech_rule()` gọi `filter_cves()` thay vì return raw list

### 4.2. Performance Metrics (quan trọng nhất)

| Metric | Baseline (hiện tại) | Target (P0-3) | Measurement |
|---|---|---|---|
| **False-positive reduction** | 0% (no filter) | **≥ 60%** | Số CVE bị `dropped` / tổng số CVE candidate × 100% |
| **Version-mismatch false positives** | Cho 4 CVE đã hardcode | Cho TẤT CẢ CVE có version_regex/range | Test với 10 CVE known-version |
| **OS-mismatch false positives** | Không filter | 100% drop nếu mismatch | Test CVE-2017-0144 trên Linux target |
| **EPSS query overhead** | N/A | ≤ 500ms / CVE (cached) | Đo thời gian với 50 CVE |
| **Output ranking quality** | Không rank | KEV CVE xếp đầu | Verify thủ công 5 CVE known-KEV |

### 4.3. Test plan cụ thể để verify AC

**Test 1 — Cross-validation (AC-2):**
```
Input:
  nmap_cpes = ["cpe:2.3:a:apache:http_server:2.4.49", "cpe:2.3:o:microsoft:windows_10"]
  httpx_techs = ["Nginx", "PHP"]
Expected:
  Output CPEs chỉ còn "cpe:2.3:o:microsoft:windows_10"
  Drop count = 1
  Log: "[SmartCPE] DROP conflict CPE: cpe:2.3:a:apache:http_server:2.4.49 (httpx says 'nginx' but CPE vendor:product=apache:http_server)"
```

**Test 2 — Version range (AC-3):**
```
Input:
  Apache version = "2.4.51"
  Range spec = "2.4.0-2.4.49"  (affected for CVE-2021-41773 patch range)
Expected:
  match_range("2.4.51", "2.4.0-2.4.49") = False  (out of range → drop CVE)
```

**Test 3 — OS gate (AC-4):**
```
Input:
  CVE = "CVE-2017-0144"  (EternalBlue — Windows SMBv1 only)
  target_os = "linux"
Expected:
  OSGate.is_compatible("CVE-2017-0144", "linux") = False  (drop)
```

**Test 4 — EPSS ranking (AC-5):**
```
Input:
  hits = [
    CVEHit("CVE-A", epss=0.05, in_kev=False, confidence=0.9),
    CVEHit("CVE-B", epss=0.8, in_kev=False, confidence=0.9),
    CVEHit("CVE-C", epss=0.3, in_kev=True, confidence=0.9),
  ]
Expected order:
  ["CVE-C", "CVE-B", "CVE-A"]  (KEV > EPSS > Confidence)
```

**Test 5 — End-to-end FP reduction (AC Performance):**
```
Input:
  Raw hits: 50 CVE candidates (mix of true positives + false positives)
  - 10 CVE có version ngoài affected range (vd: Apache 2.4.51 vs CVE for 2.4.49)
  - 5 CVE là Windows-only nhưng target là Linux
  - 5 CPE conflict (Nmap vs httpx)
  - 30 CVE hợp lệ
Expected:
  Filtered output: ≤ 20 CVE
  FP reduction = (50 - 20) / 50 = 60%  ✅ PASS
```

### 4.4. Backward Compatibility

- [ ] **BC-1:** Output format của `_match_tech_rule()` giữ nguyên dict structure (thêm 3 field: `epss_score`, `in_kev`, `severity`)
- [ ] **BC-2:** Nếu `httpx_techs` rỗng, filter vẫn chạy (safe default: giữ CPE Nmap)
- [ ] **BC-3:** Nếu EPSS plugin lỗi/network down, score = 0.0 (không crash pipeline)
- [ ] **BC-4:** `top_n=None` → return tất cả CVE sau filter (không truncate)

---

## 5. Rollout Plan (3 phases)

| Phase | Scope | Risk | Rollback |
|---|---|---|---|
| **Phase 1** (Day 1) | Tạo `core/cpe_filter.py` + unit test, KHÔNG sửa `Module2_VulnAnalysis.py` | Low | Xóa file mới |
| **Phase 2** (Day 2) | Wire `FilterPipeline` vào `VulnAnalyzer._match_tech_rule()` với `top_n=None` (giữ tất cả CVE, chỉ thêm score) | Medium | Revert patch, giữ module mới |
| **Phase 3** (Day 3) | Bật `top_n=20` + log dropped CVEs, đo FP reduction rate | Low | Set `top_n=None` để disable truncation |

---

## 6. Out of Scope (deferred)

- Auto-update EPSS scores từ NVD API (chỉ dùng plugin hiện có)
- CPE 2.2 format support (chỉ CPE 2.3)
- Multi-target batch filtering (chỉ single-target per call)
- GUI/web dashboard cho filter stats (chỉ logging)

---

## 7. References

- NVD CPE Dictionary: https://nvd.nist.gov/vuln/vulnerabilities
- EPSS API: https://api.first.org/data/v1/epss
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Existing code: `scripts/Module2_VulnAnalysis.py` lines 73–78 (`_CVE_VERSION_RANGES`), 229–317 (`_match_tech_rule`), 360+ (`_smart_cpe_filter`)
