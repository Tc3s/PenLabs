#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-3] Smart CPE Filter.

Cross-validates Nmap/Shodan CPEs with HttpX tech-detect, applies affected
version ranges, drops OS-incompatible CVEs, and ranks candidates by KEV/EPSS.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from core.version_range import COMMON_CVE_RANGES, VersionRange

logger = logging.getLogger(__name__)


TECH_TO_CPE_KEYWORDS: Dict[str, List[str]] = {
    # Web servers
    "nginx": ["nginx"],
    "apache": ["apache", "http_server", "httpd"],
    "iis": ["iis", "internet_information_services"],
    "tomcat": ["tomcat"],
    "jetty": ["jetty"],
    "lighttpd": ["lighttpd"],
    "caddy": ["caddy"],
    "envoy": ["envoy"],
    "haproxy": ["haproxy"],
    "squid": ["squid"],
    # Runtimes / frameworks
    "python": ["python", "cpython"],
    "node.js": ["node.js", "nodejs"],
    "nodejs": ["node.js", "nodejs"],
    "php": ["php"],
    "ruby": ["ruby", "ruby_on_rails"],
    "java": ["java", "openjdk", "oracle_jdk", "log4j"],
    "go": ["go"],
    "perl": ["perl"],
    "asp.net": ["asp.net"],
    "django": ["django"],
    "flask": ["flask"],
    "express": ["express"],
    "express.js": ["express"],
    "rails": ["ruby_on_rails", "rails"],
    "laravel": ["laravel"],
    "spring": ["spring", "spring_boot", "spring_framework"],
    "fastapi": ["fastapi"],
    "next.js": ["next.js"],
    "nuxt.js": ["nuxt.js"],
    # CMS
    "wordpress": ["wordpress"],
    "drupal": ["drupal"],
    "joomla": ["joomla"],
    "magento": ["magento"],
    "shopify": ["shopify"],
    # Databases
    "mysql": ["mysql"],
    "postgresql": ["postgresql", "postgres"],
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "elasticsearch": ["elasticsearch"],
    "mariadb": ["mariadb"],
    # OS
    "ubuntu": ["ubuntu", "canonical"],
    "debian": ["debian"],
    "centos": ["centos"],
    "redhat": ["redhat", "rhel"],
    "windows": ["windows", "microsoft_windows"],
    "linux": ["linux", "linux_kernel"],
    "freebsd": ["freebsd"],
}

WINDOWS_CPE_KEYWORDS = [
    "windows",
    "microsoft",
    "iis",
    "asp.net",
    "mssql",
    ".net_framework",
    "exchange",
    "sharepoint",
    "smb",
]

LINUX_CPE_KEYWORDS = [
    "linux",
    "ubuntu",
    "debian",
    "centos",
    "redhat",
    "rhel",
    "apache",
    "nginx",
    "mysql",
    "postgresql",
    "php",
]

_SEVERITY_VALUES = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "info": 0.05,
    "unknown": 0.3,
    "": 0.3,
}


def _parse_cpe(cpe_string: str) -> Dict[str, str]:
    parts = (cpe_string or "").lower().split(":")
    if len(parts) >= 5:
        return {
            "raw": cpe_string.lower(),
            "type": parts[2] if len(parts) > 2 else "",
            "vendor": parts[3] if len(parts) > 3 else "",
            "product": parts[4] if len(parts) > 4 else "",
            "version": parts[5] if len(parts) > 5 else "*",
        }
    return {"raw": cpe_string.lower(), "type": "", "vendor": "", "product": "", "version": ""}


def _version_tuple(v: str) -> Tuple[int, ...]:
    nums = []
    for part in re.split(r"[.\-_]", v or ""):
        match = re.match(r"(\d+)", part)
        nums.append(int(match.group(1)) if match else 0)
    return tuple(nums) if nums else (0,)


def _pad_versions(a: Tuple[int, ...], b: Tuple[int, ...]) -> Tuple[Tuple[int, ...], Tuple[int, ...]]:
    size = max(len(a), len(b))
    return a + (0,) * (size - len(a)), b + (0,) * (size - len(b))


@dataclass
class CVEHit:
    cve: str
    confidence: float
    description: str = ""
    match_type: str = "unknown"
    version_mismatch: bool = False
    source_rule: Optional[Dict[str, Any]] = None
    target_os: Optional[str] = None
    epss_score: float = 0.0
    in_kev: bool = False
    severity: str = "unknown"


@dataclass
class FilterResult:
    kept: List[CVEHit] = field(default_factory=list)
    dropped: List[Tuple[CVEHit, str]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


class SmartCPEFilter:
    """Drop CPEs that contradict HttpX tech-detect evidence."""

    TECH_TO_CPE_KEYWORDS = TECH_TO_CPE_KEYWORDS

    def __init__(self, strict_mode: bool = False):
        self.strict_mode = strict_mode

    @classmethod
    def cross_validate(cls, nmap_cpes: List[str], httpx_techs: List[str]) -> List[str]:
        """
        Keep unrelated CPEs, drop known product conflicts.

        Missing HttpX data is not evidence of conflict, so the safe default is to
        keep the original Nmap/Shodan CPE list.
        """
        if not nmap_cpes or not httpx_techs:
            return nmap_cpes or []

        expected_keywords = cls._keywords_for_techs(httpx_techs)
        if not expected_keywords:
            return nmap_cpes

        known_product_keywords = {
            kw for keywords in cls.TECH_TO_CPE_KEYWORDS.values() for kw in keywords
        }
        valid_cpes = []
        dropped = 0
        for cpe in nmap_cpes:
            parsed = _parse_cpe(cpe)
            if parsed.get("type") == "o":
                valid_cpes.append(cpe)
                continue
            cpe_identity = f"{parsed['vendor']} {parsed['product']}"
            cpe_keywords = {kw for kw in known_product_keywords if kw in cpe_identity}

            # Unknown/unmapped product: keep. Known product that conflicts with
            # all HttpX tech signals: drop.
            if cpe_keywords and not cpe_keywords.intersection(expected_keywords):
                dropped += 1
                logger.info(
                    "[SmartCPE] DROP conflict CPE: %s (httpx=%s, cpe=%s:%s)",
                    cpe,
                    httpx_techs,
                    parsed["vendor"],
                    parsed["product"],
                )
                continue
            valid_cpes.append(cpe)

        if dropped:
            logger.info("[SmartCPE] Cross-validation dropped %d/%d CPEs", dropped, len(nmap_cpes))
        return valid_cpes

    @classmethod
    def _keywords_for_techs(cls, httpx_techs: List[str]) -> Set[str]:
        expected: Set[str] = set()
        for tech in httpx_techs:
            tech_lower = (tech or "").lower().strip()
            if not tech_lower:
                continue
            if tech_lower in cls.TECH_TO_CPE_KEYWORDS:
                expected.update(cls.TECH_TO_CPE_KEYWORDS[tech_lower])
            for tech_key, cpe_keywords in cls.TECH_TO_CPE_KEYWORDS.items():
                if tech_key in tech_lower or tech_lower in tech_key:
                    expected.update(cpe_keywords)
        return expected

    def filter(
        self,
        tech_stack: List[str],
        httpx_tech: List[str],
        target_os: str = "unknown",
    ) -> List[str]:
        if not tech_stack:
            return []
        if not httpx_tech and self.strict_mode:
            return []

        filtered = self.cross_validate(tech_stack, httpx_tech)
        return [cpe for cpe in filtered if is_os_compatible(cpe, target_os)]

    def enrich_with_versions(
        self,
        tech_stack: List[str],
        cve_ranges: Optional[Dict[str, str]] = None,
    ) -> List[Tuple[str, str, bool]]:
        results = []
        for cpe in tech_stack:
            version = self._extract_version_from_cpe(cpe)
            for cve_id, range_str in (cve_ranges or COMMON_CVE_RANGES).items():
                affected = bool(version and VersionRangeMatcher.match_range(version, range_str))
                results.append((cve_id, cpe, affected))
        return results

    @staticmethod
    def _extract_version_from_cpe(cpe: str) -> Optional[str]:
        version = _parse_cpe(cpe).get("version")
        return version if version and version != "*" else None

    def get_priority_tech(self, tech_stack: List[str], httpx_tech: List[str]) -> Optional[str]:
        if not tech_stack:
            return None
        expected = self._keywords_for_techs(httpx_tech)
        for cpe in tech_stack:
            parsed = _parse_cpe(cpe)
            if any(kw in f"{parsed['vendor']} {parsed['product']}" for kw in expected):
                return cpe
        for cpe in tech_stack:
            if self._extract_version_from_cpe(cpe):
                return cpe
        return tech_stack[0]


class VersionRangeMatcher:
    """Range-aware version matcher with regex backward compatibility."""

    @staticmethod
    def parse_range_spec(spec: str) -> Dict[str, Any]:
        if not spec:
            return {"type": "any"}
        spec = spec.strip()
        if any(op in spec for op in (">=", "<=", ">", "<", "=")):
            constraints = []
            for part in spec.split(","):
                match = re.match(r"^(>=|<=|>|<|=|==)\s*(.+)$", part.strip())
                if match:
                    constraints.append({"op": match.group(1), "ver": match.group(2)})
            return {"type": "compound", "constraints": constraints}
        if "-" in spec and not spec.startswith("^"):
            low, high = spec.split("-", 1)
            if "." in low and "." in high:
                return {"type": "interval", "low": low.strip(), "high": high.strip()}
        return {"type": "regex", "pattern": spec}

    @classmethod
    def match_range(cls, version: str, spec: str) -> bool:
        parsed = cls.parse_range_spec(spec)
        if parsed["type"] == "any":
            return True
        if parsed["type"] == "regex":
            try:
                pattern = r"(?<![\d.])" + parsed["pattern"] + r"(?![\d.])"
                return bool(re.search(pattern, version or "", re.IGNORECASE))
            except re.error:
                # Some entries are semver-style strings without explicit range
                # operators. Fall back to core.VersionRange exact matching.
                return VersionRange(parsed["pattern"]).contains(version)
        if parsed["type"] == "interval":
            return cls._version_in_interval(version, parsed["low"], parsed["high"])
        if parsed["type"] == "compound":
            return all(cls._version_constraint(version, c) for c in parsed["constraints"])
        return False

    @staticmethod
    def _version_in_interval(version: str, low: str, high: str) -> bool:
        v, lo = _pad_versions(_version_tuple(version), _version_tuple(low))
        v, hi = _pad_versions(v, _version_tuple(high))
        return lo <= v <= hi

    @staticmethod
    def _version_constraint(version: str, constraint: Dict[str, str]) -> bool:
        op = constraint["op"]
        v, target = _pad_versions(_version_tuple(version), _version_tuple(constraint["ver"]))
        if op in ("=", "=="):
            return v == target
        if op == ">=":
            return v >= target
        if op == "<=":
            return v <= target
        if op == ">":
            return v > target
        if op == "<":
            return v < target
        return False


class OSGate:
    """CVE-to-target OS compatibility gate."""

    _CVE_OS_REQUIREMENTS = {
        "CVE-2017-0144": {"windows"},
        "CVE-2017-7269": {"windows"},
        "CVE-2019-0708": {"windows"},
        "CVE-2020-0796": {"windows"},
        "CVE-2021-31166": {"windows"},
        "CVE-2021-34527": {"windows"},
        "CVE-2014-6271": {"linux"},
        "CVE-2021-44228": {"linux", "any"},
    }

    @classmethod
    def is_compatible(cls, cve: str, target_os: Optional[str]) -> bool:
        if not target_os or target_os.lower() in ("*", "unknown", "any"):
            return True
        requirements = cls._CVE_OS_REQUIREMENTS.get(cve)
        if not requirements or "any" in requirements:
            return True
        return target_os.lower() in requirements

    @classmethod
    def detect_target_os(cls, nmap_cpes: List[str], tech_stack: List[str]) -> str:
        signals = " ".join((nmap_cpes or []) + (tech_stack or [])).lower()
        win_count = sum(signals.count(k) for k in WINDOWS_CPE_KEYWORDS)
        linux_count = sum(signals.count(k) for k in LINUX_CPE_KEYWORDS)
        if win_count > linux_count and win_count > 0:
            return "windows"
        if linux_count > win_count and linux_count > 0:
            return "linux"
        return "unknown"


class EPSSRanker:
    """Enrich and rank CVE hits by KEV, EPSS, confidence, then severity."""

    _cache: Dict[str, Dict[str, Any]] = {}

    def __init__(self, epss_plugin=None, kev_plugin=None):
        self.epss_plugin = epss_plugin
        self.kev_plugin = kev_plugin

    def enrich(self, hits: List[CVEHit]) -> List[CVEHit]:
        cves = [hit.cve for hit in hits if hit.cve.startswith("CVE-")]
        epss_data = self._batch_epss(cves)
        kev_data = self._batch_kev(cves)
        for hit in hits:
            epss_info = epss_data.get(hit.cve, {})
            kev_info = kev_data.get(hit.cve, {})
            hit.epss_score = float(epss_info.get("epss", hit.epss_score or 0.0) or 0.0)
            hit.in_kev = bool(kev_info.get("is_kev", kev_info.get("kev", hit.in_kev)))
        return hits

    def _batch_epss(self, cves: List[str]) -> Dict[str, Dict[str, Any]]:
        if not self.epss_plugin or not cves:
            return {}
        try:
            if hasattr(self.epss_plugin, "batch_lookup"):
                return self.epss_plugin.batch_lookup(cves) or {}
            if hasattr(self.epss_plugin, "get_score"):
                return {cve: {"epss": float(self.epss_plugin.get_score(cve) or 0.0)} for cve in cves}
            if hasattr(self.epss_plugin, "run"):
                return {cve: self.epss_plugin.run(cve) for cve in cves}
        except Exception as exc:
            logger.warning("[EPSSRanker] EPSS lookup failed: %s", exc)
        return {}

    def _batch_kev(self, cves: List[str]) -> Dict[str, Dict[str, Any]]:
        if not self.kev_plugin or not cves:
            return {}
        try:
            if hasattr(self.kev_plugin, "batch_check"):
                return self.kev_plugin.batch_check(cves) or {}
            if hasattr(self.kev_plugin, "is_in_kev"):
                return {cve: {"is_kev": bool(self.kev_plugin.is_in_kev(cve))} for cve in cves}
            if hasattr(self.kev_plugin, "run"):
                return {cve: self.kev_plugin.run(cve) for cve in cves}
        except Exception as exc:
            logger.warning("[EPSSRanker] KEV lookup failed: %s", exc)
        return {}

    @classmethod
    def is_backport_version(cls, version: str) -> bool:
        """
        Detect if a version string contains Linux OS backport patch signatures
        (e.g., '2.4.41-4ubuntu3.1', '2.4.37-43.module_el8', 'debian', 'rhel').
        """
        if not version:
            return False
        pattern = r"(ubuntu|debian|el[5-9]|rhel|centos|alpine|arch)"
        return bool(re.search(pattern, version, re.IGNORECASE))

    @staticmethod
    def calculate_multi_factor_confidence(
        hit: CVEHit,
        is_backport: bool = False,
        verification_status: Optional[str] = None
    ) -> float:
        """
        Calculates multi-factor confidence score combining match type, OS backporting,
        active replay verification, EPSS, and KEV status.
        """
        base_confidence = hit.confidence

        # Backport patch penalty (unless actively verified)
        if is_backport and verification_status != "confirmed":
            base_confidence *= 0.5  # 50% confidence penalty for unverified backport strings

        # Active verification adjustments
        if verification_status == "confirmed":
            base_confidence = max(base_confidence, 0.95)
        elif verification_status == "noise":
            base_confidence = min(base_confidence, 0.1)

        # Low EPSS penalty for old unverified CVEs (only when EPSS score is explicitly present > 0 and low, or epss_score is explicitly evaluated)
        if not hit.in_kev and 0.0 < hit.epss_score < 0.001 and hit.cve.startswith("CVE-"):
            try:
                cve_year = int(hit.cve.split("-")[1])
                if cve_year <= 2021 and verification_status != "confirmed":
                    base_confidence *= 0.7
            except (IndexError, ValueError):
                pass

        return round(max(0.0, min(1.0, base_confidence)), 3)

    @staticmethod
    def rank(hits: List[CVEHit], top_n: Optional[int] = None) -> List[CVEHit]:
        def priority_score(hit: CVEHit) -> float:
            mf_conf = hit.confidence
            return (
                (100.0 if hit.in_kev else 0.0)
                + (hit.epss_score * 10.0)
                + (mf_conf * 5.0)
                + _SEVERITY_VALUES.get((hit.severity or "unknown").lower(), 0.3)
            )

        ranked = sorted(hits, key=priority_score, reverse=True)
        return ranked[:top_n] if top_n else ranked


class FilterPipeline:
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
        result = FilterResult(stats={"input_count": len(raw_hits)})
        target_os = target_os or OSGate.detect_target_os(nmap_cpes, httpx_techs)
        validated_cpes = SmartCPEFilter.cross_validate(nmap_cpes or [], httpx_techs or [])
        result.stats["cpes_after_xvalidation"] = len(validated_cpes)

        kept: List[CVEHit] = []
        for hit in raw_hits:
            if hit.version_mismatch:
                result.dropped.append((hit, "version_mismatch"))
                continue

            if not self._version_compatible(hit, validated_cpes):
                hit.version_mismatch = True
                result.dropped.append((hit, "version_out_of_range"))
                continue

            hit.target_os = target_os
            if not OSGate.is_compatible(hit.cve, target_os):
                result.dropped.append((hit, f"os_mismatch:{target_os}"))
                continue

            kept.append(hit)

        result.stats["after_version_filter"] = len(kept)
        kept = self.epss_ranker.enrich(kept)
        
        # Apply multi-factor confidence scoring to kept hits
        for hit in kept:
            rule = hit.source_rule or {}
            cpe_pattern = rule.get("cpe_pattern") or ""
            version_str = SmartCPEFilter._extract_version_from_cpe(cpe_pattern) or ""
            is_bp = EPSSRanker.is_backport_version(version_str)
            hit.confidence = EPSSRanker.calculate_multi_factor_confidence(
                hit, is_backport=is_bp, verification_status=getattr(hit, "verification_status", None)
            )

        result.kept = EPSSRanker.rank(kept, top_n=top_n)
        result.stats["final_count"] = len(result.kept)
        result.stats["dropped_count"] = len(result.dropped)
        result.stats["fp_reduction_pct"] = round((len(result.dropped) / len(raw_hits)) * 100, 1) if raw_hits else 0.0
        return result

    def _version_compatible(self, hit: CVEHit, validated_cpes: List[str]) -> bool:
        rule = hit.source_rule or {}
        range_spec = rule.get("version_range") or rule.get("version_regex") or COMMON_CVE_RANGES.get(hit.cve)
        if not range_spec:
            return True

        detected_versions = self._versions_for_rule(rule, validated_cpes)
        if not detected_versions:
            return True
        return any(VersionRangeMatcher.match_range(version, range_spec) for version in detected_versions)

    @staticmethod
    def _versions_for_rule(rule: Dict[str, Any], cpes: List[str]) -> List[str]:
        product_hint = (rule.get("cpe_product") or "").lower()
        cpe_pattern = rule.get("cpe_pattern") or ""
        if not product_hint and cpe_pattern:
            product_hint = _parse_cpe(cpe_pattern).get("product", "")

        versions = []
        for cpe in cpes:
            parsed = _parse_cpe(cpe)
            if product_hint and parsed["product"] != product_hint:
                continue
            version = parsed.get("version")
            if version and version != "*":
                versions.append(version)
        return versions


def filter_cves(
    raw_hits: List[CVEHit],
    nmap_cpes: List[str],
    httpx_techs: List[str],
    target_os: Optional[str] = None,
    epss_plugin=None,
    kev_plugin=None,
    top_n: Optional[int] = 20,
) -> FilterResult:
    return FilterPipeline(epss_plugin, kev_plugin).run(
        raw_hits=raw_hits,
        nmap_cpes=nmap_cpes,
        httpx_techs=httpx_techs,
        target_os=target_os,
        top_n=top_n,
    )


# Backward-compatible helpers used by Module2 and older scripts.
def detect_target_os(httpx_tech: List[str], cpe_list: List[str], target: str = "") -> str:
    return OSGate.detect_target_os(cpe_list or [], (httpx_tech or []) + ([target] if target else []))


def is_os_compatible(cpe: str, target_os: str) -> bool:
    if not target_os or target_os == "unknown":
        return True
    cpe_lower = (cpe or "").lower()
    if target_os == "linux":
        return not any(kw in cpe_lower for kw in WINDOWS_CPE_KEYWORDS)
    if target_os == "windows":
        return not any(kw in cpe_lower for kw in ["linux_kernel", "ubuntu", "debian", "centos"])
    return True


def filter_tech_stack(
    tech_stack: List[str],
    httpx_tech: List[str],
    target_os: str = "unknown",
    strict_mode: bool = False,
) -> List[str]:
    return SmartCPEFilter(strict_mode=strict_mode).filter(tech_stack, httpx_tech, target_os)


def get_affected_cves_for_tech(
    tech: str,
    cve_ranges: Optional[Dict[str, str]] = None,
) -> List[str]:
    version = SmartCPEFilter._extract_version_from_cpe(tech)
    if not version:
        return []
    affected = []
    for cve_id, range_str in (cve_ranges or COMMON_CVE_RANGES).items():
        if VersionRangeMatcher.match_range(version, range_str):
            affected.append(cve_id)
    return affected
