#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MODULE 2: VULNERABILITY ANALYSIS (V2026 TACTICAL DOCTRINE)
# Sử dụng CPE pattern matching + Version Regex + HttpX Tech Cross-Validation để giảm False Positives.
# Hỗ trợ Blind Vuln Confidence (Interactsh OOB callback).
# [V2026] Origin-Aware Analysis, EPSS/KEV Priority Scoring, CVE Deduplication.

import os
import sys
import re
import json
import logging
import argparse

# Thêm đường dẫn gốc để import utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.registry import PluginRegistry
from core.cpe_filter import CVEHit, VersionRangeMatcher, filter_cves
from config import Config

# Fallback inline DB (dùng khi vuln_db.json không tồn tại)

# [V1.0] Noise Nuclei template IDs — chỉ report thông tin, KHÔNG phải lỗ hổng thực sự
# Loại bỏ khỏi attack plan để giảm nhiễu cho Interactive Menu
_INFO_NOISE_PATTERNS = frozenset({
    # Technology detection (not a vulnerability)
    'tech-detect', 'waf-detect', 'fingerprinthub',
    # Version exposure (informational)
    'php-version', 'apache-version', 'nginx-version', 'iis-version',
    'server-header', 'x-powered-by',
    # Certificate/TLS info
    'ssl-issuer', 'ssl-dns-names', 'self-signed-ssl', 'expired-ssl',
    'tls-version', 'weak-cipher-suites',
    # Generic info
    'robots-txt', 'sitemap-xml', 'security-txt', 'crossdomain-xml',
    'options-method', 'trace-method',
    'email-extractor', 'ip-extractor',
    # CMS detection (not vuln)
    'wordpress-detect', 'joomla-detect', 'drupal-detect',
    'wappalyzer', 'whatweb',
    # Cookies/Headers info
    'cookie-without-httponly', 'cookie-without-secure',
    'missing-x-frame-options', 'missing-csp', 'missing-hsts',
    'missing-x-content-type-options', 'strict-transport-security',
    'permissions-policy', 'content-security-policy',
    # [V1.0] Secrets/PII pattern noise (regex match, NOT a real vulnerability)
    'secrets-patterns', 'secrets-patterns-pii', 'secrets-patterns-rules',
    'pii-detect', 'secret-finder', 'generic-tokens',
})

FALLBACK_TECH_RULES = [
    {"pattern": "apache 2.4.49", "version_regex": "2\\.4\\.49", "cve": "CVE-2021-41773"},
    {"pattern": "apache 2.4.50", "version_regex": "2\\.4\\.50", "cve": "CVE-2021-42013"},
    {"pattern": "apache", "cve": "CVE-2021-41773", "confidence_penalty": 0.5},
    {"pattern": "tomcat", "cve": "DEFAULT-CREDS"},
    {"pattern": "iis 6", "version_regex": "^6\\.", "cve": "CVE-2017-7269"},
    {"pattern": "iis", "cve": "CVE-2017-7269", "confidence_penalty": 0.5},
    {"pattern": "windows", "cve": "CVE-2017-0144", "confidence_penalty": 0.5},
    {"pattern": "http.sys", "cve": "CVE-2021-31166"},
]

FALLBACK_PORT_RULES = [
    {"port": 21, "version_match": "vsftpd 2.3.4", "cve": "CVE-2011-2523"},
    {"port": 21, "version_match": "", "cve": "FTP-ANON"},
    {"port": 3389, "version_match": "", "cve": "CVE-2019-0708"},
    {"port": 3632, "version_match": "", "cve": "CVE-2004-2687"},
    {"port": 6667, "version_match": "unreal", "cve": "CVE-2010-2075"},
]

# [CRIT-01 FIX] Hardcoded affected version ranges for critical high-false-positive CVEs
_CVE_VERSION_RANGES = {
    "CVE-2021-41773": r"2\.4\.49",
    "CVE-2021-42013": r"2\.4\.50",
    "CVE-2017-7269": r"^6\.",
    "CVE-2017-0144": r"^(7|8\.1|10|2008|2012|2016)" # SMB1 Windows versions roughly
}


class CPEMatcher:
    """
    So khớp CPE string từ Nmap/Shodan với cpe_pattern trong VulnDB.
    CPE 2.3 format: cpe:2.3:type:vendor:product:version:*
    """

    @staticmethod
    def parse_cpe(cpe_string: str) -> dict:
        """Parse  CPE 2.3 string thành dict."""
        parts = cpe_string.lower().split(":")
        if len(parts) >= 5:
            return {
                "raw": cpe_string.lower(),
                "type": parts[2] if len(parts) > 2 else "",
                "vendor": parts[3] if len(parts) > 3 else "",
                "product": parts[4] if len(parts) > 4 else "",
                "version": parts[5] if len(parts) > 5 else "*",
            }
        return {"raw": cpe_string.lower(), "type": "", "vendor": "", "product": "", "version": ""}

    @staticmethod
    def match_cpe(cpe_string: str, cpe_pattern: str) -> bool:
        """
        So khớp CPE string với pattern.
        Pattern hỗ trợ wildcard (*) ở cuối version.
        VD: cpe:2.3:a:apache:http_server:2.4.49:* matches cpe:2.3:a:apache:http_server:2.4.49:*
        """
        cpe = CPEMatcher.parse_cpe(cpe_string)
        pat = CPEMatcher.parse_cpe(cpe_pattern)

        # Match type, vendor, product
        if pat["type"] and cpe["type"] != pat["type"]:
            return False
        if pat["vendor"] and cpe["vendor"] != pat["vendor"]:
            return False
        if pat["product"] and cpe["product"] != pat["product"]:
            return False

        # Version matching
        pat_ver = pat["version"]
        cpe_ver = cpe["version"]
        if pat_ver == "*" or not pat_ver:
            return True  # Wildcard matches all
        if pat_ver.endswith(".*"):
            prefix = pat_ver[:-2]
            return cpe_ver.startswith(prefix)
        return cpe_ver == pat_ver


class VersionMatcher:
    """
    Regex-based version matching để xác minh trước khi gán CVE.
    """

    @staticmethod
    def match(version_string: str, version_regex: str) -> bool:
        """Kiểm tra version_string có match regex pattern không."""
        if not version_regex:
            return True  # Không có regex = match tất cả (backward compatible)
        try:
            # [V1.0] Apply negative lookbehind and lookahead to explicitly enforce version boundaries
            # Tự động từ chối partial matches: vd "2.4" sẽ không còn match "12.40"
            bound_pattern = r'(?<![\d.])' + version_regex + r'(?![\d.])'
            return bool(re.search(bound_pattern, version_string, re.IGNORECASE))
        except re.error:
            return False


def load_vuln_db():
    """Load VulnDB từ file JSON bên ngoài, fallback về inline DB."""
    db_path = Config.VULN_DB_PATH
    if os.path.exists(db_path):
        try:
            with open(db_path, 'r') as f:
                db = json.load(f)
                tech_rules = db.get("tech_stack_rules", FALLBACK_TECH_RULES)
                port_rules = db.get("port_rules", FALLBACK_PORT_RULES)
                logging.info(f"[VulnDB] Loaded {len(tech_rules)} tech rules + {len(port_rules)} port rules from {db_path}")
                return tech_rules, port_rules
        except Exception as e:
            logging.warning(f"[VulnDB] Failed to load {db_path}: {e}. Using fallback DB.")
    else:
        logging.info("[VulnDB] External DB not found. Using inline fallback DB.")
    return FALLBACK_TECH_RULES, FALLBACK_PORT_RULES


# [V2026] Infrastructure CVE patterns — used for Origin-Aware confidence boost
_INFRA_CVE_KEYWORDS = frozenset({
    'openssh', 'ssh', 'redis', 'rdp', 'smb', 'ftp', 'postgresql', 'postgres',
    'mysql', 'mssql', 'telnet', 'vnc', 'ldap', 'snmp', 'ntp', 'dns',
    'elasticsearch', 'mongodb', 'memcached', 'docker', 'kubernetes',
    'jenkins', 'grafana', 'prometheus', 'rabbitmq', 'kafka', 'etcd',
    'vsftpd', 'proftpd', 'pure-ftpd', 'samba', 'cups', 'nfs',
})

# [V2026] CVSS Severity → numeric value mapping for priority scoring
_SEVERITY_VALUES = {
    'critical': 1.0,
    'high': 0.8,
    'medium': 0.5,
    'low': 0.2,
    'info': 0.05,
    'unknown': 0.3,
}


class VulnAnalyzer:
    def __init__(self, m1_file, out_file):
        self.m1_file = m1_file
        self.out_file = out_file
        self.tech_rules, self.port_rules = load_vuln_db()

        # Phase 2 plugins are lazy-loaded only when CVEs exist.
        self._epss_plugin = None
        self._kev_plugin = None
        self._nvd_plugin = None

        # Sắp xếp rules: version-specific trước, generic sau
        # Rules có version_regex hoặc cpe_pattern cụ thể (không wildcard) được ưu tiên
        self._sort_rules()

    @staticmethod
    def _is_infra_cve(cve_id: str, source: str = "", description: str = "", port: int = 0) -> bool:
        """
        [V2026] Classify whether a CVE targets infrastructure layer (not web app).
        Used by Origin-Aware Analysis to boost confidence for infra CVEs on origin IPs.
        """
        combined = f"{cve_id} {source} {description}".lower()
        # Check keyword match
        if any(kw in combined for kw in _INFRA_CVE_KEYWORDS):
            return True
        # Non-HTTP ports are typically infrastructure
        if port and port not in (80, 443, 8080, 8443, 8000, 8888, 3000, 5000):
            return True
        return False

    def _sort_rules(self):
        """Sắp xếp tech_rules: version-specific rules xếp trước generic."""
        def rule_specificity(rule):
            score = 0
            if rule.get("version_regex"):
                score += 2  # Có regex = rất cụ thể
            if rule.get("cpe_pattern") and not rule.get("cpe_pattern", "").endswith(":*"):
                score += 1  # CPE cụ thể (không wildcard)
            if rule.get("confidence_penalty"):
                score -= 1  # Generic rule
            return -score  # Negative vì sort ascending
        self.tech_rules.sort(key=rule_specificity)

    def _get_epss_plugin(self):
        if self._epss_plugin is None:
            self._epss_plugin = PluginRegistry.get("EPSS")
        return self._epss_plugin

    def _get_kev_plugin(self):
        if self._kev_plugin is None:
            self._kev_plugin = PluginRegistry.get("CISAKEV")
        return self._kev_plugin

    def _get_nvd_plugin(self):
        if self._nvd_plugin is None:
            self._nvd_plugin = PluginRegistry.get("NVD")
        return self._nvd_plugin

    def _match_tech_rule(self, tech_string: str, cpe_list: list) -> list:
        """
        Match tech_string và CPE list với rules trong DB.
        Trả về list of (cve, confidence, description).
        Ưu tiên version-specific match, bỏ qua generic nếu đã có specific.
        """
        matches = []
        matched_cves = set()

        for rule in self.tech_rules:
            cve = rule["cve"]
            # Nếu đã match cve cụ thể hơn, skip generic rule
            if cve in matched_cves:
                continue

            matched = False
            confidence = 1.0
            ver_regex = rule.get("version_regex", "")

            # Strategy 1: CPE matching (ưu tiên)
            cpe_pattern = rule.get("cpe_pattern", "")
            if cpe_pattern and cpe_list:
                for cpe in cpe_list:
                    if CPEMatcher.match_cpe(cpe, cpe_pattern):
                        matched = True
                        # Nếu có version_regex và CPE chứa version, double-check
                        if ver_regex:
                            parsed = CPEMatcher.parse_cpe(cpe)
                            if VersionRangeMatcher.match_range(parsed["version"], ver_regex):
                                confidence = 1.0  # Exact version match
                            else:
                                confidence = 0.4  # CPE match nhưng version sai
                        break

            # Strategy 2: Substring matching (fallback) — normalize separators
            normalized = re.sub(r'[/_\-]', ' ', tech_string.lower())
            if not matched and rule["pattern"] in normalized:
                matched = True
                # Check version regex nếu có
                if ver_regex:
                    version_text = tech_string
                    version_match = re.search(r"\d+(?:\.\d+)+", tech_string)
                    if version_match:
                        version_text = version_match.group(0)
                    if VersionRangeMatcher.match_range(version_text, ver_regex):
                        confidence = 0.9  # Banner-based version match
                    else:
                        continue  # Có pattern match nhưng version sai → skip rule
                else:
                    confidence = 0.6  # Substring match, không version verify

            if matched:
                # [CRIT-01 FIX] Chặn false positive chặn đứng nếu nằm ngoài affected version range
                version_mismatch = False
                if cve in _CVE_VERSION_RANGES:
                    required_range = _CVE_VERSION_RANGES[cve]
                    
                    # Cố gắng trích xuất version từ CPE
                    detected_version = None
                    if cpe_pattern and cpe_list:
                        for cpe in cpe_list:
                            parsed = CPEMatcher.parse_cpe(cpe)
                            if parsed["version"] and parsed["version"] != "*":
                                detected_version = parsed["version"]
                                break
                    # Hoặc từ tech_string
                    if not detected_version:
                        # Rất khó trích xuất chính xác từ raw banner, nhưng nếu tech_rule có version_regex 
                        # mà không match (đã set confidence < 1 ở trên)
                        version_text = tech_string
                        version_match = re.search(r"\d+(?:\.\d+)+", tech_string)
                        if version_match:
                            version_text = version_match.group(0)
                        if ver_regex and not VersionRangeMatcher.match_range(version_text, ver_regex):
                            detected_version = "mismatch" # dummy name to fail the check

                    if detected_version:
                        if not VersionRangeMatcher.match_range(detected_version, required_range):
                            version_mismatch = True
                            confidence = 0.0

                # Áp dụng confidence_penalty nếu có
                penalty = rule.get("confidence_penalty", 0)
                if penalty:
                    confidence *= (1.0 - penalty)

                matches.append({
                    "cve": cve,
                    "confidence": round(confidence, 2),
                    "description": rule.get("description", ""),
                    "match_type": "cpe" if cpe_pattern and cpe_list else "pattern",
                    "version_mismatch": version_mismatch,
                    "source_rule": rule,
                })
                matched_cves.add(cve)

        # P0-3: normalize raw rule matches through the reusable Smart CPE
        # pipeline.  This keeps the legacy dict output shape while adding
        # version-range filtering, OS gating, and EPSS/KEV ranking metadata.
        hits = [
            CVEHit(
                cve=m["cve"],
                confidence=m["confidence"],
                description=m.get("description", ""),
                match_type=m.get("match_type", "unknown"),
                version_mismatch=m.get("version_mismatch", False),
                source_rule=m.get("source_rule"),
                severity=(m.get("source_rule") or {}).get("severity", "unknown"),
            )
            for m in matches
        ]

        result = filter_cves(
            raw_hits=hits,
            nmap_cpes=cpe_list or [],
            httpx_techs=getattr(self, "_last_httpx_tech", []),
            target_os=getattr(self, "_last_target_os", None),
            epss_plugin=self._epss_plugin,
            kev_plugin=self._kev_plugin,
            top_n=None,
        )

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

    # ===== Phase 3: CPE REFINEMENT =====

    def _deduplicate_cpe(self, tech_stack: list) -> list:
        """
        Phase 3: Lọc CPE trùng lặp/xung đột.
        Nếu có nhiều version cùng vendor:product → chỉ giữ version mới nhất.
        """
        from collections import defaultdict
        import re

        grouped = defaultdict(list)  # (vendor, product) -> [(version, full_cpe)]
        clean_stack = []

        for cpe in tech_stack:
            parts = cpe.lower().split(":")
            if len(parts) >= 6 and parts[5] != "*":
                vendor = parts[3]
                product = parts[4]
                version = parts[5]
                grouped[(vendor, product)].append((version, cpe))
            else:
                clean_stack.append(cpe)  # Wildcard/no-version giữ nguyên

        for key, versions in grouped.items():
            if len(versions) <= 1:
                clean_stack.append(versions[0][1])
            else:
                # Sắp xếp version (best-effort numeric sort)
                def version_key(v):
                    return [int(x) if x.isdigit() else 0 for x in re.split(r'[.\-_]', v[0])]
                try:
                    versions.sort(key=version_key, reverse=True)
                except Exception:
                    pass
                # Giữ version mới nhất
                clean_stack.append(versions[0][1])
                if len(versions) > 1:
                    print(f"    [CPE-DEDUP] {key[0]}:{key[1]} — Giữ v{versions[0][0]}, loại v{', v'.join(v[0] for v in versions[1:])}")

        return clean_stack

    def _smart_cpe_filter(self, tech_stack: list, httpx_tech: list) -> list:
        """
        [P0-3 FIX] Use SmartCPEFilter from core.cpe_filter for cross-validation.

        Refactored from inline logic (~120 lines) to use the reusable
        SmartCPEFilter class in core/cpe_filter.py.

        Logic:
        - Cross-validate Nmap CPE vs HttpX tech-detect
        - Drop CPEs that conflict with HttpX findings
        - Drop OS-incompatible CPEs (e.g., IIS on Linux target)

        Args:
            tech_stack: List of CPE strings from Nmap
            httpx_tech: List of tech names from HttpX/Wappalyzer

        Returns:
            Filtered tech_stack
        """
        # [P0-3 FIX] Delegate to core.cpe_filter.SmartCPEFilter
        try:
            from core.cpe_filter import SmartCPEFilter, detect_target_os

            # Detect OS from httpx tech + tech_stack for OS-based filtering
            target_os = detect_target_os(httpx_tech or [], tech_stack or [])

            filter_obj = SmartCPEFilter(strict_mode=False)
            filtered = filter_obj.filter(
                tech_stack=tech_stack or [],
                httpx_tech=httpx_tech or [],
                target_os=target_os,
            )

            removed_count = (len(tech_stack or []) - len(filtered))
            if removed_count:
                print(f"    [SMART-CPE] Loại bỏ {removed_count} CPE xung đột (Nmap vs HttpX tech-detect)")
            return filtered

        except ImportError:
            # Fallback: if core.cpe_filter not available, return original
            # (backward compatible — better to have false positives than crash)
            print("    [SMART-CPE] WARNING: core.cpe_filter not available, skipping filter")
            return tech_stack

    def _filter_by_os(self, tags_ports: dict, os_detection: list) -> dict:
        """
        Phase 3: Lọc CVE dựa trên OS detection từ Nmap.
        Nếu OS là Windows → loại LinuxKernel CVEs và ngược lại.
        """
        if not os_detection:
            return tags_ports

        detected_os = ""
        for os_item in os_detection:
            os_name = ""
            if isinstance(os_item, dict):
                os_name = os_item.get("name", "").lower()
            elif isinstance(os_item, str):
                os_name = os_item.lower()
            if "windows" in os_name:
                detected_os = "windows"
                break
            elif "linux" in os_name or "ubuntu" in os_name or "centos" in os_name or "debian" in os_name:
                detected_os = "linux"
                break

        if not detected_os:
            return tags_ports

        print(f"    [OS-FILTER] Detected OS: {detected_os.upper()}")

        # Danh sách CVE đặc thù theo OS
        linux_only_patterns = ["linux_kernel", "glibc", "sudo", "polkit", "pkexec"]
        windows_only_patterns = ["windows", "smb", "rdp", "exchange", "iis", "active_directory"]

        filtered = {}
        removed_count = 0
        for cve, info in tags_ports.items():
            cve_lower = cve.lower()
            source = info.get("source", "").lower()
            desc = info.get("description", "").lower()
            combined = f"{cve_lower} {source} {desc}"

            should_remove = False
            if detected_os == "windows":
                for pat in linux_only_patterns:
                    if pat in combined:
                        should_remove = True
                        break
            elif detected_os == "linux":
                for pat in windows_only_patterns:
                    if pat in combined:
                        # Chỉ loại nếu CVE từ OSINT (confidence thấp)
                        if info.get("confidence", 1.0) < 0.6:
                            should_remove = True
                            break

            if should_remove:
                removed_count += 1
            else:
                filtered[cve] = info

        if removed_count:
            print(f"    [OS-FILTER] Loại bỏ {removed_count} CVE không khớp OS ({detected_os}).")

        return filtered

    # ===== Phase 2: EPSS & KEV ENRICHMENT (V2026 TACTICAL SCORING) =====

    def _enrich_with_epss_kev(self, attack_plan: list) -> list:
        """
        Phase 2 (V2026): Bổ sung EPSS Score + CISA KEV status + NVD CVSS cho mỗi CVE.
        
        [V2026] Công thức ưu tiên mới:
          Score = (Severity_Value * 0.4) + (EPSS_Score * 0.4) + (KEV_Bonus * 0.2)
          KEV entries: force priority_score = 1.0 (always top-1).
        """
        cve_ids = [item["cve"] for item in attack_plan if item["cve"].startswith("CVE-")]

        # Batch EPSS lookup
        epss_data = {}
        epss_plugin = self._get_epss_plugin() if cve_ids else None
        if epss_plugin and cve_ids:
            print(f"    [EPSS] Tra cứu EPSS Score cho {len(cve_ids)} CVE...")
            epss_data = epss_plugin.batch_lookup(cve_ids)

        # Batch KEV check
        kev_data = {}
        kev_plugin = self._get_kev_plugin() if cve_ids else None
        if kev_plugin and cve_ids:
            print(f"    [KEV] Kiểm tra CISA KEV catalog...")
            kev_data = kev_plugin.batch_check(cve_ids)

        # [V1.0] Batch NVD CVSS lookup
        nvd_data = {}
        nvd_plugin = self._get_nvd_plugin() if cve_ids else None
        if nvd_plugin and cve_ids:
            print(f"    [NVD] Tra cứu CVSS v3.1 scores cho {len(cve_ids)} CVE...")
            nvd_data = nvd_plugin.batch_lookup(cve_ids)

        kev_count = 0
        high_epss_count = 0
        critical_cvss_count = 0

        for item in attack_plan:
            cve = item["cve"]

            # EPSS enrichment
            epss_info = epss_data.get(cve, {})
            item["epss_score"] = epss_info.get("epss", 0.0)
            item["epss_percentile"] = epss_info.get("percentile", 0.0)

            # KEV enrichment
            kev_info = kev_data.get(cve, {})
            item["is_kev"] = kev_info.get("is_kev", False)
            item["kev_due_date"] = kev_info.get("kev_due_date", "")

            # [V1.0] NVD CVSS enrichment
            nvd_info = nvd_data.get(cve, {})
            item["cvss_score"] = nvd_info.get("cvss_score", 0.0)
            item["cvss_vector"] = nvd_info.get("cvss_vector", "")
            item["cvss_severity"] = nvd_info.get("cvss_severity", "UNKNOWN")

            if item["is_kev"]:
                kev_count += 1
            if item["epss_score"] > 0.1:
                high_epss_count += 1
            if item["cvss_score"] >= 9.0:
                critical_cvss_count += 1

            # ═══════════════════════════════════════════════════════
            # [V2026] TACTICAL PRIORITY SCORING — 4-Factor Formula
            # Score = (Severity_Value * 0.35) + (EPSS * 0.35) + (KEV_Bonus * 0.15) + (Origin_Bonus * 0.15)
            # KEV entries: force priority_score = 1.0 (always top-1).
            # Origin_Bonus: +0.2 khi CVE nằm trên Origin IP (bypass WAF/CDN).
            # ═══════════════════════════════════════════════════════
            severity_str = item.get("cvss_severity", item.get("severity", "UNKNOWN")).lower()
            severity_value = _SEVERITY_VALUES.get(severity_str, 0.3)
            epss = item["epss_score"]
            kev_bonus = 1.0 if item["is_kev"] else 0.0
            origin_bonus = 0.2 if item.get("origin_boosted", False) else 0.0

            if item["is_kev"]:
                # KEV = CISA actively exploited → force top priority
                item["priority_score"] = 1.0
            else:
                raw_score = (
                    (severity_value * 0.35) +
                    (epss * 0.35) +
                    (kev_bonus * 0.15) +
                    origin_bonus  # Flat +0.2 for origin-exposed infra CVEs
                )
                item["priority_score"] = round(min(raw_score, 1.0), 4)

        if kev_count:
            print(f"    \033[91m[KEV] 🔴 {kev_count} CVE đang bị khai thác trong thực tế (CISA KEV) — FORCED TOP PRIORITY!\033[0m")
        if high_epss_count:
            print(f"    \033[93m[EPSS] {high_epss_count} CVE có xác suất bị exploit > 10%\033[0m")
        if critical_cvss_count:
            print(f"    \033[91m[CVSS] {critical_cvss_count} CVE có CVSS >= 9.0 (CRITICAL)\033[0m")

        return attack_plan

    def _filter_junk_cves(self, attack_plan: list) -> list:
        """
        [V1.0] Phase 2: Loại bỏ CVE rác và Nuclei noise.
        Các cấp độ lọc:
          1. Nuclei info/low không có EPSS, không KEV, không verified → LOẠI
          2. Nuclei template thuộc _INFO_NOISE_PATTERNS → LOẠI
          3. EPSS < 1% + không KEV + confidence < 0.3 + không MSF + không verified → LOẠI
        """
        original_count = len(attack_plan)
        filtered = []
        noise_removed = 0
        info_low_removed = 0
        junk_removed = 0

        for item in attack_plan:
            epss = item.get("epss_score", 0.0)
            is_kev = item.get("is_kev", False)
            conf = item.get("confidence", 0)
            msf_ready = item.get("msf_ready", False)
            verified = item.get("verified", False)
            severity = item.get("severity", "").lower()
            cve = item.get("cve", "")
            source = item.get("match_source", "").lower()

            # [V1.0] Rule 0: Loại Nuclei template trùng với noise patterns
            template_id = cve.replace("NUCLEI-", "") if cve.startswith("NUCLEI-") else ""
            if template_id:
                template_lower = template_id.lower()
                is_noise = any(noise in template_lower for noise in _INFO_NOISE_PATTERNS)
                if is_noise and not is_kev and epss <= 0.01:
                    noise_removed += 1
                    continue

            # [CRIT-03 FIX] Rule 0.5: Loại bỏ các CVE bị flag version_mismatch
            if item.get("version_mismatch"):
                junk_removed += 1
                continue

            # [V1.0] Rule 1: Nuclei info/low — chỉ giữ nếu có EPSS cao, KEV, hoặc OOB verified
            if severity in ('info', 'low') and 'nuclei' in source:
                has_signal = (
                    epss > 0.05 or         # EPSS > 5% là đáng chú ý
                    is_kev or              # CISA đang bị tấn công
                    msf_ready or           # Có module MSF sẵn
                    (verified and conf >= 0.9)  # OOB verified với confidence cao
                )
                if not has_signal:
                    info_low_removed += 1
                    continue

            # [CRIT-04 FIX] Rule 2: Strict Dynamic Verification filter
            # Require vulnerabilities to be dynamically confirmed (verified == True),
            # exist in CISA KEV, or have a high EPSS score.
            if is_kev or epss > 0.05 or verified:
                filtered.append(item)
            else:
                junk_removed += 1

        removed = original_count - len(filtered)
        if removed:
            details = []
            if noise_removed:
                details.append(f"{noise_removed} noise templates")
            if info_low_removed:
                details.append(f"{info_low_removed} info/low severity")
            if junk_removed:
                details.append(f"{junk_removed} low-signal CVEs")
            print(f"    [JUNK-FILTER] Loại bỏ {removed}/{original_count} mục tiêu rác ({', '.join(details)})")

        return filtered

    # ===== V1.0-FIX: HIGH-FIDELITY INTELLIGENCE FILTER =====

    @staticmethod
    def _apply_high_fidelity_filter(attack_plan: list) -> tuple:
        """
        [V1.0] Final gate: Only include CVEs meeting strict criteria.
        Also boosts confidence for EPSS > 0.4 or CISA KEV.
        """
        original_count = len(attack_plan)
        kept = []
        graylist = []
        dropped_low_conf = 0
        dropped_unverified = 0

        for item in attack_plan:
            confidence = item.get("confidence", 0)
            verified = item.get("verified", False)
            is_kev = item.get("is_kev", False)
            epss_score = item.get("epss_score", 0.0)

            # Dynamic Boost
            if epss_score > 0.4 or is_kev:
                confidence += 0.2
                if is_kev:
                    confidence = 1.0
                confidence = min(confidence, 1.0)
                item["confidence"] = round(confidence, 2)

            # Gate: HIGH-FIDELITY criteria
            if confidence >= 0.85 or verified or is_kev:
                kept.append(item)
            else:
                graylist.append(item)
                if confidence < 0.85:
                    dropped_low_conf += 1
                else:
                    dropped_unverified += 1

        dropped_total = original_count - len(kept)
        if dropped_total:
            print(
                f"    \033[93m[HIGH-FIDELITY] Segregated {dropped_total}/{original_count} "
                f"low-confidence candidates to graylist. Keeping {len(kept)} actionable targets.\033[0m"
            )
        else:
            print(f"    [HIGH-FIDELITY] All {original_count} candidates passed quality gate.")

        return kept, graylist
    # ===== V2026: CVE DEDUPLICATION =====

    @staticmethod
    def _deduplicate_cves(tags_ports: dict) -> dict:
        """
        [V2026] Loại bỏ CVE trùng lặp giữa Nuclei, Nmap NSE, và OSINT.
        Khi cùng CVE ID xuất hiện từ nhiều nguồn, giữ entry có confidence cao nhất
        và merge trường source.
        """
        # Group by normalized CVE ID
        cve_groups = {}  # cve_id -> list of (key, info)
        non_cve_entries = {}  # Non-CVE entries (NUCLEI-*, CLOUD-*, etc.) — giữ nguyên
        
        for key, info in tags_ports.items():
            # Normalize: CVE-XXXX-YYYY is the dedup key
            if key.startswith("CVE-"):
                if key not in cve_groups:
                    cve_groups[key] = []
                cve_groups[key].append((key, info))
            else:
                non_cve_entries[key] = info
        
        deduped = dict(non_cve_entries)  # Start with non-CVE entries
        dedup_count = 0
        
        for cve_id, entries in cve_groups.items():
            if len(entries) <= 1:
                deduped[cve_id] = entries[0][1]
                continue
            
            # Sort by confidence descending, keep the best
            entries.sort(key=lambda x: x[1].get("confidence", 0), reverse=True)
            best_key, best_info = entries[0]
            
            # Merge sources from all duplicates
            all_sources = [e[1].get("source", "") for e in entries if e[1].get("source")]
            unique_sources = list(dict.fromkeys(all_sources))  # Preserve order, remove dupes
            best_info["source"] = " + ".join(unique_sources)
            
            # Keep highest verified status
            if any(e[1].get("verified", False) for e in entries):
                best_info["verified"] = True
            
            deduped[cve_id] = best_info
            dedup_count += len(entries) - 1
        
        if dedup_count:
            print(f"    \033[93m[CVE-DEDUP] Loại bỏ {dedup_count} CVE trùng lặp (Nuclei ∩ Nmap NSE ∩ OSINT)\033[0m")
        
        return deduped

    # ===== MAIN ANALYZE =====

    def analyze(self):
        print(f"[*] Đang nạp Target Profile từ: {self.m1_file}")
        try:
            with open(self.m1_file, 'r') as f:
                assets = json.load(f)
        except Exception as e:
            print(f"[!] Lỗi khi đọc file Recon JSON: {e}")
            sys.exit(1)

        attack_plan = []
        print("\n[+] Bắt đầu phân tích CPE-Aware Smart Filter (V2026 — Tactical Doctrine)...")
        # [V1.0-FIX] Passive Intelligence: Cảnh báo ngay các dữ liệu rò rỉ
        for asset in assets:
            target = asset.get('target', '')
            # Scan Secrets
            secrets = asset.get('secrets', asset.get('js_secrets', []))
            if secrets:
                print(f"\n    {Y}[!] Cảnh báo: Tìm thấy {len(secrets)} Secrets trong JS!{X}")
                for s in secrets[:5]:
                    print(f"        -> [{s.get('type', 'Secret')}] {s.get('value', '...')[:30]}...")
            
            # Scan Emails
            emails = asset.get('emails', [])
            if emails:
                print(f"    {Y}[!] Cảnh báo: Tìm thấy {len(emails)} Email nhân sự!{X}")
                for e in emails[:5]:
                    print(f"        -> {e}")

        # Phase 1: Historical OSINT data
            ip = asset.get('ip', '')
            tech_stack = asset.get('tech_stack', [])  # CPEs from Shodan/Nmap
            ports = asset.get('open_ports', [])
            osint_cves = asset.get('cve_candidates', [])
            
            # [V2026] Origin-Aware Analysis — detect origin IP from M1
            origin_ip = asset.get('origin_ip', '')
            has_origin = bool(origin_ip and origin_ip != ip)
            scan_mode = asset.get('scan_mode', 'sniper')

            # 2026 Doctrine: Nuclei & Cloud data
            nuclei_findings = asset.get('nuclei_findings', [])
            cloud_findings = asset.get('cloud_findings', {})
            os_detection = asset.get('os_detection', [])

            # Phase 1: Historical OSINT data (đã bị hạ confidence bởi M1)
            historical_osint = asset.get('historical_osint', [])
            if historical_osint:
                print(f"    [!] {len(historical_osint)} CVE từ OSINT bị đánh dấu 'Historical' (Active Scan thất bại)")

            vt_org = asset.get('vt_organization', '')
            vt_rep = asset.get('vt_reputation', 0)
            if vt_org or vt_rep < 0:
                print(f"    [!] Context: Thuộc về {vt_org} - Reputation Score: {vt_rep}")

            # Phase 3: CPE Deduplication
            tech_stack = self._deduplicate_cpe(tech_stack)

            #  Phase 3.5: Smart CPE Filter — Cross-validate Nmap CPE với HttpX Tech-Detect
            httpx_tech = []
            for p in ports:
                httpx_tech.extend(p.get('tech', []))
            httpx_tech = list(set(t.lower() for t in httpx_tech if t))
            self._last_httpx_tech = httpx_tech
            self._last_target_os = None
            if httpx_tech and Config.SMART_CPE_FILTER:
                tech_stack = self._smart_cpe_filter(tech_stack, httpx_tech)
                print(f"    [SMART-CPE] HttpX tech-detect cross-validated {len(tech_stack)} CPEs (httpx tags: {', '.join(httpx_tech[:5])})")
            elif httpx_tech and not Config.SMART_CPE_FILTER:
                print(f"    [SMART-CPE] SKIP — Smart CPE Filter đã bị tắt (--no-smart-cpe)")

            tags_ports = {}  # cve -> {port, confidence, description}

            # Lọc các cổng chết (dead)
            alive_ports = {p.get('port') for p in ports if p.get('status', 'unknown') != 'dead'}

            # Rule 1: OSINT CVE Candidates (từ Shodan + Nmap NSE) — Highest confidence
            for cand in osint_cves:
                cve = cand.get('cve')
                cve_port = cand.get('port', 80)
                if cve_port not in alive_ports and cve_port != 0:
                    continue  # Bỏ qua CVE cho port đã chết
                conf = cand.get('confidence', 0.8)
                verified = cand.get('verified', False)
                tags_ports[cve] = {
                    "port": cve_port,
                    "confidence": conf,
                    "source": cand.get("source", "OSINT/NSE"),
                    "severity": cand.get("severity", ""),
                    "matched_at": cand.get("matched_at", ""),
                    "verified": verified,
                }

            # Rule 2: Nuclei Findings — Direct Ingestion (2026 Doctrine)
            # Nuclei results đã chứa sẵn CVE ID + severity → KHÔNG cần regex CPE
            #  Blind_Vuln_Confidence: nếu finding từ OAST/Interactsh → confidence = 1.0
            if nuclei_findings:
                print(f"    [+] Ingesting {len(nuclei_findings)} Nuclei findings (direct CVE mapping)...")
                blind_count = 0
                for finding in nuclei_findings:
                    cve_id = finding.get("cve_id", "")
                    template_id = finding.get("template_id", "")
                    identifier = cve_id if cve_id else f"NUCLEI-{template_id}"

                    if identifier:
                        severity = finding.get("severity", "unknown")
                        conf = self._nuclei_severity_to_confidence(severity)
                        port = finding.get("port", 80)
                        
                        # [V1.0] Diệt Ma (Ghost Exorcism): Xác thực tương tác OOB thực sự
                        matched_at = finding.get("matched_at", "").lower()
                        template_lower = template_id.lower()
                        has_interaction = finding.get("interaction", False)
                        
                        # Logic 1: Nuclei xác nhận có tương tác thực sự -> 100% Verified
                        if has_interaction:
                            conf = 1.0
                            blind_count += 1
                        
                        # Logic 2: Phát hiện URL OOB trong kết quả nhưng chưa chắc chắn
                        # Nếu URL OOB nằm trong query string (vd: ?q=http://oast) -> Có thể chỉ là payload in ra màn hình
                        elif "interact.sh" in matched_at or "oast" in matched_at or "oast" in template_lower:
                            # [AUDIT-FIX V-01] Enhanced Ghost Exorcism — mở rộng pattern detection
                            _is_ghost = False
                            
                            # Check 1: OOB URL trong query string parameters
                            if "?" in matched_at and ("oast" in matched_at.split("?")[-1] or "interact" in matched_at.split("?")[-1]):
                                _is_ghost = True
                            
                            # Check 2: OOB URL trong fragment (#) — vd: page.html#http://oast...
                            elif "#" in matched_at and ("oast" in matched_at.split("#")[-1] or "interact" in matched_at.split("#")[-1]):
                                _is_ghost = True
                            
                            # Check 3: OOB URL double-encoded (vd: %68%74%74%70 = http) 
                            elif "%25" in matched_at and ("oast" in matched_at or "interact" in matched_at):
                                _is_ghost = True
                            
                            # Check 4: OOB URL nằm trong path segment giống parameter echo
                            # vd: /search/http%3A%2F%2Foast.fun/results
                            elif matched_at.count("/") > 4 and ("oast" in matched_at.split("?")[0] or "interact" in matched_at.split("?")[0]):
                                # Kiểm tra OOB URL có nằm giữa 2 dấu / trong path không
                                from urllib.parse import unquote
                                decoded_path = unquote(matched_at.split("?")[0])
                                path_segments = decoded_path.split("/")
                                for seg in path_segments:
                                    if "oast" in seg or "interact" in seg:
                                        _is_ghost = True
                                        break
                            
                            if _is_ghost:
                                # Đây khả năng cao là "Ma" (Ghost) — chỉ là payload echo
                                conf = min(conf, 0.3) 
                                logging.debug(f"    [V1.0-GHOST-CHECK] Giảm confidence cho {template_id} vì OOB URL nằm trong query/fragment/path (ghost echo).")
                            else:
                                # [V1.0-POLISH] Không đếm INFO templates là Blind OOB nếu chỉ dựa trên string match
                                if severity.lower() != "info":
                                    conf = 0.8
                                    blind_count += 1
                                    logging.debug(f"    [V1.0-GHOST-CHECK] Ghi nhận tiềm năng Blind Vuln cho {template_id} (String match).")
                                else:
                                    conf = min(conf, 0.4)
                                    logging.debug(f"    [V1.0-GHOST-CHECK] Bỏ qua OOB string-match cho INFO template {template_id}.")

                        # Chỉ override nếu confidence cao hơn
                        if identifier not in tags_ports or tags_ports[identifier]["confidence"] < conf:
                            # [F-08 FIX] Disambiguate verified semantics:
                            #   - has_interaction=True → OOB confirmed (verified=True, method=oob_callback)
                            #   - OOB string match → partially verified (method=oob_string_match)
                            #   - Template match only → NOT verified (method=template_match)
                            if has_interaction:
                                _verified = True
                                _verify_method = "oob_callback"
                            elif "interact.sh" in matched_at or "oast" in matched_at:
                                _verified = conf >= 0.8  # Only verified if not ghosted
                                _verify_method = "oob_string_match"
                            else:
                                _verified = False
                                _verify_method = "template_match"
                            tags_ports[identifier] = {
                                "port": port,
                                "confidence": conf,
                                "source": f"Nuclei ({severity})",
                                "severity": severity,
                                "matched_at": finding.get("matched_at", ""),
                                "description": finding.get("description", finding.get("template_name", "")),
                                "verified": _verified,
                                "verification_method": _verify_method,
                                "curl_command": finding.get("curl_command", ""),
                                "vuln_type": finding.get("type", "Custom"),
                            }

                if blind_count:
                    print(f"    \033[95m[BLIND-VULN] {blind_count} lỗ hổng xác nhận qua OOB callback (Interactsh) — Confidence 100%!\033[0m")

            # Rule 3: Cloud/DevOps Findings (2026 Doctrine)
            if cloud_findings:
                # Public buckets
                for bucket in cloud_findings.get("bucket_findings", []):
                    if bucket.get("status") == "PUBLIC_READ":
                        bid = f"CLOUD-{bucket['provider']}-PUBLIC-{bucket['bucket']}"
                        tags_ports[bid] = {
                            "port": 443,
                            "confidence": 0.95,
                            "source": "CloudDevOps",
                            "severity": "critical",
                            "description": f"Public {bucket['provider']} bucket: {bucket['url']}",
                            "verified": True,
                        }
                # Subdomain takeovers
                for takeover in cloud_findings.get("takeover_candidates", []):
                    tid = f"TAKEOVER-{takeover.get('subdomain', '')}"
                    tags_ports[tid] = {
                        "port": 80,
                        "confidence": 0.9 if takeover.get("status") == "VULNERABLE" else 0.7,
                        "source": "CloudDevOps",
                        "severity": "critical",
                        "description": f"Subdomain takeover via {takeover.get('service', 'unknown')}",
                        "verified": True,
                    }
                # Exposed DevOps ports
                for devops in cloud_findings.get("devops_exposed", []):
                    did = f"DEVOPS-{devops['service'].replace(' ', '-')}"
                    tags_ports[did] = {
                        "port": devops["port"],
                        "confidence": 0.9,
                        "source": "CloudDevOps",
                        "severity": devops.get("severity", "high"),
                        "description": f"Exposed {devops['service']} on port {devops['port']}",
                        "verified": True,
                    }

            # Rule 4: CPE-Aware Tech Stack matching (VulnDB V1.0)
            for tech in tech_stack:
                matches = self._match_tech_rule(tech, tech_stack)
                for m in matches:
                    cve = m["cve"]
                    if cve not in tags_ports or tags_ports[cve]["confidence"] < m["confidence"]:
                        tags_ports[cve] = {
                            "port": 80,
                            "confidence": m["confidence"],
                            "source": f"VulnDB ({m['match_type']})",
                            "description": m["description"]
                        }

            # Rule 5: Active Scan Port-based matching
            for p in ports:
                service = p.get('service', '').lower()
                port = int(p.get('port', 0))
                ver = p.get('version', '').lower()

                for rule in self.port_rules:
                    if port == rule["port"]:
                        vm = rule.get("version_match", "")
                        if vm and vm in ver:
                            cve = rule["cve"]
                            tags_ports[cve] = {"port": port, "confidence": 0.9, "source": "Port+Version", "verified": True}
                        elif not vm:
                            cve = rule["cve"]
                            if cve not in tags_ports:
                                tags_ports[cve] = {"port": port, "confidence": 0.4, "source": "Port-only"}

                # Legacy service-based matching
                if service in ['smb', 'microsoft-ds', 'netbios-ssn'] or port in [139, 445]:
                    if 'samba 3.0.20' in ver:
                        tags_ports["CVE-2007-2447"] = {"port": port, "confidence": 0.95, "source": "Service+Version", "verified": True}
                    elif "CVE-2017-0144" not in tags_ports:
                        tags_ports["CVE-2017-0144"] = {"port": port, "confidence": 0.5, "source": "Service-generic"}

                if service in ['http', 'ssl/http'] and port in [8180, 8080, 8443, 8000]:
                    tags_ports["DEFAULT-CREDS"] = {"port": port, "confidence": 0.6, "source": "Service+Port"}

            # Phase 3: OS-based filtering
            tags_ports = self._filter_by_os(tags_ports, os_detection)

            # [V2026] Phase 3.5: CVE Deduplication — merge Nuclei + NSE + OSINT
            tags_ports = self._deduplicate_cves(tags_ports)

            # [V2026] Phase 4: Origin-Aware Tagging (NO confidence change)
            # Origin presence is factored into priority_score via origin_bonus,
            # NOT by inflating confidence (per user directive).
            if has_origin:
                origin_tag_count = 0
                for cve, info in tags_ports.items():
                    if self._is_infra_cve(cve, info.get('source', ''), info.get('description', ''), info.get('port', 0)):
                        info['origin_boosted'] = True
                        origin_tag_count += 1
                    else:
                        info['origin_boosted'] = False
                if origin_tag_count:
                    print(f"    \033[96m[ORIGIN-TAG] {origin_tag_count} infra CVEs tagged for priority boost (origin IP: {origin_ip})\033[0m")

            if tags_ports:
                for cve, info in tags_ports.items():
                    cache_dir = os.path.dirname(self.m1_file)

                    # ===== V2 SMART MULTI-KEY LOOKUP =====
                    # Tìm module MSF theo nhiều chiều: CVE → Port+Service → Nuclei → Product
                    plugin = PluginRegistry.get("MSFSearch")
                    msf_modules = []
                    
                    if plugin:
                        # [V1.0] BLOCK: Nêcléi INFO severity — KHÔNG BAO GIỊ̀ được mapping sang MSF module
                        # INFO findings (như secrets-patterns-pii) không phải lỗ hổng, chỉ là thông tin.
                        nuclei_severity = info.get("severity", "").lower()
                        is_info_severity = nuclei_severity in ('info', '')
                        
                        if is_info_severity and cve.startswith("NUCLEI-"):
                            # Skip MSF mapping entirely for INFO-level Nuclei templates
                            print(f"    [V1.0-GUARD] Skipping MSF mapping for INFO template: {cve}")
                        else:
                            # Tier 1: Try CVE first (backward compatible)
                            if cve.startswith("CVE-"):
                                msf_modules = plugin.run(cve, cache_dir)
                            
                            # Tier 2: If no CVE match, try smart multi-key search
                            if not msf_modules and hasattr(plugin, 'smart_search'):
                                search_port = int(info.get("port", 0)) or None
                                
                                # Extract service name from source/description
                                search_service = None
                                desc = info.get("description", "").lower()
                                source = info.get("source", "").lower()
                                matched_at = info.get("matched_at", "").lower()
                                
                                # Map Nuclei template IDs to service
                                nuclei_template = None
                                if cve.startswith("NUCLEI-"):
                                    nuclei_template = cve.replace("NUCLEI-", "")
                                elif cve.startswith("NSE-"):
                                    # Nmap NSE script → extract service hint
                                    nse_name = cve.replace("NSE-", "").lower()
                                    for svc_hint in ["ftp", "ssh", "smtp", "http", "smb", "rmi", "sql", "vnc", "rdp", "ldap", "dns"]:
                                        if svc_hint in nse_name:
                                            search_service = svc_hint
                                            break
                                
                                # Extract product name for fuzzy match
                                search_product = None
                                for product_name in ["tomcat", "apache", "nginx", "postgres", "mysql", "redis",
                                                     "jenkins", "wordpress", "drupal", "joomla", "elasticsearch",
                                                     "grafana", "gitlab", "confluence", "docker", "vmware",
                                                     "exchange", "iis", "weblogic", "jboss", "samba"]:
                                    if product_name in desc or product_name in source or product_name in cve.lower():
                                        search_product = product_name
                                        break
                                
                                smart_results = plugin.smart_search(
                                    cve=cve if cve.startswith("CVE-") else None,
                                    port=search_port,
                                    service=search_service,
                                    product=search_product,
                                    nuclei_template=nuclei_template,
                                    limit=6
                                )
                                
                                if smart_results:
                                    # Convert smart_search results to legacy format
                                    msf_modules = []
                                    for r in smart_results:
                                        rank = r.get("rank", "normal")
                                        score = {"excellent": 100, "great": 90, "good": 80, "normal": 70, "average": 60, "low": 50, "manual": 10}.get(rank, 70)
                                        if r.get("type") == "exploit":
                                            score += 500
                                        msf_modules.append({
                                            "path": r["path"],
                                            "type": r.get("type", "exploit"),
                                            "rank": rank,
                                            "score": score,
                                        })
                                if msf_modules:
                                    print(f"    [SMART-MSF] {cve}: Tìm thấy {len(msf_modules)} module(s) qua Smart Lookup (Port/Service/Product)")

                    # [V1.0] OS GUARDRAIL: Loại bỏ MSF module trái ngược OS target
                    # Nếu target là Linux/CentOS → cấm module có "windows", "vmware", "citrix" trong path
                    # Nếu target là Windows → cấm module có "linux", "unix" trong path
                    if msf_modules and os_detection:
                        detected_os_lower = " ".join(d.lower() for d in os_detection if isinstance(d, str))
                        target_is_linux = any(k in detected_os_lower for k in ["linux", "centos", "ubuntu", "debian", "redhat", "fedora", "unix"])
                        target_is_windows = "windows" in detected_os_lower

                        if target_is_linux or target_is_windows:
                            os_blocked_keywords_linux = ["windows", "vmware", "vcenter", "citrix", "exchange", "iis",
                                                         "netscaler", "active_directory", "powershell"]
                            os_blocked_keywords_windows = ["linux", "unix", "polkit", "pkexec", "glibc"]

                            blocked_kw = os_blocked_keywords_linux if target_is_linux else os_blocked_keywords_windows
                            pre_count = len(msf_modules)
                            msf_modules = [
                                m for m in msf_modules
                                if not any(bk in m.get("path", "").lower() for bk in blocked_kw)
                            ]
                            removed_os = pre_count - len(msf_modules)
                            if removed_os:
                                os_label = "Linux" if target_is_linux else "Windows"
                                print(f"    [V1.0-OS-GUARD] Removed {removed_os} cross-OS module(s) "
                                      f"incompatible with detected {os_label} target.")

                    attack_plan.append({
                        "target": target,
                        "ip": ip,
                        "cve": cve,
                        "rport": info["port"],
                        "confidence": info["confidence"],
                        "match_source": info.get("source", "unknown"),
                        "severity": info.get("severity", ""),
                        "matched_at": info.get("matched_at", ""),
                        "tech_origin": "VulnAnalyzer-V1.0-SmartIndex",
                        "msf_ready": len(msf_modules) > 0,
                        "suggested_modules": [m['path'] for m in msf_modules],
                        "verified": info.get("verified", False),
                        "verification_method": info.get("verification_method", "heuristic"),
                        "curl_command": info.get("curl_command", ""),
                        "vuln_type": info.get("vuln_type", "CVE"),
                    })

                # Hiển thị kết quả kèm confidence
                display_tags = []
                for cve, info in tags_ports.items():
                    conf_pct = int(info["confidence"] * 100)
                    sev = f" [{info.get('severity', '').upper()}]" if info.get("severity") else ""
                    verified_badge = " ✓" if info.get("verified") else ""
                    display_tags.append(f"{cve}{sev} (Port {info['port']}, {conf_pct}% conf{verified_badge})")
                print(f"    -> [MATCH] {target}: {', '.join(display_tags)}")

        if not attack_plan:
            print(f"\n[-] Không tìm thấy bề mặt tấn công rõ ràng (0 targets).")

        # Phase 2: EPSS & KEV Enrichment
        if attack_plan:
            print(f"\n[+] Phase 2: EPSS & CISA KEV Enrichment...")
            attack_plan = self._enrich_with_epss_kev(attack_plan)

            # Phase 2: Lọc CVE rác
            attack_plan = self._filter_junk_cves(attack_plan)

            # V1.0-FIX: HIGH-FIDELITY INTELLIGENCE FILTER
            # Only keep CVEs that meet strict threshold (confidence >= 0.85 OR verified OR KEV)
            pre_filter_count = len(attack_plan)
            attack_plan, graylist = self._apply_high_fidelity_filter(attack_plan)
            dropped_count = pre_filter_count - len(attack_plan)
            
            if graylist:
                graylist_file = os.path.join(os.path.dirname(self.out_file), "m2_graylist.json")
                with open(graylist_file, 'w') as gf:
                    json.dump(graylist, gf, indent=4)
                print(f"    [GRAYLIST] Đã lưu {len(graylist)} mục vào {graylist_file}")

        # Sắp xếp attack_plan theo priority_score giảm dần (thay vì chỉ confidence)
        attack_plan.sort(key=lambda x: x.get("priority_score", x.get("confidence", 0)), reverse=True)

        # V1.0-FIX: Wrap output with filter_summary metadata
        output_data = {
            "filter_summary": {
                "total_candidates_before_filter": pre_filter_count if attack_plan or 'pre_filter_count' in dir() else 0,
                "total_kept": len(attack_plan),
                "total_dropped": dropped_count if 'dropped_count' in dir() else 0,
                "filter_criteria": "confidence >= 0.85 OR verified == True OR is_kev == True",
                "framework_version": "V1.0 — High-Fidelity Intelligence",
            },
            "attack_plan": attack_plan,
        }

        with open(self.out_file, 'w') as f:
            json.dump(output_data, f, indent=4)
        print(f"\n[+] Đã tạo Attack Plan M2 V1.0 (High-Fidelity Intelligence) tại: {self.out_file} (Tổng {len(attack_plan)} targets)")

    @staticmethod
    def _nuclei_severity_to_confidence(severity: str) -> float:
        """
        [V1.0] Chuyển đổi Nuclei severity thành confidence score.
        Hạ info/low xuống thấp hơn để bộ lọc CVE rác dễ dàng loại bỏ chúng.
        """
        mapping = {
            "critical": 0.95,
            "high": 0.90,
            "medium": 0.75,
            "low": 0.35,     # [V1.0] Hạ từ 0.50 → 0.35 (để _filter_junk_cves dễ loại)
            "info": 0.15,     # [V1.0] Hạ từ 0.30 → 0.15 (gần như luôn bị loại)
        }
        return mapping.get(severity.lower(), 0.60)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--m1-json", required=True, help="File JSON đầu vào từ Module 1")
    p.add_argument("--output", required=True, help="File JSON đầu ra Kế hoạch tấn công (M2)")
    p.add_argument("--debug", action="store_true", help="Bật chế độ xuất toàn bộ log nội bộ")
    a = p.parse_args()
    VulnAnalyzer(a.m1_json, a.output).analyze()
