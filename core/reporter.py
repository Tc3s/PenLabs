#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — Reporter Module (Extracted from Module1/main.py)
================================================================
Generates Markdown attack_surface_report.md by merging:
  - M1 Recon data (subdomains, endpoints, tech stack)
  - M2 VulnAnalysis attack plan (CVEs, severity)
  - Web Logic Flaws (XSS, SSRF, CORS, BOLA — bypass M2 CPE filter)
  - Recursive subdomain scan results
  - Origin discovery findings

Provides a single entry point: generate_attack_surface_report()
"""

import os
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def _dast_findings_by_category(findings: list[dict], category: str) -> list[dict]:
    return [finding for finding in findings or [] if str(finding.get("category", "")).lower() == category]


def _dast_summary(m1_data: dict) -> dict:
    summary = m1_data.get("summary", {}) if isinstance(m1_data, dict) else {}
    if summary:
        return summary

    dast_findings = m1_data.get("dast_findings", []) if isinstance(m1_data, dict) else []
    return {
        "mode": m1_data.get("scan_mode", ""),
        "nuclei_findings": len(m1_data.get("nuclei_findings", [])),
        "xss": len(_dast_findings_by_category(dast_findings, "xss")),
        "cors": len(_dast_findings_by_category(dast_findings, "cors")),
        "blind_xss": len(_dast_findings_by_category(dast_findings, "blind_xss")),
        "mass_assignment": len(_dast_findings_by_category(dast_findings, "mass_assignment")),
        "ssrf": len(_dast_findings_by_category(dast_findings, "ssrf")),
        "sqli": len(_dast_findings_by_category(dast_findings, "sqli")),
        "open_redirect": len(_dast_findings_by_category(dast_findings, "open_redirect")),
        "crlf": len(_dast_findings_by_category(dast_findings, "crlf")),
        "parameterized_urls": len(m1_data.get("web_urls_with_params", []) or []),
        "vhosts": len(m1_data.get("vhosts", []) or []),
    }


def _merge_web_logic_findings(m1_data: dict, web_logic_findings: list | None) -> list[dict]:
    merged = list(web_logic_findings or [])
    dast_findings = m1_data.get("dast_findings", []) if isinstance(m1_data, dict) else []
    existing_keys = {
        (
            str(item.get("type", "")),
            str(item.get("url", "")),
            str(item.get("details", item.get("evidence", ""))),
        )
        for item in merged
        if isinstance(item, dict)
    }

    category_alias = {
        "cors": "CORS_Misconfiguration",
        "xss": "XSS",
        "blind_xss": "Blind_XSS",
        "mass_assignment": "Mass_Assignment",
        "ssrf": "SSRF",
        "sqli": "SQLi",
        "open_redirect": "Open_Redirect",
        "crlf": "CRLF_Injection",
        "bypass_403": "Bypass_403",
        "cache_poisoning": "Cache_Poisoning",
        "race_condition": "Race_Condition",
        "graphql": "GraphQL_Exposure",
        "bola": "BOLA_IDOR",
        "wordpress": "WordPress_Vulnerability",
    }

    for finding in dast_findings:
        if not isinstance(finding, dict):
            continue
        ftype = category_alias.get(str(finding.get("category", "")).lower(), finding.get("category", "unknown"))
        normalized = {
            "type": ftype,
            "severity": str(finding.get("severity", "medium")).upper(),
            "url": finding.get("url", ""),
            "source": finding.get("tool", "DAST"),
            "details": finding.get("title", ""),
            "evidence": finding.get("evidence", ""),
            "verification_status": finding.get("verification_status", ""),
            "evidence_path": (
                finding.get("evidence_detail", {}).get("raw_artifact", "")
                if isinstance(finding.get("evidence_detail"), dict) else ""
            ),
        }
        dedupe_key = (normalized["type"], normalized["url"], normalized["details"] or normalized["evidence"])
        if dedupe_key not in existing_keys:
            merged.append(normalized)
            existing_keys.add(dedupe_key)

    return merged


def _verification_summary(m1_data: dict) -> dict:
    summary = m1_data.get("verification_summary", {}) if isinstance(m1_data, dict) else {}
    if summary:
        return summary
    buckets = {"confirmed": 0, "suspected": 0, "manual_review": 0, "noise": 0}
    for finding in m1_data.get("dast_findings", []) if isinstance(m1_data, dict) else []:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("verification_status", "manual_review")).lower()
        buckets[status if status in buckets else "manual_review"] += 1
    return buckets


def _knowledge_profile(m1_data: dict) -> dict:
    if not isinstance(m1_data, dict):
        return {}
    profile = m1_data.get("knowledge_profile", {})
    if isinstance(profile, dict) and profile:
        return profile
    coverage = m1_data.get("wstg_coverage", {})
    manual_handoff = m1_data.get("manual_handoff", [])
    if isinstance(coverage, dict) and coverage:
        return {
            "wstg_coverage": coverage,
            "manual_handoff": manual_handoff if isinstance(manual_handoff, list) else [],
            "technique_codes": coverage.get("technique_codes", []),
        }
    return {}


def generate_attack_surface_report(
    session_dir: str,
    target: str,
    mode: str = "sniper",
    m1_json_path: str = "",
    m2_json_path: str = "",
    web_logic_findings: list = None,
    recursive_summary: list = None,
    origin_result: dict = None,
) -> str:
    """
    Generate a comprehensive Markdown attack surface report.

    Args:
        session_dir: Session output directory
        target: Primary scan target
        mode: Scan mode used
        m1_json_path: Path to m1_recon.json
        m2_json_path: Path to m2_vuln.json
        web_logic_findings: List of web logic flaw dicts (XSS, SSRF, CORS, etc.)
        recursive_summary: List of recursive subdomain scan results
        origin_result: Origin discovery engine result dict

    Returns:
        str: Path to generated report file
    """
    report_lines = []
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Header ──
    report_lines.append(f"# 🎯 PenLabs V1.0 — Attack Surface Report")
    report_lines.append(f"")
    report_lines.append(f"**Target:** `{target}`")
    report_lines.append(f"**Mode:** `{mode.upper()}`")
    report_lines.append(f"**Generated:** {timestamp}")
    report_lines.append(f"**Session:** `{os.path.basename(session_dir)}`")
    report_lines.append(f"")
    report_lines.append(f"---")
    report_lines.append(f"")

    # ── Origin Discovery ──
    if origin_result and origin_result.get("origin_ip"):
        report_lines.append(f"## 🌐 Origin Discovery")
        report_lines.append(f"")
        report_lines.append(f"| Field | Value |")
        report_lines.append(f"|-------|-------|")
        report_lines.append(f"| Origin IP | `{origin_result['origin_ip']}` |")
        report_lines.append(f"| Method | {origin_result.get('method', 'N/A')} |")
        report_lines.append(f"| Confidence | {origin_result.get('confidence', 0)}% |")
        if origin_result.get("favicon_hash"):
            report_lines.append(f"| Favicon Hash | `{origin_result['favicon_hash']}` |")
        report_lines.append(f"")

    # ── M1 Recon Summary ──
    m1_data = {}
    if m1_json_path and os.path.exists(m1_json_path):
        try:
            with open(m1_json_path, "r") as f:
                raw = json.load(f)
                m1_data = raw[0] if isinstance(raw, list) and raw else (raw if isinstance(raw, dict) else {})
        except Exception as e:
            logger.warning(f"[Reporter] M1 JSON parse error: {e}")

    if m1_data:
        dast_summary = _dast_summary(m1_data)
        report_lines.append(f"## 📡 Reconnaissance Summary")
        report_lines.append(f"")
        report_lines.append(f"| Metric | Count |")
        report_lines.append(f"|--------|-------|")
        report_lines.append(f"| Open Ports | {len(m1_data.get('open_ports', []))} |")
        report_lines.append(f"| Subdomains | {len(m1_data.get('subdomains', []))} |")
        report_lines.append(f"| Web URLs | {len(m1_data.get('web_urls', []))} |")
        report_lines.append(f"| API Endpoints | {len(m1_data.get('api_endpoints', []))} |")
        report_lines.append(f"| JS Files | {len(m1_data.get('js_files', []))} |")
        report_lines.append(f"| Nuclei Findings | {len(m1_data.get('nuclei_findings', []))} |")
        report_lines.append(f"| CVE Candidates | {len(m1_data.get('cve_candidates', []))} |")
        if dast_summary.get("blind_xss", 0):
            report_lines.append(f"| Blind XSS | {dast_summary.get('blind_xss', 0)} |")
        if dast_summary.get("mass_assignment", 0):
            report_lines.append(f"| Mass Assignment | {dast_summary.get('mass_assignment', 0)} |")
        report_lines.append(f"")

        verification = _verification_summary(m1_data)
        if any(verification.values()):
            report_lines.append(f"**DAST Verification Buckets**")
            report_lines.append(f"")
            report_lines.append(f"| Bucket | Count |")
            report_lines.append(f"|--------|-------|")
            for label, key in [
                ("Confirmed", "confirmed"),
                ("Suspected", "suspected"),
                ("Manual Review", "manual_review"),
                ("Noise", "noise"),
            ]:
                report_lines.append(f"| {label} | {verification.get(key, 0)} |")
            report_lines.append(f"")

        # Tech Stack
        tech = m1_data.get("tech_stack", [])
        if tech:
            report_lines.append(f"**Tech Stack:** {', '.join(tech)}")
            report_lines.append(f"")

        # OS Detection
        os_detect = m1_data.get("os_detection", [])
        if os_detect:
            report_lines.append(f"**OS Detection:** {', '.join(os_detect)}")
            report_lines.append(f"")

        wordlist_profile = m1_data.get("wordlist_profile", {}) if isinstance(m1_data.get("wordlist_profile", {}), dict) else {}
        if wordlist_profile:
            report_lines.append(f"## 📚 Wordlist Profile")
            report_lines.append(f"")
            report_lines.append(f"| Purpose | Source | Path |")
            report_lines.append(f"|---------|--------|------|")
            for purpose in ["web_content", "sensitive_paths", "api_routes", "api_params", "s3_buckets", "passwords"]:
                item = wordlist_profile.get(purpose, {})
                if not isinstance(item, dict):
                    continue
                path = item.get("path", "")
                report_lines.append(f"| {purpose} | {item.get('source', '')} | `{path}` |")
            report_lines.append(f"")

        knowledge = _knowledge_profile(m1_data)
        coverage = knowledge.get("wstg_coverage", {}) if isinstance(knowledge.get("wstg_coverage"), dict) else {}
        if coverage:
            report_lines.append(f"## 🧭 Knowledge-Guided Coverage")
            report_lines.append(f"")
            technique_codes = coverage.get("technique_codes", []) or knowledge.get("technique_codes", [])
            if technique_codes:
                report_lines.append(f"**Technique Codes:** {', '.join(str(code) for code in technique_codes[:20])}")
                report_lines.append(f"")
            covered_refs = coverage.get("covered_wstg_refs", []) or []
            manual_gaps = coverage.get("manual_gaps", []) or []
            report_lines.append(f"| Metric | Count |")
            report_lines.append(f"|--------|------:|")
            report_lines.append(f"| Covered WSTG Refs | {len(covered_refs)} |")
            report_lines.append(f"| Manual Coverage Gaps | {len(manual_gaps)} |")
            report_lines.append(f"| Framework Hints | {len(coverage.get('framework_hints', []) or [])} |")
            report_lines.append(f"")
            if covered_refs:
                report_lines.append(f"**Covered refs:** {', '.join(str(ref) for ref in covered_refs[:30])}")
                report_lines.append(f"")
            framework_hints = coverage.get("framework_hints", []) or []
            if framework_hints:
                report_lines.append(f"### Framework First Tests")
                report_lines.append(f"")
                report_lines.append(f"| Framework | First Tests | Guide |")
                report_lines.append(f"|-----------|-------------|-------|")
                for hint in framework_hints[:10]:
                    tests = ", ".join(str(item) for item in hint.get("first_tests", [])[:5])
                    report_lines.append(f"| {hint.get('framework', '')} | {tests} | `{hint.get('guide', '')}` |")
                report_lines.append(f"")
            if manual_gaps:
                report_lines.append(f"### Manual Coverage Gaps")
                report_lines.append(f"")
                report_lines.append(f"| WSTG | Title | Reason | Guide |")
                report_lines.append(f"|------|-------|--------|-------|")
                for gap in manual_gaps[:12]:
                    report_lines.append(
                        f"| `{gap.get('wstg_id', '')}` | {gap.get('title', '')} | {gap.get('reason', '')} | `{gap.get('guide', '')}` |"
                    )
                report_lines.append(f"")
            handoff = knowledge.get("manual_handoff", []) if isinstance(knowledge.get("manual_handoff"), list) else []
            if handoff:
                report_lines.append(f"### Manual Handoff Queue")
                report_lines.append(f"")
                report_lines.append(f"| Category | Status | WSTG | Next Step |")
                report_lines.append(f"|----------|--------|------|-----------|")
                for item in handoff[:15]:
                    refs = ", ".join(str(ref) for ref in item.get("wstg_refs", [])[:3])
                    next_step = str(item.get("next_step", "")).replace("|", "/")
                    report_lines.append(
                        f"| {item.get('category', '')} | {item.get('status', '')} | {refs} | {next_step} |"
                    )
                report_lines.append(f"")

    # ── M2 Vulnerability Attack Plan ──
    m2_data = {}
    if m2_json_path and os.path.exists(m2_json_path):
        try:
            with open(m2_json_path, "r") as f:
                m2_data = json.load(f)
        except Exception as e:
            logger.warning(f"[Reporter] M2 JSON parse error: {e}")

    # V1.0-FIX: Handle both old format (flat list) and new format (dict with filter_summary)
    if isinstance(m2_data, dict):
        attack_plan = m2_data.get("attack_plan", [])
        filter_summary = m2_data.get("filter_summary", {})
    elif isinstance(m2_data, list):
        attack_plan = m2_data  # Legacy flat list format
        filter_summary = {}
    else:
        attack_plan = []
        filter_summary = {}

    if attack_plan:
        report_lines.append(f"## ⚔️ Vulnerability Attack Plan ({len(attack_plan)} entries)")
        report_lines.append(f"")

        # V1.0-FIX: Show filter summary if available
        if filter_summary:
            report_lines.append(f"> **Intelligence Filter:** {filter_summary.get('filter_criteria', 'N/A')}")
            report_lines.append(f"> Candidates: {filter_summary.get('total_candidates_before_filter', '?')} → "
                                f"Kept: {filter_summary.get('total_kept', '?')} | "
                                f"Dropped: {filter_summary.get('total_dropped', '?')}")
            report_lines.append(f"")

        # Group by severity
        severity_groups = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        for entry in attack_plan:
            sev = entry.get("severity", "MEDIUM").upper()
            if sev not in severity_groups:
                sev = "MEDIUM"
            severity_groups[sev].append(entry)

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            entries = severity_groups[sev]
            if not entries:
                continue
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
            report_lines.append(f"### {emoji} {sev} ({len(entries)})")
            report_lines.append(f"")
            report_lines.append(f"| CVE/ID | Target | Source | Description |")
            report_lines.append(f"|--------|--------|--------|-------------|")
            for e in entries[:50]:  # Cap to prevent massive reports
                cve = e.get("cve", "N/A")
                tgt = e.get("target", e.get("matched_at", ""))[:60]
                src = e.get("source", e.get("match_source", ""))
                desc = e.get("description", "")[:80]
                report_lines.append(f"| `{cve}` | `{tgt}` | {src} | {desc} |")
            report_lines.append(f"")

    # ── Web Logic Flaws (Bypass M2 CPE Filter) ──
    web_logic = _merge_web_logic_findings(m1_data, web_logic_findings)
    if web_logic:
        report_lines.append(f"## 🕸️ Web Logic Flaws ({len(web_logic)} findings)")
        report_lines.append(f"")
        report_lines.append(f"> These findings bypass the M2 CPE version filter — they are ")
        report_lines.append(f"> logic-level vulnerabilities confirmed directly by scanning tools.")
        report_lines.append(f"")

        dast_summary = _dast_summary(m1_data)
        report_lines.append(f"| Category | Count |")
        report_lines.append(f"|----------|-------|")
        for name, key in [
            ("XSS", "xss"),
            ("Blind XSS", "blind_xss"),
            ("Mass Assignment", "mass_assignment"),
            ("CORS", "cors"),
            ("SSRF", "ssrf"),
            ("SQLi", "sqli"),
            ("Open Redirect", "open_redirect"),
            ("CRLF", "crlf"),
        ]:
            if dast_summary.get(key, 0):
                report_lines.append(f"| {name} | {dast_summary.get(key, 0)} |")
        report_lines.append(f"")

        # Separate CORS findings for explicit surfacing
        cors_findings = [f for f in web_logic if f.get("type") == "CORS_Misconfiguration"]
        other_findings = [f for f in web_logic if f.get("type") != "CORS_Misconfiguration"]

        if cors_findings:
            report_lines.append(f"### 🔓 CORS Misconfigurations ({len(cors_findings)})")
            report_lines.append(f"")
            for cors in cors_findings:
                sev = cors.get("severity", "MEDIUM")
                url = cors.get("url", "")
                details = cors.get("details", "")
                evidence = cors.get("evidence", "")
                remediation = cors.get("remediation", "")
                emoji = "🔴" if sev in ("CRITICAL", "critical") else "🟠" if sev in ("HIGH", "high") else "🟡"
                report_lines.append(f"- {emoji} **[{sev}]** `{url}`")
                report_lines.append(f"  - {details}")
                if evidence:
                    report_lines.append(f"  - **Evidence:**")
                    for ev_line in evidence.split("\n"):
                        report_lines.append(f"    ```")
                        report_lines.append(f"    {ev_line}")
                        report_lines.append(f"    ```")
                if remediation:
                    report_lines.append(f"  - **Remediation:** {remediation}")
                report_lines.append(f"")

        if other_findings:
            report_lines.append(f"### 🔍 Other Web Logic Findings ({len(other_findings)})")
            report_lines.append(f"")
            report_lines.append(f"| Type | Severity | Status | URL | Source | Details | Evidence Path |")
            report_lines.append(f"|------|----------|--------|-----|--------|---------|---------------|")
            for f in other_findings:
                ftype = f.get("type", "unknown")
                sev = f.get("severity", "MEDIUM")
                status = f.get("verification_status", "")
                url = f.get("url", "")[:50]
                src = f.get("source", "")
                det = f.get("details", f.get("payload", ""))[:60]
                evidence_path = f.get("evidence_path", "")
                report_lines.append(f"| {ftype} | {sev} | {status} | `{url}` | {src} | {det} | `{evidence_path}` |")
            report_lines.append(f"")

    attack_chains = m1_data.get("attack_chains", []) if isinstance(m1_data, dict) else []
    if attack_chains:
        report_lines.append(f"## 🔗 Correlated Attack Paths ({len(attack_chains)})")
        report_lines.append(f"")
        report_lines.append(f"| Chain | Severity | Score | Manual Next Step |")
        report_lines.append(f"|-------|----------|------:|------------------|")
        for chain in attack_chains[:20]:
            report_lines.append(
                f"| {chain.get('title', '')} | {str(chain.get('severity', '')).upper()} | {chain.get('score', 0)} | {chain.get('manual_next', '')} |"
            )
        report_lines.append(f"")

    # ── Recursive Subdomain Scan Results ──
    rec_summary = recursive_summary or []
    if not rec_summary and os.path.exists(os.path.join(session_dir, "raw")):
        raw_dir = os.path.join(session_dir, "raw")
        sub_results = [f for f in os.listdir(raw_dir) if f.startswith("sub_result_") and f.endswith(".json")]
        if sub_results:
            auto_summary = []
            for sr in sorted(sub_results):
                sr_path = os.path.join(raw_dir, sr)
                try:
                    with open(sr_path, "r") as f:
                        sr_data = json.load(f)
                        sub_name = sr_data.get("_subdomain", sr.replace("sub_result_", "").replace(".json", ""))
                        origin_ip = sr_data.get("_origin_ip") or sr_data.get("_ip") or "N/A"
                        dast_count = len(sr_data.get("dast_findings", []))
                        nuclei_count = len(sr_data.get("nuclei_findings", []))
                        auto_summary.append({
                            "subdomain": sub_name,
                            "origin_ip": origin_ip,
                            "m2_findings": dast_count + nuclei_count
                        })
                except Exception:
                    pass
            if auto_summary:
                rec_summary = auto_summary

    if rec_summary:
        total_findings = sum(r.get("m2_findings", 0) for r in rec_summary)
        origins_found = sum(1 for r in rec_summary if r.get("origin_ip") and r.get("origin_ip") != "N/A")
        report_lines.append(f"## 🔄 Recursive Subdomain Scan ({len(rec_summary)} subdomains)")
        report_lines.append(f"")
        report_lines.append(f"| Subdomain | Origin IP | Findings |")
        report_lines.append(f"|-----------|-----------|----------|")
        for rs in rec_summary:
            sub = rs.get("subdomain", "")
            origin = rs.get("origin_ip", "N/A") or "N/A"
            findings = rs.get("m2_findings", 0)
            report_lines.append(f"| `{sub}` | `{origin}` | {findings} |")
        report_lines.append(f"")
        report_lines.append(f"**Total:** {len(rec_summary)} subdomains, {origins_found} origins, {total_findings} findings")
        report_lines.append(f"")

    # ── Nuclei Details ──
    nuclei_findings = m1_data.get("nuclei_findings", [])
    if nuclei_findings:
        report_lines.append(f"## 🔬 Nuclei Findings ({len(nuclei_findings)} detections)")
        report_lines.append(f"")
        report_lines.append(f"| Template | Severity | Matched At |")
        report_lines.append(f"|----------|----------|------------|")
        for nf in nuclei_findings[:100]:
            if isinstance(nf, dict):
                template = nf.get("template-id", nf.get("name", "N/A"))
                sev = nf.get("info", {}).get("severity", nf.get("severity", "unknown"))
                matched = nf.get("matched-at", nf.get("matched_at", ""))[:60]
                report_lines.append(f"| `{template}` | {sev} | `{matched}` |")
        report_lines.append(f"")

    # ── Footer ──
    report_lines.append(f"---")
    report_lines.append(f"")
    report_lines.append(f"*Generated by PenLabs V1.0 — Automated Pentest Framework*")
    report_lines.append(f"*Report timestamp: {timestamp}*")

    # Write report
    report_path = os.path.join(session_dir, "attack_surface_report.md")
    with open(report_path, "w") as f:
        f.write("\n".join(report_lines))

    logger.info(f"[Reporter] Attack surface report saved: {report_path}")
    return report_path


def merge_recursive_into_report(
    session_dir: str,
    report_path: str,
    recursive_results_dir: str,
) -> str:
    """
    Append recursive scan findings into an existing attack_surface_report.md.

    Walks recursive_results_dir for m2_vuln.json files and appends their
    attack plans to the report.

    Returns:
        str: Updated report path
    """
    if not os.path.exists(report_path) or not os.path.exists(recursive_results_dir):
        return report_path

    append_lines = []
    total_merged = 0

    for sub_dir_name in sorted(os.listdir(recursive_results_dir)):
        sub_dir = os.path.join(recursive_results_dir, sub_dir_name)
        if not os.path.isdir(sub_dir):
            continue

        m2_file = os.path.join(sub_dir, "m2_vuln.json")
        if not os.path.exists(m2_file):
            continue

        try:
            with open(m2_file, "r") as f:
                m2_data = json.load(f)

            attack_plan = m2_data.get("attack_plan", []) if isinstance(m2_data, dict) else []
            if attack_plan:
                subdomain = sub_dir_name.replace("_", ".")
                append_lines.append(f"\n### 📂 {subdomain} ({len(attack_plan)} findings)\n")
                for entry in attack_plan[:20]:
                    cve = entry.get("cve", "N/A")
                    sev = entry.get("severity", "MEDIUM")
                    tgt = entry.get("target", "")[:60]
                    append_lines.append(f"- **[{sev}]** `{cve}` — `{tgt}`")
                append_lines.append("")
                total_merged += len(attack_plan)
        except Exception:
            continue

    if append_lines:
        with open(report_path, "a") as f:
            f.write(f"\n## 📊 Recursive Scan Details ({total_merged} merged findings)\n")
            f.write("\n".join(append_lines))

        logger.info(f"[Reporter] Merged {total_merged} recursive findings into report.")

    return report_path
