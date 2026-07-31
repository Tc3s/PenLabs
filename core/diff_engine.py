#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — Diff Engine (Scan-to-Scan Comparison)
======================================================
Compares current scan results against the persistent database state
to detect NEW, CHANGED, and REMOVED assets/vulnerabilities.

Generates ScanDiff events for local reporting and regression tracking.

Inspired by reNgine's continuous monitoring and delta reporting.

Usage:
    from core.diff_engine import DiffEngine
    from core.db import get_session, init_db

    engine = DiffEngine(project_id=1, scan_session_id=5)
    with get_session() as session:
        diff_report = engine.ingest_recon_results(session, m1_data)
"""

import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from core.db import (
    Asset, AssetType, Technology, Port, Vulnerability, ScanDiff,
    DiffEventType, Severity, VulnStatus,
    upsert_asset, upsert_vulnerability, _utcnow,
)
from sqlalchemy.orm import Session as SASession

logger = logging.getLogger(__name__)


def _as_finding_list(findings: Any) -> List[dict]:
    if isinstance(findings, list):
        return [item for item in findings if isinstance(item, dict)]
    if isinstance(findings, dict):
        flattened = []
        for value in findings.values():
            if isinstance(value, list):
                flattened.extend(item for item in value if isinstance(item, dict))
        return flattened
    return []


def _collect_dast_findings(m1_data: dict[str, Any]) -> List[dict]:
    findings = m1_data.get("dast_findings", [])
    if findings:
        return _as_finding_list(findings)

    from core.dast_contract import normalize_dast_findings

    collected: List[dict] = []
    for category, key in [
        ("xss", "xss_findings"),
        ("ssrf", "ssrf_findings"),
        ("cors", "cors_findings"),
        ("open_redirect", "open_redirect_findings"),
        ("bola", "bola_findings"),
        ("graphql", "graphql_findings"),
        ("crlf", "crlf_findings"),
        ("blind_xss", "blind_xss"),
        ("mass_assignment", "mass_assignment_findings"),
        ("bypass_403", "bypass_403"),
        ("cache_poisoning", "cache_poisoning"),
        ("race_condition", "race_condition_findings"),
        ("sqli", "sqli_findings"),
        ("wordpress", "wpscan"),
    ]:
        raw_output = m1_data.get(key)
        if raw_output:
            collected.extend(normalize_dast_findings(category, raw_output))
    return collected


# ═══════════════════════════════════════════════════════════════════
# DIFF REPORT — Summary of what changed
# ═══════════════════════════════════════════════════════════════════

@dataclass
class DiffReport:
    """Structured summary of changes detected in this scan cycle."""
    new_subdomains: List[str] = field(default_factory=list)
    new_endpoints: List[str] = field(default_factory=list)
    new_ips: List[str] = field(default_factory=list)
    new_ports: List[dict] = field(default_factory=list)
    new_vulns: List[dict] = field(default_factory=list)
    new_js_files: List[str] = field(default_factory=list)
    changed_js: List[dict] = field(default_factory=list)
    tech_changes: List[dict] = field(default_factory=list)
    
    # Stats
    total_assets_processed: int = 0
    total_vulns_processed: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_subdomains or self.new_endpoints or self.new_ips
            or self.new_ports or self.new_vulns or self.new_js_files
            or self.changed_js or self.tech_changes
        )

    @property
    def summary(self) -> str:
        parts = []
        if self.new_subdomains:
            parts.append(f"{len(self.new_subdomains)} new subdomains")
        if self.new_endpoints:
            parts.append(f"{len(self.new_endpoints)} new endpoints")
        if self.new_ips:
            parts.append(f"{len(self.new_ips)} new IPs")
        if self.new_ports:
            parts.append(f"{len(self.new_ports)} new ports")
        if self.new_vulns:
            parts.append(f"{len(self.new_vulns)} new vulnerabilities")
        if self.new_js_files:
            parts.append(f"{len(self.new_js_files)} new JS files")
        if self.changed_js:
            parts.append(f"{len(self.changed_js)} changed JS files")
        if self.tech_changes:
            parts.append(f"{len(self.tech_changes)} tech changes")
        return ", ".join(parts) if parts else "No changes detected"


# ═══════════════════════════════════════════════════════════════════
# DIFF ENGINE
# ═══════════════════════════════════════════════════════════════════

class DiffEngine:
    """
    Core intelligence engine for scan-to-scan comparison.
    
    Workflow:
      1. Receive raw M1 recon data (JSON dict)
      2. Upsert into DB (dedup automatically)
      3. Track which assets are NEW vs EXISTING
      4. Generate ScanDiff events for new discoveries
      5. Return DiffReport for local reporting
    """

    def __init__(self, project_id: int, scan_session_id: int):
        self.project_id = project_id
        self.scan_session_id = scan_session_id

    # ─── Main Entry Point ─────────────────────────────────────────

    def ingest_recon_results(self, session: SASession, m1_data) -> DiffReport:
        """
        Ingest Module 1 recon results into the database.
        Performs deduplication and generates a DiffReport.
        
        Args:
            session: SQLAlchemy session (from get_session context manager)
            m1_data: Parsed JSON from m1_recon.json (list of asset dicts or single dict)
            
        Returns:
            DiffReport with lists of new/changed assets
        """
        report = DiffReport()

        # V1.0-FIX: Handle both list format (per schema) and legacy dict format
        if isinstance(m1_data, list):
            assets = m1_data
        elif isinstance(m1_data, dict):
            assets = [m1_data]
        else:
            logger.warning(f"[DiffEngine] Unexpected m1_data type: {type(m1_data)}")
            return report

        for asset in assets:
            if not isinstance(asset, dict):
                continue
            # 1. Subdomains
            self._ingest_subdomains(session, asset, report)

            # 2. Endpoints (from Katana, httpx, etc.)
            self._ingest_endpoints(session, asset, report)

            # 3. Ports (from Nmap, Naabu)
            self._ingest_ports(session, asset, report)

            # 4. Technologies (from Wappalyzer, httpx)
            self._ingest_technologies(session, asset, report)

            # 5. JS files
            self._ingest_js_files(session, asset, report)

            # 6. Vulnerabilities (from M1 direct findings)
            self._ingest_vulnerabilities(session, asset, report)

        logger.info(
            f"[DiffEngine] Ingestion complete: {report.total_assets_processed} assets, "
            f"{report.total_vulns_processed} vulns. Changes: {report.summary}"
        )
        return report

    # ─── Subdomain Ingestion ──────────────────────────────────────

    def _ingest_subdomains(self, session: SASession, m1_data: dict, report: DiffReport):
        """Parse and upsert subdomains from M1 output."""
        subdomains = m1_data.get("subdomains", [])
        if not subdomains:
            return

        for sub in subdomains:
            if isinstance(sub, str):
                sub_value = sub.strip().lower()
                source = "unknown"
            elif isinstance(sub, dict):
                sub_value = sub.get("subdomain", sub.get("value", "")).strip().lower()
                source = sub.get("source", "unknown")
            else:
                continue

            if not sub_value:
                continue

            asset, is_new = upsert_asset(
                session, self.project_id, AssetType.SUBDOMAIN,
                sub_value, source_tool=source, is_alive=True,
            )
            report.total_assets_processed += 1

            if is_new:
                report.new_subdomains.append(sub_value)
                self._create_diff_event(
                    session, DiffEventType.NEW_SUBDOMAIN,
                    asset_id=asset.id, target_value=sub_value,
                    details={"source": source},
                )

    # ─── Endpoint Ingestion ───────────────────────────────────────

    def _ingest_endpoints(self, session: SASession, m1_data: dict, report: DiffReport):
        """Parse and upsert endpoints from httpx/Katana output."""
        # httpx live URLs
        live_urls = m1_data.get("live_urls", [])
        for url_entry in live_urls:
            if isinstance(url_entry, str):
                url = url_entry.strip()
                status = None
                title = ""
            elif isinstance(url_entry, dict):
                url = url_entry.get("url", "").strip()
                status = url_entry.get("status_code") or url_entry.get("status")
                title = url_entry.get("title", "")
            else:
                continue

            if not url:
                continue

            asset, is_new = upsert_asset(
                session, self.project_id, AssetType.ENDPOINT,
                url, is_alive=True, http_status=status, http_title=title,
                source_tool="httpx",
            )
            report.total_assets_processed += 1

            if is_new:
                report.new_endpoints.append(url)
                self._create_diff_event(
                    session, DiffEventType.NEW_ENDPOINT,
                    asset_id=asset.id, target_value=url,
                    details={"status": status, "title": title},
                )

        # Katana crawled URLs
        katana_urls = m1_data.get("katana_urls", m1_data.get("crawled_urls", []))
        for url in katana_urls:
            url_val = url.strip() if isinstance(url, str) else url.get("url", "").strip()
            if not url_val:
                continue
            asset, is_new = upsert_asset(
                session, self.project_id, AssetType.ENDPOINT,
                url_val, source_tool="katana",
            )
            report.total_assets_processed += 1
            if is_new:
                report.new_endpoints.append(url_val)

    # ─── Port Ingestion ───────────────────────────────────────────

    def _ingest_ports(self, session: SASession, m1_data: dict, report: DiffReport):
        """Parse and upsert port scan results from Nmap/Naabu."""
        # Nmap results
        nmap_data = m1_data.get("nmap", m1_data.get("nmap_results", {}))
        
        # Handle different nmap output formats
        hosts = nmap_data.get("hosts", [])
        if not hosts and isinstance(nmap_data, dict):
            # Flat format: {"ip": "...", "ports": [...]}
            if "ports" in nmap_data:
                hosts = [nmap_data]

        for host in hosts:
            ip = host.get("ip", host.get("address", ""))
            if not ip:
                continue

            # Upsert the IP as an asset
            ip_asset, ip_is_new = upsert_asset(
                session, self.project_id, AssetType.IP,
                ip, source_tool="nmap", is_alive=True,
            )
            report.total_assets_processed += 1
            if ip_is_new:
                report.new_ips.append(ip)

            # Upsert ports
            for port_info in host.get("ports", []):
                port_num = port_info.get("port", port_info.get("portid"))
                if port_num is None:
                    continue
                port_num = int(port_num)

                existing_port = session.query(Port).filter_by(
                    asset_id=ip_asset.id, port_number=port_num,
                    protocol=port_info.get("protocol", "tcp"),
                ).first()

                if existing_port:
                    existing_port.last_seen = _utcnow()
                    existing_port.state = port_info.get("state", "open")
                    if port_info.get("service"):
                        existing_port.service_name = port_info["service"]
                    if port_info.get("version"):
                        existing_port.service_version = port_info["version"]
                else:
                    new_port = Port(
                        asset_id=ip_asset.id,
                        port_number=port_num,
                        protocol=port_info.get("protocol", "tcp"),
                        state=port_info.get("state", "open"),
                        service_name=port_info.get("service", ""),
                        service_version=port_info.get("version", ""),
                        banner=port_info.get("banner", ""),
                    )
                    session.add(new_port)
                    session.flush()

                    report.new_ports.append({
                        "ip": ip,
                        "port": port_num,
                        "service": port_info.get("service", ""),
                    })
                    self._create_diff_event(
                        session, DiffEventType.NEW_PORT,
                        asset_id=ip_asset.id,
                        target_value=f"{ip}:{port_num}",
                        details=port_info,
                    )

    # ─── Technology Ingestion ─────────────────────────────────────

    def _ingest_technologies(self, session: SASession, m1_data: dict, report: DiffReport):
        """Parse and upsert technology stack from Wappalyzer/httpx."""
        tech_data = m1_data.get("technologies", m1_data.get("tech_stack", []))

        for tech_entry in tech_data:
            if isinstance(tech_entry, str):
                # Simple string: "Apache/2.4.51"
                name = tech_entry.split("/")[0] if "/" in tech_entry else tech_entry
                version = tech_entry.split("/")[1] if "/" in tech_entry else ""
                url = ""
            elif isinstance(tech_entry, dict):
                name = tech_entry.get("name", tech_entry.get("technology", ""))
                version = tech_entry.get("version", "")
                url = tech_entry.get("url", tech_entry.get("host", ""))
            else:
                continue

            if not name:
                continue

            # Find the parent asset (endpoint or subdomain)
            parent_asset = None
            if url:
                parent_asset = session.query(Asset).filter_by(
                    project_id=self.project_id, value=url,
                ).first()

            if not parent_asset:
                # Create a generic domain asset if needed
                target = m1_data.get("target", "")
                if target:
                    parent_asset, _ = upsert_asset(
                        session, self.project_id, AssetType.DOMAIN,
                        target, source_tool="wappalyzer",
                    )

            if not parent_asset:
                continue

            # Check if technology already known
            existing_tech = session.query(Technology).filter_by(
                asset_id=parent_asset.id, name=name,
            ).first()

            if existing_tech:
                if existing_tech.version != version and version:
                    # Version changed!
                    old_version = existing_tech.version
                    existing_tech.version = version
                    existing_tech.last_seen = _utcnow()
                    report.tech_changes.append({
                        "name": name,
                        "old_version": old_version,
                        "new_version": version,
                        "url": url,
                    })
                    self._create_diff_event(
                        session, DiffEventType.TECH_CHANGED,
                        asset_id=parent_asset.id,
                        target_value=f"{name} {old_version} → {version}",
                        details={"name": name, "old": old_version, "new": version},
                    )
                else:
                    existing_tech.last_seen = _utcnow()
            else:
                new_tech = Technology(
                    asset_id=parent_asset.id,
                    name=name,
                    version=version,
                    cpe=tech_entry.get("cpe", "") if isinstance(tech_entry, dict) else "",
                    category=tech_entry.get("category", "") if isinstance(tech_entry, dict) else "",
                )
                session.add(new_tech)

    # ─── JS File Ingestion ────────────────────────────────────────

    def _ingest_js_files(self, session: SASession, m1_data: dict, report: DiffReport):
        """Parse and upsert JS files (for content change tracking)."""
        js_files = m1_data.get("js_files", m1_data.get("javascript_files", []))

        for js_entry in js_files:
            if isinstance(js_entry, str):
                js_url = js_entry.strip()
                js_hash = ""
            elif isinstance(js_entry, dict):
                js_url = js_entry.get("url", "").strip()
                js_hash = js_entry.get("hash", js_entry.get("content_hash", ""))
            else:
                continue

            if not js_url:
                continue

            asset, is_new = upsert_asset(
                session, self.project_id, AssetType.JS_FILE,
                js_url, content_hash=js_hash, source_tool="linkfinder",
            )
            report.total_assets_processed += 1

            if is_new:
                report.new_js_files.append(js_url)
                self._create_diff_event(
                    session, DiffEventType.NEW_JS,
                    asset_id=asset.id, target_value=js_url,
                )
            elif js_hash and asset.content_hash and asset.content_hash != js_hash:
                # JS content changed!
                old_hash = asset.content_hash
                asset.content_hash = js_hash
                report.changed_js.append({
                    "url": js_url,
                    "old_hash": old_hash,
                    "new_hash": js_hash,
                })
                self._create_diff_event(
                    session, DiffEventType.JS_CONTENT_CHANGED,
                    asset_id=asset.id, target_value=js_url,
                    details={"old_hash": old_hash, "new_hash": js_hash},
                )

    # ─── Vulnerability Ingestion ──────────────────────────────────

    def _ingest_vulnerabilities(self, session: SASession, m1_data: dict, report: DiffReport):
        """
        Parse and upsert vulnerabilities from M1 direct findings.
        Covers: XSS, SSRF, CORS, BOLA, Open Redirect, CRLF, GraphQL, Secrets.
        """
        dast_findings = _collect_dast_findings(m1_data)
        if dast_findings:
            category_map = {
                "xss": ("XSS", "dalfox"),
                "ssrf": ("SSRF", "SSRFProbe"),
                "cors": ("CORS_Misconfiguration", "corsy"),
                "open_redirect": ("Open_Redirect", "OpenRedirect"),
                "bola": ("BOLA_IDOR", "BOLAEngine"),
                "graphql": ("GraphQL_Exposure", "GraphQLProbe"),
                "crlf": ("CRLF_Injection", "CRLF"),
                "blind_xss": ("Blind_XSS", "blind_xss"),
                "mass_assignment": ("Mass_Assignment", "mass_assignment"),
                "bypass_403": ("Bypass_403", "bypass_403"),
                "cache_poisoning": ("Cache_Poisoning", "cache_poison_probe"),
                "race_condition": ("Race_Condition", "race_test"),
                "wordpress": ("WordPress_Vulnerability", "wpscan"),
            }

            for finding in _as_finding_list(dast_findings):
                if not isinstance(finding, dict):
                    continue

                category = str(finding.get("category", "")).lower()
                mapped = category_map.get(category)
                if not mapped:
                    continue

                vuln_type, default_tool = mapped
                url = finding.get("matched_at", finding.get("url", ""))
                severity_str = str(finding.get("severity", "medium")).upper()
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFO": Severity.INFO,
                }
                severity = severity_map.get(severity_str, Severity.MEDIUM)

                details_parts = []
                for detail_key in ["title", "evidence", "payload", "param", "finding_type", "confidence"]:
                    val = finding.get(detail_key)
                    if val:
                        details_parts.append(f"{detail_key}: {str(val)[:200]}")
                description = " | ".join(details_parts) if details_parts else ""

                vuln, is_new = upsert_vulnerability(
                    session, self.project_id, vuln_type,
                    evidence_url=url,
                    severity=severity.value,
                    title=f"{vuln_type} — {str(url)[:80]}",
                    description=description,
                    evidence_payload=finding.get("payload", ""),
                    reporter_tool=finding.get("tool", default_tool),
                    reporter_source="M1-DAST-Contract",
                    scan_session_id=self.scan_session_id,
                )
                report.total_vulns_processed += 1

                if is_new:
                    report.new_vulns.append({
                        "type": vuln_type,
                        "url": url,
                        "severity": severity.value,
                        "tool": finding.get("tool", default_tool),
                    })
                    self._create_diff_event(
                        session, DiffEventType.NEW_VULN,
                        target_value=f"[{severity.value.upper()}] {vuln_type}: {str(url)[:60]}",
                        details={"type": vuln_type, "url": url, "severity": severity.value},
                    )

            for finding in _as_finding_list(m1_data.get("secrets", m1_data.get("js_secrets", []))):
                url = finding.get("source", "")
                vuln, is_new = upsert_vulnerability(
                    session, self.project_id, "Hardcoded_Secret",
                    evidence_url=url,
                    severity=Severity.INFO.value,
                    title=f"Hardcoded_Secret — {str(url)[:80]}",
                    description=f"type: {finding.get('type', 'Unknown')} | value: {str(finding.get('value', ''))[:200]}",
                    reporter_tool="LinkFinder",
                    reporter_source="M1-Direct",
                    scan_session_id=self.scan_session_id,
                )
                report.total_vulns_processed += 1
                if is_new:
                    report.new_vulns.append({
                        "type": "Hardcoded_Secret",
                        "url": url,
                        "severity": Severity.INFO.value,
                        "tool": "LinkFinder",
                    })
                    self._create_diff_event(
                        session, DiffEventType.NEW_VULN,
                        target_value=f"[INFO] Hardcoded_Secret: {str(url)[:60]}",
                        details={"type": "Hardcoded_Secret", "url": url, "severity": Severity.INFO.value},
                    )

            # Nuclei remains separate below.
            nuclei_findings = m1_data.get("nuclei_findings", m1_data.get("nuclei", []))
            for finding in nuclei_findings:
                if not isinstance(finding, dict):
                    continue

                template = finding.get("template-id", finding.get("template", ""))
                matched_url = finding.get("matched-at", finding.get("host", finding.get("url", "")))
                sev = finding.get("info", {}).get("severity", finding.get("severity", "info"))

                severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                               "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
                severity = severity_map.get(sev.lower(), Severity.INFO)

                vuln, is_new = upsert_vulnerability(
                    session, self.project_id, f"Nuclei-{template}",
                    evidence_url=matched_url,
                    severity=severity.value,
                    title=finding.get("info", {}).get("name", template),
                    description=finding.get("info", {}).get("description", ""),
                    reporter_tool="nuclei",
                    reporter_source="M1-Direct",
                    scan_session_id=self.scan_session_id,
                )
                report.total_vulns_processed += 1
                if is_new:
                    report.new_vulns.append({
                        "type": f"Nuclei-{template}",
                        "url": matched_url,
                        "severity": severity.value,
                        "tool": "nuclei",
                    })
            return

        vuln_mappings = [
            ("xss_findings", "XSS", "dalfox"),
            ("ssrf_findings", "SSRF", "SSRFProbe"),
            ("cors_findings", "CORS_Misconfiguration", "corsy"),
            ("open_redirect_findings", "Open_Redirect", "OpenRedirect"),
            ("bola_findings", "BOLA_IDOR", "BOLAEngine"),
            ("graphql_findings", "GraphQL_Exposure", "GraphQLProbe"),
            ("crlf_findings", "CRLF_Injection", "CRLF"),
            ("secrets", "Hardcoded_Secret", "LinkFinder"),
        ]

        for json_key, vuln_type, tool in vuln_mappings:
            findings = m1_data.get(json_key, [])
            if json_key == "bola_findings":
                findings = _as_finding_list(findings)
            elif json_key == "graphql_findings" and isinstance(findings, dict):
                findings = _as_finding_list(findings)
            else:
                findings = _as_finding_list(findings)
            for finding in findings:
                if not isinstance(finding, dict):
                    continue

                url = finding.get("url", finding.get("source", ""))
                severity_str = finding.get("severity", "medium").upper()
                
                # Map to our Severity enum
                severity_map = {
                    "CRITICAL": Severity.CRITICAL,
                    "HIGH": Severity.HIGH,
                    "MEDIUM": Severity.MEDIUM,
                    "LOW": Severity.LOW,
                    "INFO": Severity.INFO,
                }
                severity = severity_map.get(severity_str, Severity.MEDIUM)

                # Build description from available fields
                details_parts = []
                for detail_key in ["details", "evidence", "payload", "param", "type", "value"]:
                    val = finding.get(detail_key)
                    if val:
                        details_parts.append(f"{detail_key}: {str(val)[:200]}")
                description = " | ".join(details_parts) if details_parts else ""

                vuln, is_new = upsert_vulnerability(
                    session, self.project_id, vuln_type,
                    evidence_url=url,
                    severity=severity.value,
                    title=f"{vuln_type} — {url[:80]}",
                    description=description,
                    evidence_payload=finding.get("payload", ""),
                    reporter_tool=tool,
                    reporter_source="M1-Direct",
                    scan_session_id=self.scan_session_id,
                )
                report.total_vulns_processed += 1

                if is_new:
                    report.new_vulns.append({
                        "type": vuln_type,
                        "url": url,
                        "severity": severity.value,
                        "tool": tool,
                    })
                    self._create_diff_event(
                        session, DiffEventType.NEW_VULN,
                        target_value=f"[{severity.value.upper()}] {vuln_type}: {url[:60]}",
                        details={"type": vuln_type, "url": url, "severity": severity.value},
                    )

        # Nuclei results (from M2 or direct nuclei runs)
        nuclei_findings = m1_data.get("nuclei_findings", m1_data.get("nuclei", []))
        for finding in nuclei_findings:
            if not isinstance(finding, dict):
                continue

            template = finding.get("template-id", finding.get("template", ""))
            matched_url = finding.get("matched-at", finding.get("host", finding.get("url", "")))
            sev = finding.get("info", {}).get("severity", finding.get("severity", "info"))

            severity_map = {"critical": Severity.CRITICAL, "high": Severity.HIGH,
                           "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO}
            severity = severity_map.get(sev.lower(), Severity.INFO)

            vuln, is_new = upsert_vulnerability(
                session, self.project_id, f"Nuclei-{template}",
                evidence_url=matched_url,
                severity=severity.value,
                title=finding.get("info", {}).get("name", template),
                description=finding.get("info", {}).get("description", ""),
                reporter_tool="nuclei",
                reporter_source="M1-Direct",
                scan_session_id=self.scan_session_id,
            )
            report.total_vulns_processed += 1
            if is_new:
                report.new_vulns.append({
                    "type": f"Nuclei-{template}",
                    "url": matched_url,
                    "severity": severity.value,
                    "tool": "nuclei",
                })

    # ─── ScanDiff Event Creator ───────────────────────────────────

    def _create_diff_event(self, session: SASession, event_type: DiffEventType,
                           asset_id: Optional[int] = None,
                           target_value: str = "",
                           details: Optional[dict] = None):
        """Create a ScanDiff record for change tracking and alerting."""
        diff = ScanDiff(
            scan_session_id=self.scan_session_id,
            event_type=event_type.value if isinstance(event_type, DiffEventType) else event_type,
            target_asset_id=asset_id,
            target_value=target_value[:2048],
            details=details or {},
            notified=False,
        )
        session.add(diff)
