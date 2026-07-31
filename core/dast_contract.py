#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical DAST finding contract for bounty/web-vuln plugins."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DASTFinding(BaseModel):
    category: str
    tool: str
    title: str
    severity: str = "medium"
    url: str = ""
    matched_at: str = ""
    method: str = ""
    param: str = ""
    payload: str = ""
    evidence: str = ""
    evidence_detail: dict[str, Any] = Field(default_factory=dict)
    confidence: str = ""
    finding_type: str = ""
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    return []


def _severity(value: Any, default: str = "medium") -> str:
    text = str(value or default).lower()
    return text if text in {"critical", "high", "medium", "low", "info"} else default


def _make(category: str, tool: str, item: dict[str, Any], **kwargs) -> dict[str, Any]:
    finding = DASTFinding(
        category=category,
        tool=tool,
        title=kwargs.get("title", category.replace("_", " ").title()),
        severity=_severity(kwargs.get("severity", item.get("severity"))),
        url=kwargs.get("url", item.get("url", item.get("endpoint", ""))),
        matched_at=kwargs.get("matched_at", item.get("matched_at", item.get("url", item.get("endpoint", "")))),
        method=str(kwargs.get("method", item.get("method", ""))).upper(),
        param=kwargs.get("param", item.get("param", "")),
        payload=kwargs.get("payload", item.get("payload", "")),
        evidence=kwargs.get("evidence", item.get("evidence", item.get("details", ""))),
        evidence_detail=kwargs.get("evidence_detail", item.get("evidence_detail", {})),
        confidence=str(kwargs.get("confidence", item.get("confidence", ""))).lower(),
        finding_type=kwargs.get("finding_type", item.get("finding_type", item.get("type", category))),
        tags=list(kwargs.get("tags", [])),
        raw=item,
    )
    if not finding.matched_at:
        finding.matched_at = finding.url
    return finding.model_dump()


def normalize_dast_findings(category: str, raw_output: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if category == "xss":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("xss", "dalfox", item, title="Cross-Site Scripting", tags=["xss", "cwe-79"]))

    elif category == "sqli":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("sqli", "sqlmap", item, title=item.get("title", "SQL Injection"), param=item.get("param", item.get("parameter", "")), tags=["sqli"]))

    elif category == "ssrf":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("ssrf", "ssrf_probe", item, title="Server-Side Request Forgery", tags=["ssrf"]))

    elif category == "cors":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("cors", "corsy", item, title="CORS Misconfiguration", tags=["cors"]))

    elif category == "graphql":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("graphql", "graphql_probe", item, title="GraphQL Exposure", tags=["graphql"]))

    elif category == "blind_xss":
        if isinstance(raw_output, dict):
            existing = raw_output.get("dast_findings") or raw_output.get("findings") or []
            for item in existing:
                if isinstance(item, dict):
                    findings.append(_make(
                        "blind_xss",
                        "blind_xss",
                        item,
                        title="Blind XSS Injection",
                        severity=item.get("severity", "medium"),
                        url=item.get("url", item.get("action", "")),
                        matched_at=item.get("matched_at", item.get("url", item.get("action", ""))),
                        evidence=item.get("evidence", ""),
                        finding_type=item.get("type", item.get("payload_type", "blind_xss")),
                        tags=["blind-xss", "xss", "stored-xss"],
                    ))
            if findings:
                return findings
            injections = raw_output.get("injections", [])
            for item in injections:
                if isinstance(item, dict):
                    fields = item.get("fields_injected", [])
                    findings.append(_make(
                        "blind_xss",
                        "blind_xss",
                        item,
                        title="Blind XSS Injection",
                        severity="medium",
                        url=item.get("action", item.get("url", "")),
                        matched_at=item.get("action", item.get("url", "")),
                        evidence=f"Injected blind XSS payload into fields: {', '.join(fields) if fields else 'unknown'}",
                        finding_type=item.get("payload_type", "blind_xss"),
                        tags=["blind-xss", "xss", "stored-xss"],
                    ))
            if not findings and raw_output.get("injected_count", 0):
                findings.append(_make(
                    "blind_xss",
                    "blind_xss",
                    raw_output,
                    title="Blind XSS Injection",
                    severity="medium",
                    evidence=(
                        f"Injected {raw_output.get('injected_count', 0)} blind XSS payloads "
                        f"into {raw_output.get('forms_found', 0)} forms; await OOB callbacks."
                    ),
                    finding_type="blind_xss_injection",
                    tags=["blind-xss", "xss", "stored-xss"],
                ))

    elif category == "mass_assignment":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make(
                    "mass_assignment",
                    "mass_assignment",
                    item,
                    title=item.get("vulnerability", "Mass Assignment"),
                    severity=item.get("severity", "medium"),
                    evidence=item.get("evidence", ""),
                    finding_type="mass_assignment",
                    tags=["mass-assignment", "api", "authorization"],
                ))

    elif category == "bypass_403":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make(
                    "bypass_403",
                    "bypass_403",
                    item,
                    title="403 Bypass",
                    severity=item.get("severity", "high"),
                    evidence=item.get("evidence", f"{item.get('bypass_method', '')} returned status {item.get('status', '')}").strip(),
                    finding_type="403_bypass",
                    tags=["403-bypass", "access-control"],
                ))

    elif category == "cache_poisoning":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make(
                    "cache_poisoning",
                    "cache_poison_probe",
                    item,
                    title="Web Cache Poisoning",
                    severity=item.get("severity", "medium"),
                    evidence=item.get("details", f"Unkeyed header {item.get('unkeyed_header', '')} reflected in response"),
                    finding_type="cache_poisoning",
                    tags=["cache-poisoning", "web-cache"],
                ))

    elif category == "open_redirect":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("open_redirect", "open_redirect", item, title="Open Redirect", tags=["redirect"]))

    elif category == "crlf":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("crlf", "crlf_scan", item, title="CRLF Injection", tags=["crlf"]))

    elif category == "race_condition":
        for item in _as_list(raw_output):
            if isinstance(item, dict):
                findings.append(_make("race_condition", "race_test", item, title="Race Condition", tags=["race-condition"]))

    elif category == "bola":
        if isinstance(raw_output, dict):
            for group_name in ("high_confidence_bola", "graphql_findings", "websocket_findings", "privilege_escalation", "suspicious"):
                for item in raw_output.get(group_name, []):
                    if isinstance(item, dict):
                        findings.append(_make("bola", "bola_engine", item, title="Broken Object Level Authorization", tags=["idor", "bola", group_name]))
        else:
            for item in _as_list(raw_output):
                if isinstance(item, dict):
                    findings.append(_make("bola", "bola_engine", item, title="Broken Object Level Authorization", tags=["idor", "bola"]))

    elif category == "wordpress":
        if isinstance(raw_output, dict):
            for item in raw_output.get("vulnerabilities", []):
                if isinstance(item, dict):
                    findings.append(_make(
                        "wordpress",
                        "wpscan",
                        item,
                        title=item.get("title", "WordPress Vulnerability"),
                        severity=item.get("severity", "medium"),
                        url=raw_output.get("target_url", ""),
                        matched_at=raw_output.get("target_url", ""),
                        finding_type=item.get("type", "wordpress"),
                        tags=["wordpress"],
                    ))

    return findings


def dast_findings_by_category(findings: list[dict[str, Any]], category: str) -> list[dict[str, Any]]:
    return [finding for finding in findings or [] if finding.get("category") == category]


def dast_findings_count(findings: list[dict[str, Any]], category: str) -> int:
    return len(dast_findings_by_category(findings, category))
