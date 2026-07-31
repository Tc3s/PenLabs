#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical non-DAST finding contract for recon/cloud/infra outputs."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class OperationalFinding(BaseModel):
    category: str
    tool: str = ""
    title: str
    severity: str = "info"
    target: str = ""
    matched_at: str = ""
    evidence: str = ""
    confidence: str = ""
    finding_type: str = ""
    tags: list[str] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


def _severity(value: Any, default: str = "info") -> str:
    text = str(value or default).lower()
    return text if text in {"critical", "high", "medium", "low", "info"} else default


def _as_list(value: Any) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return [value]
    if isinstance(value, str) and value.strip():
        return [value.strip()]
    return []


def _make(category: str, title: str, item: dict[str, Any], **kwargs) -> dict[str, Any]:
    finding = OperationalFinding(
        category=category,
        tool=str(kwargs.get("tool", item.get("tool", item.get("source", "")))),
        title=title,
        severity=_severity(kwargs.get("severity", item.get("severity"))),
        target=str(kwargs.get("target", item.get("target", ""))),
        matched_at=str(kwargs.get("matched_at", item.get("matched_at", item.get("url", item.get("host", ""))))),
        evidence=str(kwargs.get("evidence", item.get("evidence", item.get("details", item.get("description", ""))))),
        confidence=str(kwargs.get("confidence", item.get("confidence", ""))).lower(),
        finding_type=str(kwargs.get("finding_type", item.get("type", category))),
        tags=list(kwargs.get("tags", [])),
        raw=item,
    )
    if not finding.matched_at:
        finding.matched_at = finding.target
    return finding.model_dump()


def normalize_asset_findings(asset: dict[str, Any]) -> list[dict[str, Any]]:
    target = str(asset.get("target", ""))
    findings: list[dict[str, Any]] = []

    for subdomain in _as_list(asset.get("subdomains", [])):
        value = subdomain.get("subdomain") if isinstance(subdomain, dict) else str(subdomain)
        if value:
            findings.append(_make(
                "asset", "Discovered Subdomain", {"value": value},
                tool="subdomain", target=target, matched_at=value,
                finding_type="subdomain", tags=["recon", "subdomain"],
            ))

    for url in _as_list(asset.get("web_urls", [])):
        value = url.get("url") if isinstance(url, dict) else str(url)
        if value:
            findings.append(_make(
                "asset", "Live Web URL", {"url": value},
                tool="httpx", target=target, matched_at=value,
                finding_type="web_url", tags=["recon", "http"],
            ))

    for endpoint in _as_list(asset.get("api_endpoints", [])):
        if isinstance(endpoint, dict):
            url = str(endpoint.get("url", endpoint.get("path", "")))
            raw = endpoint
        else:
            url = str(endpoint)
            raw = {"url": url}
        if url:
            findings.append(_make(
                "asset", "API Endpoint", raw,
                tool=str(raw.get("source", "crawler")),
                target=target, matched_at=url,
                finding_type="api_endpoint", tags=["recon", "api"],
            ))

    return findings


def normalize_exposure_findings(asset: dict[str, Any]) -> list[dict[str, Any]]:
    target = str(asset.get("target", ""))
    findings: list[dict[str, Any]] = []

    for secret in _as_list(asset.get("secrets") or asset.get("js_secrets")):
        if not isinstance(secret, dict):
            secret = {"value": str(secret)}
        matched = str(secret.get("source", secret.get("url", target)))
        findings.append(_make(
            "exposure", "Potential Secret Exposure", secret,
            tool=str(secret.get("tool", secret.get("source_tool", "secret_scanner"))),
            target=target, matched_at=matched,
            severity=secret.get("severity", "medium"),
            evidence=secret.get("type", secret.get("value", "secret-like value detected")),
            finding_type="secret", tags=["exposure", "secret"],
        ))

    for item in _as_list(asset.get("nuclei_findings", [])):
        if isinstance(item, dict):
            matched = str(item.get("matched_at", item.get("matched-at", item.get("url", target))))
            title = item.get("template_name") or item.get("name") or item.get("template_id") or "Nuclei Finding"
            findings.append(_make(
                "exposure", str(title), item,
                tool="nuclei", target=target, matched_at=matched,
                severity=item.get("severity", "info"),
                finding_type=item.get("template_id", item.get("type", "nuclei")),
                tags=["exposure", "nuclei"],
            ))

    return findings


def normalize_infra_findings(asset: dict[str, Any]) -> list[dict[str, Any]]:
    target = str(asset.get("target", asset.get("ip", "")))
    findings: list[dict[str, Any]] = []

    for port in _as_list(asset.get("ports") or asset.get("open_ports")):
        if not isinstance(port, dict):
            continue
        port_num = port.get("port")
        svc = port.get("service", "unknown")
        findings.append(_make(
            "infra", f"Open Port {port_num}/{svc}", port,
            tool=str(port.get("source", "nmap")), target=target,
            matched_at=f"{asset.get('ip', target)}:{port_num}",
            severity="info", finding_type="open_port", tags=["infra", "port"],
        ))

    for cve in _as_list(asset.get("nse_cves") or asset.get("cve_candidates")):
        if not isinstance(cve, dict):
            continue
        cve_id = cve.get("cve", cve.get("cve_id", "NSE finding"))
        findings.append(_make(
            "infra", str(cve_id), cve,
            tool=str(cve.get("source", "nmap")), target=target,
            matched_at=cve.get("matched_at", f"{asset.get('ip', target)}:{cve.get('port', '')}"),
            severity=cve.get("severity", "high" if str(cve_id).startswith("CVE-") else "medium"),
            finding_type="cve_candidate", tags=["infra", "cve"],
        ))

    return findings


def normalize_cloud_findings(asset: dict[str, Any]) -> list[dict[str, Any]]:
    target = str(asset.get("target", ""))
    cloud = asset.get("cloud_findings", {})
    findings: list[dict[str, Any]] = []
    if not isinstance(cloud, dict):
        return findings

    def walk(tool: str, value: Any, prefix: str = "") -> None:
        if isinstance(value, list):
            for item in value:
                walk(tool, item, prefix)
            return
        if isinstance(value, dict):
            if any(key in value for key in ("bucket", "resource", "url", "host", "name", "issue", "severity")):
                matched = str(value.get("url", value.get("resource", value.get("bucket", value.get("host", value.get("name", target))))))
                title = value.get("issue") or value.get("type") or f"Cloud Finding ({tool})"
                findings.append(_make(
                    "cloud", str(title), value,
                    tool=tool, target=target, matched_at=matched,
                    severity=value.get("severity", "info"),
                    finding_type=prefix or tool,
                    tags=["cloud", tool],
                ))
                return
            for key, child in value.items():
                if key == "summary":
                    continue
                walk(tool, child, key)
            return
        if isinstance(value, str) and value.strip():
            findings.append(_make(
                "cloud", f"Cloud Resource ({tool})", {"value": value},
                tool=tool, target=target, matched_at=value,
                finding_type=prefix or tool, tags=["cloud", tool],
            ))

    for tool, value in cloud.items():
        walk(str(tool), value)

    return findings
