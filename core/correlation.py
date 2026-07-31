#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple correlation engine for attack-path style report hints."""

from __future__ import annotations

from typing import Any


def correlate_attack_paths(result: dict[str, Any]) -> list[dict[str, Any]]:
    findings = [f for f in result.get("dast_findings", []) if isinstance(f, dict)]
    categories = {str(f.get("category", "")).lower() for f in findings}
    by_category = {
        category: [f for f in findings if str(f.get("category", "")).lower() == category]
        for category in categories
    }
    urls = set(result.get("web_urls", []) or [])
    urls.update(ep.get("url", "") for ep in result.get("api_endpoints", []) or [] if isinstance(ep, dict))
    oauth_urls = [url for url in urls if any(token in url.lower() for token in ("oauth", "authorize", "callback", "sso", "token"))]

    chains: list[dict[str, Any]] = []
    def add(title: str, severity: str, base_score: int, evidence: list[Any], manual_next: str, categories_used: list[str]) -> None:
        verified_bonus = sum(
            10 for category in categories_used
            for finding in by_category.get(category, [])
            if finding.get("verification_status") == "confirmed"
        )
        score = min(100, base_score + verified_bonus + min(len(evidence), 5) * 2)
        chains.append({
            "title": title,
            "severity": severity,
            "score": score,
            "categories": categories_used,
            "evidence": evidence[:5],
            "manual_next": manual_next,
        })

    if "open_redirect" in categories and oauth_urls:
        add("Open Redirect + OAuth/SSO", "high", 70, oauth_urls,
            "Validate redirect_uri/state handling with user-controlled redirect targets.",
            ["open_redirect"])
    if {"cors", "xss"} <= categories:
        add("CORS Misconfiguration + XSS", "high", 75, [],
            "Check whether XSS can read authenticated API data cross-origin.",
            ["cors", "xss"])
    if "ssrf" in categories:
        cloud_bonus = 10 if result.get("cloud_infra_depth", {}).get("needs_manual_cloud_review") else 0
        add("SSRF + Cloud Metadata", "critical", 80 + cloud_bonus, [],
            "Manually verify metadata endpoints only within RoE-approved boundaries.",
            ["ssrf"])
    if {"crlf", "cache_poisoning"} <= categories:
        add("CRLF + Cache Poisoning", "high", 70, [],
            "Confirm cache key behavior and response splitting impact with a non-destructive cache buster.",
            ["crlf", "cache_poisoning"])
    if "blind_xss" in categories:
        add("Blind XSS + Privileged Workflow", "medium", 55, [],
            "Wait for OOB callbacks and map callback source to admin/reviewer workflows.",
            ["blind_xss"])
    return sorted(chains, key=lambda chain: chain.get("score", 0), reverse=True)
