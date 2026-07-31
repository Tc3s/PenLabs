#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Stable dry-run snapshot for route/report regression checks."""

from __future__ import annotations

from typing import Any


def build_dry_run_snapshot(result: dict[str, Any], mode: str) -> dict[str, Any]:
    endpoints = result.get("endpoint_store") or result.get("api_endpoints") or []
    dast_findings = [f for f in result.get("dast_findings", []) or [] if isinstance(f, dict)]
    categories: dict[str, int] = {}
    for finding in dast_findings:
        category = str(finding.get("category", "unknown")).lower()
        categories[category] = categories.get(category, 0) + 1

    return {
        "mode": mode,
        "counts": {
            "web_urls": len(result.get("web_urls", []) or []),
            "api_endpoints": len(result.get("api_endpoints", []) or []),
            "endpoint_store": len(endpoints),
            "dast_findings": len(dast_findings),
            "nuclei_findings": len(result.get("nuclei_findings", []) or []),
            "attack_chains": len(result.get("attack_chains", []) or []),
        },
        "dast_categories": dict(sorted(categories.items())),
        "verification_summary": dict(result.get("verification_summary", {}) or {}),
        "strategy_tools": sorted((result.get("strategy_profiles", {}) or {}).keys()),
    }
