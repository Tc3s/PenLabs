#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verification and triage buckets for normalized DAST findings."""

from __future__ import annotations

from typing import Any


CONFIRMED_CATEGORIES = {"xss", "sqli", "open_redirect", "crlf", "cors", "graphql", "wordpress"}
PASS2_CATEGORIES = {"ssrf", "cache_poisoning", "bypass_403", "race_condition", "blind_xss", "bola", "mass_assignment"}
NOISE_STATUSES = {400, 404, 429, 502, 503}


def _confidence(finding: dict[str, Any]) -> str:
    return str(finding.get("confidence") or finding.get("raw", {}).get("confidence") or "").lower()


def verification_status(finding: dict[str, Any]) -> str:
    category = str(finding.get("category", "")).lower()
    raw = finding.get("raw", {}) if isinstance(finding.get("raw"), dict) else {}
    status = raw.get("status", raw.get("status_code"))
    try:
        status_int = int(status)
    except (TypeError, ValueError):
        status_int = None

    if status_int in NOISE_STATUSES and category not in {"bypass_403"}:
        return "noise"

    conf = _confidence(finding)
    evidence = str(finding.get("evidence") or raw.get("evidence") or raw.get("details") or "")
    severity = str(finding.get("severity", "")).lower()

    if conf == "high" or category in CONFIRMED_CATEGORIES and evidence:
        return "confirmed"
    if category == "cache_poisoning" and "hit" in str(raw.get("cache_status", "")).lower():
        return "confirmed"
    if category == "bypass_403" and status_int in {200, 201, 204, 301, 302}:
        return "suspected"
    if category in PASS2_CATEGORIES:
        return "manual_review" if category in {"blind_xss", "bola"} else "suspected"
    if severity in {"critical", "high"} and evidence:
        return "suspected"
    return "manual_review"


def annotate_verification(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    annotated = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        item["verification_status"] = item.get("verification_status") or verification_status(item)
        item["needs_pass2"] = item["verification_status"] in {"suspected", "manual_review"} and str(item.get("category", "")).lower() in PASS2_CATEGORIES
        annotated.append(item)
    return annotated


def bucket_findings(findings: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    buckets = {"confirmed": [], "suspected": [], "manual_review": [], "noise": []}
    for finding in annotate_verification(findings):
        buckets.setdefault(finding["verification_status"], []).append(finding)
    return buckets


def bucket_summary(buckets: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    return {name: len(items or []) for name, items in buckets.items()}
