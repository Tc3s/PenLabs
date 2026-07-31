#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HTTP replay verification for high false-positive DAST findings."""

from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlparse

import requests

from core.evidence import make_evidence
from core.verification import PASS2_CATEGORIES, annotate_verification


def _status(resp: Any) -> int:
    try:
        return int(getattr(resp, "status_code", 0) or 0)
    except (TypeError, ValueError):
        return 0


def _headers(resp: Any) -> dict:
    return dict(getattr(resp, "headers", {}) or {})


def _body(resp: Any) -> str:
    return str(getattr(resp, "text", "") or "")


def _external_redirect(location: str, original_url: str) -> bool:
    if not location:
        return False
    loc = urlparse(location)
    if not loc.netloc:
        return False
    original = urlparse(original_url)
    return loc.netloc.lower() != original.netloc.lower()


def replay_verify_finding(
    finding: dict[str, Any],
    *,
    session: requests.Session | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 8,
) -> dict[str, Any]:
    item = dict(finding)
    category = str(item.get("category", "")).lower()
    if category not in PASS2_CATEGORIES and category not in {"open_redirect", "crlf", "cors"}:
        return item

    url = str(item.get("url") or item.get("matched_at") or "").strip()
    if not url.startswith(("http://", "https://")):
        return item

    client = session or requests.Session()
    req_headers = dict(headers or {})
    raw = item.get("raw", {}) if isinstance(item.get("raw"), dict) else {}
    evidence = item.get("evidence_detail", {}) if isinstance(item.get("evidence_detail"), dict) else {}
    request_meta = evidence.get("request", {}) if isinstance(evidence.get("request"), dict) else {}

    try:
        if category == "open_redirect":
            resp = client.get(url, headers=req_headers, timeout=timeout, verify=False, allow_redirects=False)
            location = _headers(resp).get("Location", "")
            if _status(resp) in {301, 302, 303, 307, 308} and _external_redirect(location, url):
                item["verification_status"] = "confirmed"
                item["confidence"] = "high"
                item["evidence_detail"] = make_evidence(
                    method="GET", url=url, status_code=_status(resp),
                    response_headers=_headers(resp),
                    validation=f"Replay returned external redirect Location={location}",
                    confidence="high",
                )
            return item

        if category == "cors":
            origin = raw.get("origin") or "https://penlabs-verifier.invalid"
            replay_headers = {**req_headers, "Origin": origin}
            resp = client.get(url, headers=replay_headers, timeout=timeout, verify=False, allow_redirects=False)
            acao = _headers(resp).get("Access-Control-Allow-Origin", "")
            acac = _headers(resp).get("Access-Control-Allow-Credentials", "")
            if acao == "*" or acao == origin or acac.lower() == "true":
                item["verification_status"] = "confirmed"
                item["confidence"] = "high"
            return item

        if category == "bypass_403":
            baseline = client.get(url, headers=req_headers, timeout=timeout, verify=False, allow_redirects=False)
            attack_headers = dict(req_headers)
            method = str(raw.get("bypass_method", ""))
            if method.lower().startswith("header:"):
                header_name = method.split(":", 1)[1].strip()
                attack_headers[header_name] = "127.0.0.1" if "ip" in header_name.lower() or "for" in header_name.lower() else "/"
            attack = client.get(url, headers=attack_headers, timeout=timeout, verify=False, allow_redirects=False)
            if _status(baseline) == 403 and _status(attack) in {200, 201, 204, 301, 302}:
                item["verification_status"] = "confirmed"
                item["confidence"] = "high"
            elif _status(attack) in {200, 201, 204, 301, 302}:
                item["verification_status"] = "suspected"
            return item

        if category == "cache_poisoning":
            header_name = raw.get("unkeyed_header") or "X-Forwarded-Host"
            marker = f"penlabs-{hashlib.md5(url.encode()).hexdigest()[:8]}.invalid"
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}plcb={marker}"
            resp = client.get(test_url, headers={**req_headers, header_name: marker}, timeout=timeout, verify=False, allow_redirects=False)
            reflected = marker in _body(resp)
            cache_status = _headers(resp).get("X-Cache", _headers(resp).get("CF-Cache-Status", raw.get("cache_status", "")))
            if reflected and "hit" in str(cache_status).lower():
                item["verification_status"] = "confirmed"
                item["confidence"] = "high"
            elif reflected:
                item["verification_status"] = "suspected"
            return item

        if category == "crlf":
            resp = client.get(url, headers=req_headers, timeout=timeout, verify=False, allow_redirects=False)
            expected = raw.get("injected_header") or raw.get("header_name")
            if expected and expected in _headers(resp):
                item["verification_status"] = "confirmed"
                item["confidence"] = "high"
            return item

        if category == "ssrf":
            if raw.get("interaction") or raw.get("oob_interaction") or request_meta.get("validation"):
                item["verification_status"] = "confirmed"
                item["confidence"] = "high"
            return item

        if category in {"mass_assignment", "bola", "race_condition", "blind_xss"}:
            if str(item.get("confidence", "")).lower() == "high":
                item["verification_status"] = "confirmed"
            return item
    except Exception as exc:
        item["pass2_error"] = str(exc)

    return item


def replay_verify_findings(
    findings: list[dict[str, Any]],
    *,
    session: requests.Session | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 8,
    max_findings: int = 20,
) -> list[dict[str, Any]]:
    annotated = annotate_verification(findings)
    verified = []
    replayed = 0
    for finding in annotated:
        if finding.get("needs_pass2") and replayed < max_findings:
            finding = replay_verify_finding(finding, session=session, headers=headers, timeout=timeout)
            replayed += 1
        verified.append(finding)
    return annotate_verification(verified)
