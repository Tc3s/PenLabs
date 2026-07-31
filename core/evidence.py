#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shared evidence helpers for plugin findings."""

from __future__ import annotations

from typing import Any


SENSITIVE_HEADER_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
}


def _truncate(value: Any, limit: int = 600) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit].rstrip() + "..."


def redact_headers(headers: dict | None) -> dict:
    redacted = {}
    for key, value in (headers or {}).items():
        if str(key).lower() in SENSITIVE_HEADER_NAMES:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = _truncate(value, 240)
    return redacted


def make_evidence(
    *,
    method: str = "GET",
    url: str = "",
    param: str = "",
    payload: str = "",
    status_code: int | str = "",
    request_headers: dict | None = None,
    response_headers: dict | None = None,
    response_snippet: str = "",
    validation: str = "",
    raw_artifact: str = "",
    confidence: str = "medium",
) -> dict[str, Any]:
    return {
        "request": {
            "method": str(method or "GET").upper(),
            "url": url,
            "param": param,
            "payload": _truncate(payload, 500),
            "headers": redact_headers(request_headers),
        },
        "response": {
            "status_code": status_code,
            "headers": redact_headers(response_headers),
            "snippet": _truncate(response_snippet, 800),
        },
        "validation": validation,
        "confidence": str(confidence or "medium").lower(),
        "raw_artifact": raw_artifact,
    }


def summarize_evidence(evidence: dict[str, Any]) -> str:
    request = evidence.get("request", {})
    response = evidence.get("response", {})
    validation = evidence.get("validation", "")
    parts = [
        f"{request.get('method', 'GET')} {request.get('url', '')}".strip(),
        f"status={response.get('status_code', '')}",
    ]
    if request.get("param"):
        parts.append(f"param={request.get('param')}")
    if validation:
        parts.append(str(validation))
    return " | ".join(p for p in parts if p and not p.endswith("="))


def attach_evidence(finding: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any]:
    finding["evidence_detail"] = evidence
    finding["evidence"] = finding.get("evidence") or summarize_evidence(evidence)
    if evidence.get("confidence"):
        finding["confidence"] = evidence["confidence"]
    request = evidence.get("request", {})
    if request.get("method"):
        finding.setdefault("method", request["method"])
    return finding
