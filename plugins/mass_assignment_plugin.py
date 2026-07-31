#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-2 FIX] Mass Assignment Plugin — Phát hiện Mass Assignment vulnerabilities.

REWRITE: Thay thế heuristic cũ (`"admin" in resp.text`) bằng 2-way response
diff giống BOLA pattern. So sánh:
  - Response User A baseline (no privilege fields injected)
  - Response User A sau khi inject privilege fields (is_admin=true, role=admin, ...)

Nếu 2 responses KHÁC NHAU đáng kể → có thể mass assignment hoạt động.

Why this rewrite:
- Old heuristic: "admin" in resp.text.lower() → false positive với mọi page có chữ "admin"
  (footer, nav menu, links to /admin).
- New approach: 2-way diff. Baseline vs modified. Detect actual privilege escalation.

Usage:
    from plugins.mass_assignment_plugin import MassAssignmentPlugin
    ma = MassAssignmentPlugin(auth_token="Bearer xxx")
    findings = ma.check_endpoints(["https://api.example.com/users/123"],
                                   method="PUT")
"""

import os
import json
import logging
import difflib
from typing import List, Dict, Any, Optional
import requests as _requests
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)


# Default privilege fields to inject (mass assignment payloads)
DEFAULT_PRIVILEGE_PAYLOADS = [
    {"is_admin": True, "role": "admin"},
    {"role": "admin", "admin": True},
    {"is_staff": True, "permissions": ["read", "write", "delete"]},
    {"verified": True, "email_verified": True},
    {"balance": 999999, "credits": 9999},  # Financial override
    {"status": "active", "banned": False},
]

# Fields that indicate privilege escalation in response (heuristic)
PRIVILEGE_INDICATORS = [
    "is_admin", "admin", "role", "is_staff", "permissions",
    "verified", "email_verified", "balance", "credits",
    "status", "banned", "privilege", "access_level", "tier",
]


class MassAssignmentPlugin(BasePlugin):
    """
    Plugin phát hiện lỗi Mass Assignment.

    Method: 2-way diff.
    1. Send baseline request với User A auth (no privilege fields)
    2. Send same request với same auth + privilege fields injected
    3. Compare responses:
       - If status changed OR content changed significantly → likely vulnerable
       - If response contains privilege field values that weren't in baseline → HIGH confidence
    """

    # Difference threshold for content change (ratio 0-1)
    DIFF_THRESHOLD = 0.15
    # Status codes that indicate successful modification
    SUCCESS_CODES = {200, 201}

    def __init__(self, auth_token: Optional[str] = None):
        """
        Args:
            auth_token: Bearer token (vd: "Bearer xxx") cho User A
        """
        self._auth_token = auth_token

    def _with_evidence_detail(
        self,
        finding: Dict[str, Any],
        *,
        url: str,
        method: str,
        payload: Dict,
        baseline: _requests.Response,
        modified: _requests.Response,
        validation: str,
    ) -> Dict[str, Any]:
        confidence = str(finding.get("confidence", "medium")).lower()
        return attach_evidence(
            finding,
            make_evidence(
                method=method,
                url=url,
                payload=payload,
                status_code=getattr(modified, "status_code", None),
                response_headers=dict(getattr(modified, "headers", {}) or {}),
                response_snippet=getattr(modified, "text", "") or "",
                validation=(
                    f"{validation} Baseline status {getattr(baseline, 'status_code', None)}, "
                    f"modified status {getattr(modified, 'status_code', None)}."
                ),
                confidence=confidence,
            ),
        )

    def name(self) -> str:
        return "MassAssignment"

    def description(self) -> str:
        return "Detect Mass Assignment vulnerabilities via 2-way response diff (User A baseline vs User A + privilege fields)."

    def check_installed(self) -> bool:
        return True  # Pure Python, no external deps

    def run(self, *args, **kwargs) -> List[Dict[str, Any]]:
        """
        Check endpoints cho Mass Assignment.

        Args:
            urls: List of endpoint URLs
            auth_token: Bearer token (override)
            method: HTTP method (PUT, PATCH, POST). Default: POST
            payloads: Custom privilege payloads (optional)
            headers: Extra headers (optional)
            timeout: Request timeout (default 15)

        Returns:
            List of findings: [{"url": ..., "method": ..., "evidence": ..., "severity": ...}]
        """
        urls = kwargs.get("urls") or (list(args) if args else [])
        auth_token = kwargs.get("auth_token", self._auth_token)
        method = kwargs.get("method", "POST").upper()
        payloads = kwargs.get("payloads", DEFAULT_PRIVILEGE_PAYLOADS)
        headers = kwargs.get("headers", {})
        timeout = kwargs.get("timeout", 15)

        if not urls:
            return []

        if method not in ("POST", "PUT", "PATCH"):
            logger.warning(f"[MassAssignment] Method {method} not in (POST, PUT, PATCH)")
            return []

        if auth_token:
            headers["Authorization"] = auth_token

        return self.check_endpoints(
            urls=urls,
            method=method,
            payloads=payloads,
            headers=headers,
            timeout=timeout,
        )

    def check_endpoints(
        self,
        urls: List[str],
        method: str = "POST",
        payloads: Optional[List[Dict]] = None,
        headers: Optional[Dict] = None,
        timeout: int = 15,
    ) -> List[Dict[str, Any]]:
        """
        Run 2-way diff check across multiple URLs.

        Args:
            urls: List of endpoint URLs to test
            method: HTTP method (POST, PUT, PATCH)
            payloads: List of dicts to inject
            headers: Request headers (auth tokens etc.)
            timeout: Per-request timeout

        Returns:
            List of findings, sorted by confidence (HIGH first)
        """
        if not urls:
            return []

        payloads = payloads or DEFAULT_PRIVILEGE_PAYLOADS
        headers = headers or {}
        findings: List[Dict[str, Any]] = []

        for url in urls:
            url = url.strip()
            if not url:
                continue
            try:
                url_findings = self._check_single_endpoint(
                    url, method, payloads, headers, timeout
                )
                findings.extend(url_findings)
            except Exception as e:
                logger.debug(f"[MassAssignment] Error testing {url}: {e}")
                continue

        # Sort by confidence (HIGH first, then MEDIUM, LOW)
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        findings.sort(key=lambda f: confidence_order.get(f.get("confidence", "LOW"), 3))

        return findings

    def _check_single_endpoint(
        self,
        url: str,
        method: str,
        payloads: List[Dict],
        headers: Dict,
        timeout: int,
    ) -> List[Dict[str, Any]]:
        """
        Test 1 endpoint với 2-way diff approach.

        Returns:
            List of findings (0 or more)
        """
        findings = []

        # Step 1: Send baseline request (no privilege fields, minimal body)
        baseline_body = self._get_minimal_body(method)
        try:
            baseline_resp = self._send_request(
                url, method, baseline_body, headers, timeout
            )
        except Exception as e:
            logger.debug(f"[MassAssignment] Baseline failed for {url}: {e}")
            return []

        # Step 2: Try each payload, compare với baseline
        for payload in payloads:
            try:
                modified_resp = self._send_request(
                    url, method, payload, headers, timeout
                )
            except Exception as e:
                logger.debug(f"[MassAssignment] Modified failed for {url}: {e}")
                continue

            if modified_resp is None:
                continue

            # Detect if vulnerable
            finding = self._detect_vulnerability(
                url=url,
                method=method,
                payload=payload,
                baseline=baseline_resp,
                modified=modified_resp,
            )
            if finding:
                findings.append(finding)

        return findings

    def _detect_vulnerability(
        self,
        url: str,
        method: str,
        payload: Dict,
        baseline: _requests.Response,
        modified: _requests.Response,
    ) -> Optional[Dict[str, Any]]:
        """
        Compare baseline vs modified responses.

        Detection criteria (in order of confidence):
        1. HIGH: Status changed from error to success (e.g. 403 → 200)
        2. HIGH: Response now contains privilege field values from payload
        3. MEDIUM: Response content differs significantly (diff > threshold)
        4. LOW: Status changed but ambiguous
        """
        # Criterion 1: Status changed to success
        baseline_status = baseline.status_code
        modified_status = modified.status_code
        baseline_was_error = baseline_status >= 400
        modified_now_success = modified_status in self.SUCCESS_CODES

        if baseline_was_error and modified_now_success:
            finding = {
                "url": url,
                "method": method,
                "vulnerability": "Mass Assignment",
                "severity": "high",
                "confidence": "HIGH",
                "payload": payload,
                "evidence": (
                    f"Status changed: {baseline_status} → {modified_status}. "
                    f"Baseline was error, modified request succeeded — "
                    f"server accepted injected privilege fields."
                ),
                "baseline_status": baseline_status,
                "modified_status": modified_status,
            }
            return self._with_evidence_detail(
                finding,
                url=url,
                method=method,
                payload=payload,
                baseline=baseline,
                modified=modified,
                validation="Injected privilege-field payload changed request from error to successful response.",
            )

        # Criterion 2: Response contains privilege field values from payload
        privilege_value_match = self._check_privilege_field_in_response(
            payload, modified
        )
        if privilege_value_match:
            finding = {
                "url": url,
                "method": method,
                "vulnerability": "Mass Assignment",
                "severity": "high",
                "confidence": "HIGH",
                "payload": payload,
                "evidence": (
                    f"Response contains injected privilege fields: {privilege_value_match}. "
                    f"Server echoed back mass-assigned values."
                ),
                "matched_fields": privilege_value_match,
                "baseline_status": baseline_status,
                "modified_status": modified_status,
            }
            return self._with_evidence_detail(
                finding,
                url=url,
                method=method,
                payload=payload,
                baseline=baseline,
                modified=modified,
                validation=f"Modified response reflected injected privilege fields: {privilege_value_match}.",
            )

        # Criterion 3: Content differs significantly (both same status)
        if baseline_status == modified_status and baseline_status in self.SUCCESS_CODES:
            diff_ratio = self._compute_diff_ratio(
                baseline.text or "", modified.text or ""
            )
            if diff_ratio > self.DIFF_THRESHOLD:
                finding = {
                    "url": url,
                    "method": method,
                    "vulnerability": "Mass Assignment",
                    "severity": "medium",
                    "confidence": "MEDIUM",
                    "payload": payload,
                    "evidence": (
                        f"Response content differs significantly "
                        f"(diff ratio: {diff_ratio:.2f}, threshold: {self.DIFF_THRESHOLD}). "
                        f"Privilege fields likely affected response."
                    ),
                    "diff_ratio": round(diff_ratio, 3),
                    "baseline_status": baseline_status,
                    "modified_status": modified_status,
                }
                return self._with_evidence_detail(
                    finding,
                    url=url,
                    method=method,
                    payload=payload,
                    baseline=baseline,
                    modified=modified,
                    validation=f"Modified body differed from baseline with diff ratio {diff_ratio:.2f}.",
                )

        # Criterion 4: Status changed but ambiguous
        if baseline_status != modified_status:
            finding = {
                "url": url,
                "method": method,
                "vulnerability": "Mass Assignment (Possible)",
                "severity": "low",
                "confidence": "LOW",
                "payload": payload,
                "evidence": (
                    f"Status changed: {baseline_status} → {modified_status}. "
                    f"Could be normal validation behavior — manual review needed."
                ),
                "baseline_status": baseline_status,
                "modified_status": modified_status,
            }
            return self._with_evidence_detail(
                finding,
                url=url,
                method=method,
                payload=payload,
                baseline=baseline,
                modified=modified,
                validation="Modified request changed HTTP status; manual review required because validation behavior can cause this.",
            )

        return None

    def _check_privilege_field_in_response(
        self, payload: Dict, response: _requests.Response
    ) -> Dict[str, Any]:
        """
        Check if response contains privilege field values from payload.

        Returns:
            dict of {field: value} if matched, empty dict otherwise.
        """
        matched = {}

        # Try to parse response as JSON
        try:
            resp_json = response.json()
        except (ValueError, json.JSONDecodeError):
            resp_json = None

        for key, value in payload.items():
            if key not in PRIVILEGE_INDICATORS:
                continue

            # Check JSON response
            if isinstance(resp_json, dict):
                if key in resp_json and resp_json[key] == value:
                    matched[key] = value
            elif isinstance(resp_json, list):
                for item in resp_json:
                    if isinstance(item, dict) and item.get(key) == value:
                        matched[key] = value
                        break

            # Fallback: check raw text (value as string)
            if not matched and response.text:
                value_str = str(value).lower()
                if value_str in response.text.lower():
                    matched[key] = value

        return matched

    def _compute_diff_ratio(self, text1: str, text2: str) -> float:
        """
        Compute ratio of difference between 2 strings (0 = identical, 1 = completely different).

        Uses difflib.SequenceMatcher.
        """
        if text1 == text2:
            return 0.0
        if not text1 or not text2:
            return 1.0
        matcher = difflib.SequenceMatcher(None, text1, text2)
        return 1.0 - matcher.ratio()

    def _send_request(
        self,
        url: str,
        method: str,
        body: Any,
        headers: Dict,
        timeout: int,
    ) -> Optional[_requests.Response]:
        """Send HTTP request with given method + body."""
        request_headers = headers.copy()
        if isinstance(body, dict) and body:
            request_headers.setdefault("Content-Type", "application/json")

        try:
            if method == "POST":
                resp = _requests.post(url, json=body, headers=request_headers,
                                      timeout=timeout, verify=False, allow_redirects=False)
            elif method == "PUT":
                resp = _requests.put(url, json=body, headers=request_headers,
                                     timeout=timeout, verify=False, allow_redirects=False)
            elif method == "PATCH":
                resp = _requests.patch(url, json=body, headers=request_headers,
                                       timeout=timeout, verify=False, allow_redirects=False)
            else:
                return None
            return resp
        except _requests.exceptions.RequestException as e:
            logger.debug(f"[MassAssignment] Request error: {e}")
            return None

    def _get_minimal_body(self, method: str) -> Dict:
        """
        Get minimal body for baseline request.

        For POST/PUT/PATCH, send empty dict or single non-privilege field.
        """
        # Empty body for baseline — server should still respond normally
        return {}
