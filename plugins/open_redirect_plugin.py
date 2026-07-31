"""
PenLabs V1.0 — Open Redirect Scanner Plugin
Phát hiện Open Redirect vulnerabilities với 12 bypass payloads.
Tự động tag cho Bug Chaining (SSO bypass potential).
"""
import os
import json
import logging
import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)

# Tham số phổ biến dẫn đến Open Redirect
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "return_to", "returnTo", "next", "next_url",
    "continue", "continueTo", "rurl", "dest", "destination",
    "redir", "redirect_to", "view", "image_url", "go",
    "checkout_url", "login_url", "logout_return", "callback",
    "forward", "forward_url", "out", "ref", "target",
]

# Payloads bypass (12 kỹ thuật khác nhau)
REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "/\\evil.com",
    "///evil.com",
    "https:evil.com",
    "http://evil.com%00.target.com",  # Null byte
    "http://evil.com%23.target.com",  # Fragment
    "////evil.com",
    "https://evil.com@target.com",   # Basic auth confusion
    "https://target.com.evil.com",   # Subdomain confusion
    "//evil.com/%2f%2f",
    "/%09/evil.com",                 # Tab character
]


class OpenRedirectPlugin(BasePlugin):
    def name(self) -> str:
        return "OpenRedirect"

    def description(self) -> str:
        return "Open Redirect Scanner — Phát hiện lỗi chuyển hướng mở với 12 bypass payloads, tag SSO chain potential."

    def check_installed(self) -> bool:
        return True  # Built-in Python

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, timeout: int = 10,
            max_urls: int = 50, proxy_mode: str = "fuzz") -> list:
        """
        Quét Open Redirect trên danh sách URLs.
        Returns list of redirect findings.
        """
        os.makedirs(out_dir, exist_ok=True)
        findings = []
        tested = 0

        #  Use StealthNet session for unified fingerprinting
        from plugins.stealth_net_plugin import StealthNetPlugin
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session

        TRACKING_DOMAINS = frozenset({
            'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
            'google.com', 'facebook.com', 'facebook.net', 'doubleclick.net',
            'yandex.ru', 'bing.com', 'clarity.ms', 'segment.io', 'mixpanel.com',
        })

        for url in urls[:max_urls]:
            parsed = urlparse(url)
            netloc_lower = parsed.netloc.lower().split(':')[0]
            if any(netloc_lower == td or netloc_lower.endswith('.' + td) for td in TRACKING_DOMAINS):
                continue

            existing_params = parse_qs(parsed.query)

            # Strategy 1: Test existing redirect-like params
            for param_name, param_values in existing_params.items():
                if any(rp in param_name.lower() for rp in ["url", "redirect", "return", "next", "dest", "continue", "callback", "forward", "go", "redir"]):
                    for payload in REDIRECT_PAYLOADS:
                        # V1.0-FIX: Rebuild URL with payload injected into the redirect param
                        from urllib.parse import urlencode, urlunparse, parse_qs as _pqs
                        _p = urlparse(url)
                        _params = _pqs(_p.query, keep_blank_values=True)
                        _params[param_name] = [payload]
                        _new_query = urlencode(_params, doseq=True)
                        test_url = urlunparse((_p.scheme, _p.netloc, _p.path, _p.params, _new_query, _p.fragment))
                        finding = self._test_redirect(session, test_url, param_name, payload, headers, timeout)
                        if finding:
                            findings.append(finding)
                            tested += 1
                            break  # Một payload thành công là đủ

            # Strategy 2: Inject common redirect params vào URL không có
            if not existing_params:
                base = url.rstrip("/")
                for param in REDIRECT_PARAMS[:15]:  # Top 15
                    for payload in REDIRECT_PAYLOADS[:5]:  # Top 5
                        test_url = f"{base}?{param}={payload}"
                        finding = self._test_redirect(session, test_url, param, payload, headers, timeout)
                        tested += 1
                        if finding:
                            findings.append(finding)
                            break  # Next param

        # Enrich findings with chain potential
        for f in findings:
            f["chain_potential"] = self._assess_chain(f, urls)
            f.setdefault("finding_type", "open_redirect")
            f.setdefault("matched_at", f.get("url", ""))
            f.setdefault("confidence", "high")
            f["severity"] = str(f.get("severity", "medium")).lower()
            f.setdefault("source", "open_redirect")

        # Save
        out_file = os.path.join(out_dir, "open_redirect_findings.json")
        with open(out_file, "w") as f_out:
            json.dump(findings, f_out, indent=2, default=str)

        logger.info(f"[OpenRedirect] Tested {tested} payloads, found {len(findings)} redirects.")
        return findings

    def _test_redirect(self, session, url: str, param: str, payload: str,
                       headers: dict = None, timeout: int = 10) -> dict:
        """Test một URL + param + payload, trả về finding hoặc None."""
        try:
            resp = session.get(
                url, headers=headers or {},
                timeout=timeout,
                allow_redirects=False
            )

            # Check 1: Location header redirect
            location = resp.headers.get("Location", "")
            if location and "evil.com" in location:
                # ── V1.0-FIX: False Positive Filters ──
                # FP-1: HTTP→HTTPS protocol upgrade to same host
                # Server redirects http://target.com/page?x=evil.com
                #              → https://target.com/page?x=evil.com
                # This is NOT an open redirect — just HTTPS enforcement
                try:
                    original_parsed = urlparse(url)
                    redirect_parsed = urlparse(location)

                    # Same-host redirect (protocol upgrade or path normalization)
                    if redirect_parsed.netloc and redirect_parsed.netloc == original_parsed.netloc:
                        return None  # Not a real redirect — same host

                    # FP-2: Redirect to a subdomain of the original host
                    # e.g., target.com → www.target.com or login.target.com
                    orig_domain = original_parsed.netloc.split(":")[ 0]  # Strip port
                    redir_domain = redirect_parsed.netloc.split(":")[0]
                    if redir_domain.endswith(f".{orig_domain}") or orig_domain.endswith(f".{redir_domain}"):
                        return None  # Subdomain redirect, not open redirect

                    # FP-3: The "evil.com" string appears only in query params of
                    # the Location header (server echoed the param, not redirecting TO it)
                    if redirect_parsed.netloc and "evil.com" not in redirect_parsed.netloc:
                        # evil.com is in the path/query but not the host — could be echo
                        # Only flag if evil.com IS the redirect target host
                        if "evil.com" not in redirect_parsed.netloc.lower():
                            return None
                except Exception:
                    pass  # If parsing fails, still report the finding
                # ── End FP Filters ──

                finding = {
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "redirect_to": location,
                    "type": "header_redirect",
                    "severity": "medium",
                }
                return attach_evidence(finding, make_evidence(
                    method="GET",
                    url=url,
                    param=param,
                    payload=payload,
                    status_code=resp.status_code,
                    request_headers=headers or {},
                    response_headers=dict(resp.headers),
                    validation=f"Location header redirects to attacker-controlled host: {location}",
                    confidence="high",
                ))

            # Check 2: Meta refresh redirect
            if "evil.com" in resp.text.lower() and ("meta" in resp.text.lower() and "refresh" in resp.text.lower()):
                finding = {
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "redirect_to": "meta-refresh",
                    "type": "meta_redirect",
                    "severity": "medium",
                }
                return attach_evidence(finding, make_evidence(
                    method="GET",
                    url=url,
                    param=param,
                    payload=payload,
                    status_code=resp.status_code,
                    request_headers=headers or {},
                    response_headers=dict(resp.headers),
                    response_snippet=resp.text,
                    validation="Response body contains meta refresh redirect to attacker-controlled host",
                    confidence="medium",
                ))

            # Check 3: JavaScript redirect
            if "evil.com" in resp.text and any(
                js_redir in resp.text.lower() for js_redir in
                ["window.location", "document.location", "location.href", "location.replace"]
            ):
                finding = {
                    "url": url,
                    "param": param,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "redirect_to": "javascript_redirect",
                    "type": "js_redirect",
                    "severity": "medium",
                }
                return attach_evidence(finding, make_evidence(
                    method="GET",
                    url=url,
                    param=param,
                    payload=payload,
                    status_code=resp.status_code,
                    request_headers=headers or {},
                    response_headers=dict(resp.headers),
                    response_snippet=resp.text,
                    validation="Response body contains JavaScript redirect sink with attacker-controlled host",
                    confidence="medium",
                ))

        except Exception:
            pass
        return None

    def _assess_chain(self, finding: dict, all_urls: list) -> str:
        """Đánh giá khả năng chain với OAuth/SSO."""
        url = finding.get("url", "").lower()
        
        # Check if near OAuth/SSO endpoints
        oauth_indicators = ["oauth", "authorize", "callback", "sso", "login", "auth", "token"]
        for indicator in oauth_indicators:
            if indicator in url:
                return "HIGH — Near OAuth endpoint, possible SSO token theft via redirect_uri manipulation"
        
        # Check URL pattern
        if any(p in url for p in ["redirect_uri", "return_url", "callback"]):
            return "HIGH — redirect_uri parameter found, OAuth chain likely"
        
        return "LOW — Standard open redirect, useful for phishing"
