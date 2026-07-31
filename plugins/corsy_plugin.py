import os
import json
import logging
import requests
from core.base_plugin import BasePlugin
from config import Config
from core.evidence import attach_evidence, make_evidence


class CorsyPlugin(BasePlugin):
    """Corsy — CORS misconfiguration scanner (inline Python logic)."""

    # Danh sách Origin test cases cho CORS check
    CORS_TEST_ORIGINS = [
        "{target}",                           # Reflected origin
        "null",                                # Null origin
        "https://evil.com",                    # Arbitrary origin
        "https://{domain}.evil.com",           # Subdomain of attacker
        "https://{domain}.attacker.com",       # Prefix match bypass
        "https://attacker{domain}",            # Suffix match bypass
        "http://{domain}",                     # HTTP downgrade
        "https://{domain}%60.evil.com",        # Backtick bypass
        "https://{domain}_.evil.com",          # Underscore bypass
    ]

    def name(self) -> str:
        return "Corsy"

    def description(self) -> str:
        return "Corsy — Phát hiện CORS misconfiguration (null origin, wildcard, reflection)."

    def check_installed(self) -> bool:
        # Plugin sử dụng logic nội tuyến Python — không cần external binary
        return True

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, timeout: int = 10,
            max_urls: int = 30, waf_detected: bool = False,
            proxy_mode: str = "exploit") -> list:
        """
        Kiểm tra CORS misconfiguration trên danh sách URL.

        Args:
            urls: Danh sách URL cần kiểm tra
            headers: Custom headers
            timeout: Timeout cho mỗi request (giây)
            max_urls: Giới hạn số URL
            waf_detected: Cờ báo hiệu có WAF để kích hoạt mode Evasion

        Returns:
            list: [{"url": "...", "type": "...", "severity": "...", "details": "..."}]
        """
        os.makedirs(out_dir, exist_ok=True)
        findings = []
        
        # WAF Evasion Headers (IP Spoofing)
        bypass_headers = {}
        if waf_detected:
            import random
            fake_ip = f"103.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            bypass_headers = {
                "X-Forwarded-For": fake_ip,
                "X-Real-IP": fake_ip,
                "X-Forwarded-Host": "localhost",
                "X-Client-IP": fake_ip,
                "X-Remote-IP": fake_ip,
                "X-Remote-Addr": fake_ip,
                "True-Client-IP": fake_ip,
                "Client-IP": fake_ip
            }
            logging.info(f"[Corsy] WAF Detected! Activating IP Spoofing ({fake_ip}) and throttling...")

        #  Use StealthNet session for unified fingerprinting
        from plugins.stealth_net_plugin import StealthNetPlugin
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session

        for url in urls[:max_urls]:
            url = url.strip()
            if not url or not url.startswith("http"):
                continue

            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc

                for test_origin_template in self.CORS_TEST_ORIGINS:
                    test_origin = test_origin_template.replace("{target}", url)
                    test_origin = test_origin.replace("{domain}", domain)

                    try:
                        req_headers = {"Origin": test_origin}
                        if headers:
                            req_headers.update(headers)
                        
                        if waf_detected:
                            req_headers.update(bypass_headers)
                            import time
                            import random
                            # Jittered Throttling
                            time.sleep(1.5 * random.uniform(0.8, 1.2))
                            
                        if headers:
                            req_headers.update(headers)

                        resp = session.get(url, headers=req_headers, timeout=timeout,
                                            allow_redirects=False)

                        acao = resp.headers.get("Access-Control-Allow-Origin", "")
                        acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

                        if not acao:
                            continue

                        # Wildcard + Credentials = Critical
                        if acao == "*" and acac == "true":
                            finding = {
                                "url": url,
                                "type": "wildcard_with_credentials",
                                "severity": "critical",
                                "details": f"ACAO: * + ACAC: true — Data theft possible",
                                "test_origin": test_origin,
                                #  Explicit evidence for report surfacing
                                "evidence": f"Access-Control-Allow-Origin: {acao}\n"
                                            f"Access-Control-Allow-Credentials: {acac}",
                                "remediation": "Set ACAO to a specific trusted origin. "
                                               "Never combine wildcard (*) with Access-Control-Allow-Credentials: true.",
                            }
                            findings.append(attach_evidence(finding, make_evidence(
                                method="GET",
                                url=url,
                                status_code=resp.status_code,
                                request_headers=req_headers,
                                response_headers=dict(resp.headers),
                                validation="Wildcard ACAO is combined with credentials",
                                confidence="high",
                            )))
                            break

                        # Reflected Origin + Credentials = High
                        if acao == test_origin and acac == "true":
                            severity = "critical" if test_origin in ["null", "https://evil.com"] else "high"
                            finding = {
                                "url": url,
                                "type": "reflected_origin_with_credentials",
                                "severity": severity,
                                "details": f"Origin '{test_origin}' reflected in ACAO with credentials",
                                "test_origin": test_origin,
                                "evidence": f"Request Origin: {test_origin}\n"
                                            f"Access-Control-Allow-Origin: {acao}\n"
                                            f"Access-Control-Allow-Credentials: {acac}",
                                "remediation": "Validate Origin against a strict whitelist. "
                                               "Do not reflect arbitrary Origins in ACAO when ACAC is true.",
                            }
                            findings.append(attach_evidence(finding, make_evidence(
                                method="GET",
                                url=url,
                                status_code=resp.status_code,
                                request_headers=req_headers,
                                response_headers=dict(resp.headers),
                                validation=f"Origin {test_origin} reflected with credentials enabled",
                                confidence="high",
                            )))
                            break

                        # Reflected Origin without Credentials = Medium
                        if acao == test_origin and acac != "true":
                            finding = {
                                "url": url,
                                "type": "reflected_origin_no_credentials",
                                "severity": "medium",
                                "details": f"Origin '{test_origin}' reflected in ACAO (no credentials)",
                                "test_origin": test_origin,
                                "evidence": f"Request Origin: {test_origin}\n"
                                            f"Access-Control-Allow-Origin: {acao}\n"
                                            f"Access-Control-Allow-Credentials: (not set or false)",
                                "remediation": "Restrict ACAO to a whitelist of trusted origins.",
                            }
                            findings.append(attach_evidence(finding, make_evidence(
                                method="GET",
                                url=url,
                                status_code=resp.status_code,
                                request_headers=req_headers,
                                response_headers=dict(resp.headers),
                                validation=f"Origin {test_origin} reflected without credentials",
                                confidence="medium",
                            )))
                            break

                        # Null origin accepted = High
                        if test_origin == "null" and acao == "null":
                            finding = {
                                "url": url,
                                "type": "null_origin_accepted",
                                "severity": "high",
                                "details": "Null origin accepted — sandbox iframe exploitation possible",
                                "test_origin": "null",
                                "evidence": f"Request Origin: null\n"
                                            f"Access-Control-Allow-Origin: null",
                                "remediation": "Reject null Origin. It can be spoofed via sandboxed iframes.",
                            }
                            findings.append(attach_evidence(finding, make_evidence(
                                method="GET",
                                url=url,
                                status_code=resp.status_code,
                                request_headers=req_headers,
                                response_headers=dict(resp.headers),
                                validation="Null Origin accepted in ACAO",
                                confidence="high",
                            )))
                            break

                    except requests.exceptions.Timeout:
                        continue
                    except Exception:
                        continue

            except Exception as e:
                logging.debug(f"[Corsy] Error for {url}: {e}")

        # Lưu results
        output_path = os.path.join(out_dir, "cors_findings.json")
        try:
            with open(output_path, 'w') as f:
                json.dump(findings, f, indent=2)
        except Exception:
            pass

        logging.info(f"[Corsy] Phát hiện {len(findings)} CORS misconfiguration issues.")
        return findings
