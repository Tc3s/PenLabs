#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PENLABS V1.0 — Recursive Subdomain Attack Pipeline (Full Coverage)

Quét FULL api-bounty pipeline cho TẤT CẢ subdomains.
Discovery Loop: subdomains mới phát hiện từ Katana/JS/CORS được feed ngược queue.
Recursive depth tối đa: 2.

Author: PenLabs Security Team
"""

import asyncio
import os
import re
import socket
import logging
from urllib.parse import urlparse


class SubdomainScanner:
    """
    V1.0 — Recursive Subdomain Attack Pipeline (FULL COVERAGE).

    Workflow:
    1. Nhận danh sách subdomains từ OSINT (SubdomainHunter)
    2. Resolve DNS + httpx probe → lọc subdomains sống
    3. Priority Sort → ưu tiên mail/api/admin nhưng VẪN quét tất cả
    4. Chạy FULL api-bounty 20-step pipeline cho TỪNG subdomain
    5. Discovery Loop: subdomains mới phát hiện từ Katana/JS/CORS
       → thêm vào queue (recursive depth max 2)
    6. Merge results → thêm vào profile chính
    """

    PRIORITY_KEYWORDS = [
        "mail", "api", "admin", "dev", "portal", "staging", "test",
        "uat", "cms", "login", "sso", "auth", "vpn", "remote", "gateway",
        "webmail", "cpanel", "panel", "manage", "dashboard", "internal",
    ]

    def __init__(self, scanner_router, logger, orchestrator):
        """
        Args:
            scanner_router: ScannerRouter instance (reuse existing)
            logger: Logger instance
            orchestrator: ReconOrchestrator instance (for resolve() and config access)
        """
        self.scanner = scanner_router
        self.log = logger
        self.orchestrator = orchestrator
        self.scanned_subs = set()       # Track subdomains đã quét để tránh lặp
        self.discovered_subs = set()    # Subdomains phát hiện TRONG quá trình quét
        self.all_results = []           # Kết quả scan tích lũy

        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: WILDCARD DNS PROTECTION (TASK 7)
        # Sinkhole IPs detected during wildcard check.
        # Any subdomain resolving to these IPs will be dropped.
        # ═══════════════════════════════════════════════════════════════
        self._wildcard_sinkhole_ips: set = set()
        self._depth_throttled = False  # Dynamic depth control

    # ------------------------------------------------------------------
    # V1.0-FIX: WILDCARD DNS DETECTION (TASK 7)
    # ------------------------------------------------------------------
    def detect_wildcard(self, domain: str) -> bool:
        """
        Detect wildcard DNS by resolving random non-existent subdomains.
        If they resolve, mark the IP as a sinkhole.

        Args:
            domain: Base domain to test (e.g., example.com)

        Returns:
            True if wildcard detected, False otherwise
        """
        import secrets as _sec

        test_subs = [
            f"this-should-not-exist-{_sec.token_hex(6)}.{domain}",
            f"definitely-fake-sub-{_sec.token_hex(6)}.{domain}",
            f"xyzzy-nope-{_sec.token_hex(6)}.{domain}",
        ]

        sinkhole_candidates = set()
        for test_sub in test_subs:
            try:
                addrinfo = socket.getaddrinfo(test_sub, None, socket.AF_INET)
                if addrinfo:
                    ip = addrinfo[0][4][0]
                    sinkhole_candidates.add(ip)
                    self.log.info(f"  [WILDCARD] Random sub '{test_sub}' resolved to {ip}")
            except socket.gaierror:
                # Good — this is expected behavior (NXDOMAIN)
                pass
            except Exception:
                pass

        if sinkhole_candidates:
            self._wildcard_sinkhole_ips = sinkhole_candidates
            ips_str = ', '.join(sinkhole_candidates)
            self.log.warning(
                f"  [WILDCARD] ⚠️ Detected sinkhole IP(s): {ips_str}. "
                f"All subdomains resolving to these IPs will be DROPPED."
            )
            return True

        self.log.info(f"  [WILDCARD] No wildcard DNS detected for {domain} — safe to proceed.")
        return False

    # ------------------------------------------------------------------
    # PRIORITY SORT
    # ------------------------------------------------------------------
    def priority_sort(self, subdomains: list) -> list:
        """
        Sắp xếp subdomains theo priority (mail/api/admin trước).
        KHÔNG loại bỏ bất kỳ sub nào — chỉ sort thứ tự.

        Returns:
            list: Subdomains sorted by priority score (descending)
        """
        from config import Config

        keywords = Config.SUBDOMAIN_PRIORITY_KEYWORDS

        def _score(sub: str) -> int:
            """Score cao = quét trước."""
            sub_lower = sub.lower()
            score = 0
            for i, kw in enumerate(keywords):
                if kw in sub_lower:
                    # Keywords đầu tiên trong list = priority cao hơn
                    score += (len(keywords) - i) * 10
            return score

        scored = [(sub, _score(sub)) for sub in subdomains]
        scored.sort(key=lambda x: x[1], reverse=True)

        # Log priority order
        priority_subs = [s for s, sc in scored if sc > 0]
        normal_subs = [s for s, sc in scored if sc == 0]
        if priority_subs:
            self.log.info(f"  [Priority] High-value subs ({len(priority_subs)}): {', '.join(priority_subs[:10])}")
        if normal_subs:
            self.log.info(f"  [Normal] Remaining subs ({len(normal_subs)}): {', '.join(normal_subs[:10])}")

        return [s for s, _ in scored]

    # ------------------------------------------------------------------
    # PROBE SUBDOMAINS
    # ------------------------------------------------------------------
    async def probe_subdomains(self, subdomains: list) -> list:
        """
        DNS resolve + httpx probe → trả về danh sách sub sống với metadata.

        Returns:
            list: [{"sub": "mail.x.vn", "ip": "1.2.3.4",
                    "live_urls": ["https://mail.x.vn"],
                    "tech": [...], "waf_detected": bool, "waf_name": str}]
        """
        import subprocess
        import shutil
        import json

        live_subs = []
        self.log.info(f"  [Probe] Resolving DNS + probing {len(subdomains)} subdomains...")

        for sub in subdomains:

            sub_info = {
                "sub": sub,
                "ip": None,
                "live_urls": [],
                "tech": [],
                "waf_detected": False,
                "waf_name": "",
            }

            # DNS Resolution (Optional in Ghost Mode, but useful for IP tracking)
            try:
                loop = asyncio.get_event_loop()
                addrinfo = await loop.getaddrinfo(sub, None, family=socket.AF_INET)
                if addrinfo:
                    sub_info["ip"] = addrinfo[0][4][0]
            except Exception:
                # In Ghost Mode, we don't care if local DNS fails, httpx with socks5h will handle it
                if not self.scanner.stealth_recon:
                    self.log.info(f"    [-] {sub} — DNS resolution failed, skipping.")
                    continue
                sub_info["ip"] = "via-tor"

            # httpx probe — direct subprocess (avoid plugin signature mismatch)
            if shutil.which("httpx-toolkit"):
                httpx_dir = os.path.join(self.scanner.raw, f"httpx_sub_{sub.replace('.', '_')}")
                os.makedirs(httpx_dir, exist_ok=True)
                input_file = os.path.join(httpx_dir, "httpx_input.txt")
                jsonl_file = os.path.join(httpx_dir, "httpx_output.jsonl")

                probe_targets = [f"https://{sub}", f"http://{sub}"]
                with open(input_file, "w") as f:
                    f.write("\n".join(probe_targets))

                cmd = [
                    "httpx-toolkit", "-l", input_file,
                    "-json", "-output", jsonl_file,
                    "-threads", "5", "-title", "-tech-detect", # Giảm threads khi dùng Tor
                    "-status-code", "-web-server", "-silent",
                    "-no-color", "-no-stdin", "-timeout", "30", # Tăng timeout cho Tor
                ]
                
                # Ultimate Stealth Mode: Tor Proxy + randomized JA3
                use_tor_proxy = self.scanner.stealth_recon
                if use_tor_proxy:
                    cmd.extend(["-proxy", "socks5h://127.0.0.1:9050"])
                    self.log.info(f"    [Ghost] Routing probe via Tor (Remote DNS) for {sub}...")
                try:
                    proc_result = await loop.run_in_executor(
                        None, lambda: subprocess.run(
                            cmd, capture_output=True, text=True, timeout=60
                        )
                    )
                    # Parse results
                    if os.path.exists(jsonl_file):
                        with open(jsonl_file, "r") as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    data = json.loads(line)
                                    url = data.get("url", "")
                                    if url:
                                        sub_info["live_urls"].append(url)
                                        sub_info["tech"].extend(data.get("tech", []))
                                        server = data.get("webserver", "").lower()
                                        if any(w in server for w in ["waf", "cloudflare", "imperva", "akamai"]):
                                            sub_info["waf_detected"] = True
                                            sub_info["waf_name"] = data.get("webserver", "")
                                except json.JSONDecodeError:
                                    continue

                    # [V1.0-FIX] Tor fallback: if Tor probe got 0 results, retry direct
                    if use_tor_proxy and not sub_info["live_urls"]:
                        self.log.warning(f"    [Ghost] Tor probe returned 0 results for {sub}, retrying direct...")
                        # Remove the -proxy flag and retry
                        cmd_direct = [arg for arg in cmd if arg not in ["-proxy", "socks5h://127.0.0.1:9050"]]
                        jsonl_fallback = os.path.join(httpx_dir, "httpx_output_direct.jsonl")
                        # Replace output path
                        cmd_direct = [jsonl_fallback if arg == jsonl_file else arg for arg in cmd_direct]
                        proc_result2 = await loop.run_in_executor(
                            None, lambda: subprocess.run(
                                cmd_direct, capture_output=True, text=True, timeout=60
                            )
                        )
                        if os.path.exists(jsonl_fallback):
                            with open(jsonl_fallback, "r") as f:
                                for line in f:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    try:
                                        data = json.loads(line)
                                        url = data.get("url", "")
                                        if url:
                                            sub_info["live_urls"].append(url)
                                            sub_info["tech"].extend(data.get("tech", []))
                                            server = data.get("webserver", "").lower()
                                            if any(w in server for w in ["waf", "cloudflare", "imperva", "akamai"]):
                                                sub_info["waf_detected"] = True
                                                sub_info["waf_name"] = data.get("webserver", "")
                                    except json.JSONDecodeError:
                                        continue
                        if sub_info["live_urls"]:
                            self.log.info(f"    [Ghost] Direct fallback found {len(sub_info['live_urls'])} live URLs for {sub}")

                except Exception as e:
                    self.log.warning(f"    [!] httpx probe failed for {sub}: {e}")
            else:
                # Fallback: assume live if httpx not available
                sub_info["live_urls"] = [f"https://{sub}", f"http://{sub}"]

            if sub_info["live_urls"]:
                # ═══════════════════════════════════════════════════════════
                # V1.0-FIX: WILDCARD SINKHOLE FILTER (TASK 7)
                # Drop subdomains resolving to known wildcard sinkhole IPs.
                # ═══════════════════════════════════════════════════════════
                if (self._wildcard_sinkhole_ips and
                        sub_info["ip"] in self._wildcard_sinkhole_ips):
                    self.log.info(
                        f"    [WILDCARD] Dropping {sub} — resolves to sinkhole "
                        f"{sub_info['ip']} (fake asset)"
                    )
                    continue

                live_subs.append(sub_info)
                waf_tag = f" [WAF: {sub_info['waf_name']}]" if sub_info["waf_detected"] else ""
                self.log.info(f"    [+] {sub} → {sub_info['ip']} — {len(sub_info['live_urls'])} live URLs{waf_tag}")
            else:
                self.log.info(f"    [-] {sub} → {sub_info['ip']} — No HTTP services, skipping.")

        # Report wildcard filtering stats
        if self._wildcard_sinkhole_ips:
            total_before = len(subdomains)
            dropped = total_before - len(live_subs)
            if dropped > 0:
                self.log.warning(
                    f"  [WILDCARD] Dropped {dropped} fake subdomains "
                    f"(sinkhole IPs: {', '.join(self._wildcard_sinkhole_ips)})"
                )

        self.log.success(f"  [Probe] {len(live_subs)}/{len(subdomains)} subdomains alive.")
        return live_subs

    # ------------------------------------------------------------------
    # WAF DETECTION
    # ------------------------------------------------------------------
    async def _detect_waf(self, url: str) -> tuple:
        """
        Detect WAF trên 1 URL bằng response headers.
        Returns: (has_waf: bool, waf_name: str)
        """
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
                ) as resp:
                    headers = dict(resp.headers)
                    waf_signatures = {
                        "R-WAF": "Server",
                        "Cloudflare": "Server",
                        "AWS WAF": "X-Amzn-WAF",
                        "Imperva": "X-CDN",
                        "Akamai": "X-Akamai-Transformed",
                        "F5 BIG-IP": "X-WA-Info",
                        "Sucuri": "Server",
                        "Barracuda": "Server",
                    }
                    for waf_name, header_key in waf_signatures.items():
                        val = headers.get(header_key, "")
                        if waf_name.lower() in val.lower():
                            return True, waf_name
                    return False, ""
        except Exception:
            # Fallback: try with requests if aiohttp not available
            try:
                import requests
                resp = requests.get(url, timeout=10, verify=False,
                                    headers={"User-Agent": "Mozilla/5.0"},
                                    allow_redirects=True)
                server = resp.headers.get("Server", "").lower()
                for waf_name in ["r-waf", "cloudflare", "imperva", "akamai", "sucuri"]:
                    if waf_name in server:
                        return True, resp.headers.get("Server", "")
                return False, ""
            except Exception:
                return False, ""

    # ------------------------------------------------------------------
    # SCAN SINGLE SUBDOMAIN (Full api-bounty pipeline)
    # ------------------------------------------------------------------
    async def scan_subdomain(self, sub_info: dict, base_domain: str) -> dict:
        """
        Full api-bounty 20-step pipeline cho 1 subdomain.
        Gọi scanner._route_api_bounty() với target = subdomain.

        Args:
            sub_info: Dict từ probe_subdomains (sub, ip, live_urls, waf_detected...)
            base_domain: Domain gốc (để extract new subs)

        Returns:
            dict: Kết quả scan bao gồm xss_findings, nuclei_findings, etc.
        """
        from config import Config

        sub = sub_info["sub"]
        ip = sub_info["ip"]
        waf = sub_info.get("waf_detected", False)
        waf_name = sub_info.get("waf_name", "")

        self.log.phase(f"SUBDOMAIN SCAN: {sub} ({ip})")
        if waf:
            # Thêm Jitter ngẫu nhiên để tránh pattern detection của WAF
            import random
            jitter = random.uniform(0.8, 1.2)
            actual_rate = int(Config.SUBDOMAIN_WAF_THROTTLE_RATE * jitter)
            self.log.warning(f"  [WAF] {waf_name} detected → Throttling with Jitter: {actual_rate} req/s (x{jitter:.2f})")
            self.scanner.rate_limit = actual_rate

        # Tạo output directory riêng cho subdomain
        sub_dir = os.path.join(self.scanner.raw, f"subdomain_{sub.replace('.', '_')}")
        os.makedirs(sub_dir, exist_ok=True)

        # Backup và swap ScannerRouter state cho subdomain
        original_raw = self.scanner.raw
        original_rate = self.scanner.rate_limit
        original_headers = getattr(self.scanner, 'headers', {}).copy()

        try:
            self.scanner.raw = sub_dir
            if waf:
                self.scanner.rate_limit = Config.SUBDOMAIN_WAF_THROTTLE_RATE
                
                # [WAF EVASION] Inject IP spoofing & cache-busting headers
                waf_evasion_headers = {
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Remote-Addr": "127.0.0.1",
                    "X-Client-IP": "127.0.0.1",
                    "X-Host": "127.0.0.1",
                    "X-Forwarded-Host": "127.0.0.1",
                    "Cache-Control": "no-cache"
                }
                new_headers = original_headers.copy()
                new_headers.update(waf_evasion_headers)
                self.scanner.headers = new_headers

            # [V1.0-FIX] ORIGIN IP DISCOVERY FOR SUBDOMAINS
            # Kiểm tra xem subdomain có đứng sau CDN không, nếu có thì tìm IP thật.
            effective_ip = ip
            if waf or "cloudflare" in waf_name.lower() or "akamai" in waf_name.lower():
                self.log.info(f"  [Origin] {sub} stands behind CDN/WAF. Attempting to find Origin IP...")
                try:
                    from core.origin_discovery_engine import OriginDiscoveryEngine
                    origin_engine = OriginDiscoveryEngine()
                    origin_res = origin_engine.discover(sub)
                    if origin_res.get("origin_ip") and origin_res.get("confidence", 0) >= 80:
                        effective_ip = origin_res["origin_ip"]
                        self.log.warning(f"  [Origin] 🎯 FOUND ORIGIN IP for {sub}: {effective_ip} (Confidence: {origin_res['confidence']}%)")
                        self.log.info(f"  [Origin] Switching target IP for {sub}: {ip} -> {effective_ip}")
                except Exception as e:
                    self.log.debug(f"  [Origin] Subdomain origin discovery failed: {e}")

            # Lấy OSINT ports từ Shodan cho IP thực tế (Origin nếu tìm thấy)
            osint_ports = []
            try:
                osint_collector = self.orchestrator.osint
                shodan_data = await osint_collector.get_shodan_internetdb(effective_ip)
                osint_ports = shodan_data.get("ports", [])
            except Exception:
                osint_ports = [80, 443]

            # Dynamic routing based on active scanner mode
            mode = (self.scanner.mode or "asset-discovery").lower()
            self.log.info(f"  [Subdomain-Scan] Routing subdomain '{sub}' via active mode: {mode.upper()}")
            
            if mode == "asset-discovery":
                scan_result = await self.scanner._route_asset_discovery(effective_ip, sub, 0, osint_ports)
            elif mode == "api-breach":
                scan_result = await self.scanner._route_api_breach(effective_ip, sub, 0, osint_ports)
            elif mode == "cloud-native":
                scan_result = await self.scanner._route_cloud_native(effective_ip, sub, 0, osint_ports)
            elif mode == "infra-smash":
                scan_result = await self.scanner._route_infra_smash(effective_ip, sub, 0, osint_ports)
            elif mode == "stealth":
                scan_result = await self.scanner._route_stealth(effective_ip, sub, 0, osint_ports)
            elif mode == "sniper":
                scan_result = await self.scanner._route_sniper(effective_ip, sub, 0, osint_ports)
            elif mode == "web-vuln":
                scan_result = await self.scanner._route_web_vuln(effective_ip, sub, 0, osint_ports)
            elif mode == "cloud-devops":
                scan_result = await self.scanner._route_cloud_devops(effective_ip, sub, 0, osint_ports)
            elif mode == "full-audit":
                scan_result = await self.scanner._route_full_audit(effective_ip, sub, 0, osint_ports)
            elif mode == "api-bounty":
                scan_result = await self.scanner._route_api_bounty(effective_ip, sub, 0, osint_ports, waf)
            else:
                # Default fallback
                scan_result = await self.scanner._route_api_bounty(effective_ip, sub, 0, osint_ports, waf)

            # Gắn metadata
            scan_result["_subdomain"] = sub
            scan_result["_ip"] = ip
            scan_result["_origin_ip"] = effective_ip if effective_ip != ip else None
            scan_result["_waf_detected"] = waf
            scan_result["_waf_name"] = waf_name

            # Log summary
            dast_findings = scan_result.get("dast_findings", []) or []
            xss_count = len([f for f in dast_findings if isinstance(f, dict) and f.get("category") == "xss"]) if dast_findings else len(scan_result.get("xss_findings", []))
            nuclei_count = len(scan_result.get("nuclei_findings", []))
            sqli_count = len([f for f in dast_findings if isinstance(f, dict) and f.get("category") == "sqli"]) if dast_findings else len(scan_result.get("sqli_findings", []))
            ssrf_count = len([f for f in dast_findings if isinstance(f, dict) and f.get("category") == "ssrf"]) if dast_findings else len(scan_result.get("ssrf_findings", []))
            blind_xss_count = len([f for f in dast_findings if isinstance(f, dict) and f.get("category") == "blind_xss"])
            api_count = len(scan_result.get("api_endpoints", []))
            params_count = len(scan_result.get("hidden_params", {}))

            findings_parts = []
            if xss_count: findings_parts.append(f"🕷️ {xss_count} XSS")
            if blind_xss_count: findings_parts.append(f"🪝 {blind_xss_count} Blind-XSS")
            if nuclei_count: findings_parts.append(f"🔍 {nuclei_count} Nuclei")
            if sqli_count: findings_parts.append(f"💉 {sqli_count} SQLi")
            if ssrf_count: findings_parts.append(f"🌐 {ssrf_count} SSRF")
            if api_count: findings_parts.append(f"📡 {api_count} APIs")
            if params_count: findings_parts.append(f"🔑 {params_count} hidden params")

            if findings_parts:
                self.log.success(f"  [{sub}] Findings: {' | '.join(findings_parts)}")
            else:
                self.log.info(f"  [{sub}] No findings.")

            return scan_result

        except Exception as e:
            self.log.error(f"  [{sub}] Scan failed: {e}")
            return {"_subdomain": sub, "_ip": ip, "_error": str(e)}
        finally:
            # Restore original state
            self.scanner.raw = original_raw
            self.scanner.rate_limit = original_rate
            if hasattr(self.scanner, 'headers'):
                self.scanner.headers = original_headers

    # ------------------------------------------------------------------
    # EXTRACT NEW SUBDOMAINS FROM SCAN RESULTS
    # ------------------------------------------------------------------
    def _extract_new_subdomains(self, scan_result: dict, base_domain: str) -> set:
        """
        Trích xuất subdomains mới phát hiện từ kết quả scan.
        Kiểm tra: web_urls, api_endpoints, cors_findings/cors_issues, secrets/js_secrets
        Lọc: chỉ giữ subs thuộc base_domain, loại bỏ đã quét.

        Returns:
            set: New subdomains found during scanning
        """
        new_subs = set()
        # Regex để tìm subdomains trong URLs
        domain_pattern = re.compile(
            r'(?:https?://)?([a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?\.(?:[a-zA-Z0-9\-]+\.)*'
            + re.escape(base_domain) + r')',
            re.IGNORECASE
        )

        # Thu thập tất cả URLs/strings từ scan results
        url_sources = []

        # Web URLs
        url_sources.extend(scan_result.get("web_urls", []))
        url_sources.extend(scan_result.get("web_urls_with_params", []) or [])

        # API endpoints
        for ep in scan_result.get("api_endpoints", []):
            if isinstance(ep, dict):
                url_sources.append(ep.get("url", ""))
            elif isinstance(ep, str):
                url_sources.append(ep)

        # CORS issues — Access-Control-Allow-Origin chứa subdomain
        for cors in scan_result.get("cors_findings", scan_result.get("cors_issues", [])):
            if isinstance(cors, dict):
                url_sources.append(cors.get("origin", ""))
                url_sources.append(cors.get("url", ""))

        # Nuclei findings
        for nf in scan_result.get("nuclei_findings", []):
            if isinstance(nf, dict):
                url_sources.append(nf.get("matched_at", ""))
                url_sources.append(nf.get("url", ""))

        # JS secrets
        for secret in scan_result.get("secrets", scan_result.get("js_secrets", [])):
            if isinstance(secret, dict):
                url_sources.append(secret.get("value", ""))

        # Extract subdomains from collected URLs
        for url_str in url_sources:
            if not url_str or not isinstance(url_str, str):
                continue
            # [V1.0-FIX] Decode percent-encoded characters BEFORE regex matching
            # Prevents false subdomain matches from URLs like foo%2fbar.target.com
            from urllib.parse import unquote
            url_str = unquote(url_str)
            matches = domain_pattern.findall(url_str)
            for match in matches:
                sub = match.lower().strip(".")
                if (sub and
                    sub != base_domain and
                    sub.endswith(f".{base_domain}") and
                    sub not in self.scanned_subs):
                    new_subs.add(sub)

        return new_subs

    # ------------------------------------------------------------------
    # MAIN ORCHESTRATOR
    # ------------------------------------------------------------------
    async def run(self, subdomains: list, base_domain: str) -> list:
        """
        Entry point — orchestrate toàn bộ subdomain scanning.

        Loop:
        1. Sort priority → quét sequential (delay giữa mỗi sub)
        2. Sau mỗi sub → extract new subs → thêm vào queue
        3. Lặp lại cho đến khi hết queue hoặc depth > max_depth

        Args:
            subdomains: List of subdomain strings from OSINT
            base_domain: The original target domain

        Returns:
            list: Scan results for each subdomain
        """
        from config import Config

        max_depth = Config.SUBDOMAIN_MAX_DEPTH
        delay = Config.SUBDOMAIN_DELAY

        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: WILDCARD DNS DETECTION (TASK 7)
        # Check for wildcard DNS BEFORE scanning any subdomains.
        # ═══════════════════════════════════════════════════════════════
        self.detect_wildcard(base_domain)

        # V1.0-FIX: DYNAMIC DEPTH THROTTLE THRESHOLD
        DEPTH_THROTTLE_LIMIT = 500

        # Queue: (subdomain, depth)
        queue = [(sub, 0) for sub in subdomains]
        queued_subs = set(subdomains)

        self.log.info(f"  [Queue] Initial: {len(queue)} subdomains, max recursive depth: {max_depth}")

        # Sort initial queue by priority
        sorted_subs = self.priority_sort([s for s, _ in queue])
        queue = [(s, 0) for s in sorted_subs]

        while queue:
            sub, depth = queue.pop(0)

            # Skip nếu đã quét
            if sub in self.scanned_subs:
                continue

            # Skip domain chính (đã quét ở phase trước)
            if sub == base_domain:
                continue

            self.scanned_subs.add(sub)

            # Progress log
            remaining = len(queue)
            total_done = len(self.scanned_subs)
            self.log.info(f"\n  ━━━ [{total_done}/{total_done + remaining}] Scanning: {sub} (depth={depth}) ━━━")

            # Probe subdomain
            probe_results = await self.probe_subdomains([sub])
            if not probe_results:
                self.log.info(f"  [-] {sub} not alive, skipping.")
                continue

            sub_info = probe_results[0]

            # Scan subdomain (Full api-bounty pipeline)
            scan_result = await self.scan_subdomain(sub_info, base_domain)

            # V1.0-FIX: OOM-SAFE Save to disk instead of RAM
            res_file = os.path.join(self.scanner.raw, f"sub_result_{sub.replace('.', '_')}.json")
            import json
            os.makedirs(os.path.dirname(res_file), exist_ok=True)
            with open(res_file, "w") as f:
                json.dump(scan_result, f)
            self.all_results.append(res_file)


            # Discovery Loop: extract new subdomains from results
            if depth < max_depth and not self._depth_throttled:
                new_subs = self._extract_new_subdomains(scan_result, base_domain)
                new_subs -= self.scanned_subs
                new_subs -= queued_subs

                if new_subs:
                    self.log.success(
                        f"  [Discovery] Found {len(new_subs)} NEW subdomains from {sub}: "
                        f"{', '.join(list(new_subs)[:5])}"
                    )
                    # Sort new subs by priority and add to queue
                    sorted_new = self.priority_sort(list(new_subs))
                    for ns in sorted_new:
                        queue.append((ns, depth + 1))
                        queued_subs.add(ns)
                        self.discovered_subs.add(ns)

            # ═══════════════════════════════════════════════════════════════
            # V1.0-FIX: DYNAMIC DEPTH THROTTLE (TASK 7)
            # If total discovered exceeds threshold, disable recursion.
            # ═══════════════════════════════════════════════════════════════
            if (not self._depth_throttled and
                    len(self.scanned_subs) + len(queue) > DEPTH_THROTTLE_LIMIT):
                self._depth_throttled = True
                self.log.warning(
                    f"  [⚠️ DEPTH THROTTLE] {len(self.scanned_subs) + len(queue)} subdomains "
                    f"exceed {DEPTH_THROTTLE_LIMIT} limit. Disabling recursion for "
                    f"remainder of session to prevent infinite loops."
                )

            # Delay giữa các subdomain để tránh WAF/rate-limit
            if queue:  # Không delay sau sub cuối cùng
                self.log.info(f"  [Delay] Waiting {delay}s before next subdomain...")
                await asyncio.sleep(delay)

        from scripts.Module1_Recon import _summarize_subdomain_vulns
        subdomain_summary = _summarize_subdomain_vulns(self.all_results)

        self.log.phase(f"SUBDOMAIN SCAN COMPLETE — {len(self.all_results)} subs scanned")
        self.log.info(
            f"  📊 Total: {subdomain_summary['total_xss']} XSS | "
            f"{subdomain_summary['total_blind_xss']} Blind-XSS | "
            f"{subdomain_summary['total_nuclei']} Nuclei | "
            f"{subdomain_summary['total_sqli']} SQLi | "
            f"{subdomain_summary['total_ssrf']} SSRF | "
            f"{subdomain_summary['total_mass_assignment']} Mass-Assignment"
        )
        if self.discovered_subs:
            self.log.info(f"  🔄 Discovered {len(self.discovered_subs)} NEW subs during scanning: "
                          f"{', '.join(list(self.discovered_subs)[:10])}")

        return self.all_results
