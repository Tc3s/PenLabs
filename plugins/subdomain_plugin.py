#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SUBDOMAIN HUNTER PLUGIN
Tích hợp AssetHunter và WildcardFilter từ Module1_Reconv3.py
Sử dụng StealthNet plugin để bypass WAF.
"""

import os
import random
import string
import hashlib
import re
import asyncio
import logging
import shutil
import subprocess
import socket
from urllib.parse import urlparse

from core.base_plugin import BasePlugin
from core.registry import PluginRegistry
from scripts.subdomain_scanner import SubdomainScanner


class SubdomainHunterPlugin(BasePlugin):
    """
    Subdomain enumeration plugin, bao gồm passive/active sources,
    API lookups và tính năng Wildcard Filter.
    """

    def name(self) -> str:
        return "SubdomainHunter"

    def description(self) -> str:
        return "Recon plugin săn subdomain qua OSINT, API, Subfinder và loại bỏ rác bằng wildcard filtering."

    def check_installed(self) -> bool:
        return True

    def run(self, domain: str, api_keys: dict = None, use_stealth: bool = True) -> tuple:
        """
        Thực thi săn tìm subdomain.
        Returns: (danh_sách_subdomain, danh_sách_endpoints_wayback, logs_thực_thi)
        """
        api_keys = api_keys or {}
        subs = set()
        urls = set()
        logs = []

        # Get stealth network client from registry
        net = PluginRegistry.get("StealthNet")
        if not net:
            logs.append("[!] Lỗi: Không thể tìm thấy StealthNet plugin. Fallback thất bại.")
            return list(subs), list(urls), logs

        # Khởi tạo StealthNet nếu chưa khởi tạo
        net.run(proxy=False)
        
        domain = self._sanitize_input(domain)
        logs.append(f"[*] Bắt đầu săn subdomain cho: {domain}")

        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: WILDCARD DNS DETECTION (TASK 2)
        # Call SubdomainScanner.detect_wildcard() BEFORE active enumeration
        # to identify sinkhole IPs and filter fake subdomains.
        # ═══════════════════════════════════════════════════════════════
        _wildcard_sinkhole_ips = set()
        try:
            _scanner = SubdomainScanner.__new__(SubdomainScanner)
            _scanner._wildcard_sinkhole_ips = set()
            _scanner._depth_throttled = False
            _scanner.scanned_subs = set()
            _scanner.log = logging.getLogger("SubdomainHunter.wildcard")
            has_wildcard = _scanner.detect_wildcard(domain)
            _wildcard_sinkhole_ips = _scanner._wildcard_sinkhole_ips
            if has_wildcard:
                logs.append(f"[WILDCARD] ⚠️  Wildcard DNS detected for {domain}! Sinkhole IPs: {_wildcard_sinkhole_ips}")
                logging.warning(f"[SubdomainHunter][WILDCARD] Sinkhole IPs: {_wildcard_sinkhole_ips}")
            else:
                logs.append(f"[WILDCARD] ✅ No wildcard DNS detected for {domain}.")
        except Exception as e:
            logging.warning(f"[SubdomainHunter][WILDCARD] Detection failed: {e}")
            logs.append(f"[WILDCARD] Detection failed: {e} — continuing without filter.")

        # --- 1. PASSIVE SOURCES ---
        logs.append("  -> Chạy mục tiêu bị động (crt.sh, Wayback)...")
        
        # crt.sh
        r = net.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=20)
        if r:
            try:
                for i in r.json():
                    for s in i.get('name_value', '').split('\n'):
                        s = s.strip()
                        if s.endswith(domain) and "*" not in s: 
                            subs.add(s)
            except Exception as e:
                logging.debug(f"crt.sh parse error: {e}")
                
        # Wayback Machine
        r = net.get(f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=3000", timeout=30)
        if r:
            try:
                for row in r.json()[1:]:
                    url_str = row[0]
                    urls.add(url_str)
                    parsed_domain = urlparse(url_str).netloc
                    if parsed_domain.endswith(domain): 
                        subs.add(parsed_domain)
            except Exception as e:
                logging.debug(f"Wayback parse error: {e}")

        # --- 2. ACTIVE TOOLS ---
        subfinder_path = shutil.which("subfinder")
        import sys
        is_debug = "--debug" in sys.argv

        if subfinder_path:
            logs.append("  -> Chạy công cụ Subfinder...")
            try:
                cmd = [subfinder_path, "-d", domain]
                if not is_debug:
                    cmd.append("-silent")
                elif is_debug:
                    logs.append(f"[DEBUG] CMD: {' '.join(cmd)}")
                out = subprocess.check_output(cmd, text=True, timeout=60)
                for line in out.splitlines():
                    if line.strip():
                        subs.add(line.strip())
            except Exception as e:
                logging.warning(f"Subfinder failed: {e}")
        else:
            logs.append("  -> Skip Subfinder (Không được cài đặt)")

        # --- 3. API SOURCES ---
        vt_key = api_keys.get("VIRUSTOTAL_KEY")
        if vt_key:
            logs.append("  -> Truy vấn VirusTotal API...")
            r = net.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40", 
                             headers={"x-apikey": vt_key})
            if r:
                try: 
                    for d in r.json().get('data', []): 
                        subs.add(d['id'])
                except Exception as e:
                    logging.debug(f"VirusTotal subdomain parse error: {e}")
        else:
            logs.append("  -> Skip VirusTotal (Thiếu VT_API_KEY)")

        chaos_key = api_keys.get("CHAOS_KEY")
        if chaos_key:
            logs.append("  -> Truy vấn Chaos API...")
            #  Dùng endpoint dns.projectdiscovery.io (chaos-api.* bị deprecated/DNS fail)
            # Thêm timeout=10 để tránh treo pipeline 90s
            try:
                r = net.get(
                    f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
                    headers={"Authorization": chaos_key},
                    timeout=10
                )
                if r and r.status_code == 200:
                    try:
                        for s in r.json().get('subdomains', []):
                            subs.add(f"{s}.{domain}")
                    except Exception as e:
                        logging.debug(f"Chaos API parse error: {e}")
                elif r:
                    logs.append(f"  [!] Chaos API returned {r.status_code} — skipping (rate limit/auth)")
            except Exception as e:
                logs.append(f"  [!] Chaos API unreachable — skipping ({type(e).__name__})")

        # SecurityTrails
        st_key = api_keys.get("SECURITYTRAILS_KEY", os.getenv("SECURITYTRAILS_KEY", ""))
        if st_key:
            logs.append("  -> Truy vấn SecurityTrails API...")
            r = net.post(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                              headers={"APIKEY": st_key},
                              json_data={"children_only": True})
            if r:
                try:
                    for s in r.json().get('subdomains', []): 
                        subs.add(f"{s}.{domain}")
                except Exception as e:
                    logging.debug(f"SecurityTrails parse error: {e}")

        subs.add(domain)
        logs.append(f"[*] Tìm thấy tổng cộng {len(subs)} subdomains thô.")

        # --- 4. WILDCARD FILTERING ---
        if use_stealth:
            logs.append(f"[*] Chạy bộ lọc honeypot/wildcard để loại subdomain rác...")
            live_subs, w_logs = self._filter_wildcards(domain, list(subs), net)
            logs.extend(w_logs)

            # V1.0-FIX: Apply sinkhole IP filter from detect_wildcard()
            if _wildcard_sinkhole_ips:
                pre_count = len(live_subs)
                filtered_subs = []
                for sub_info in live_subs:
                    sub_ip = sub_info.get("ip", "") if isinstance(sub_info, dict) else ""
                    sub_name = sub_info.get("sub", "") if isinstance(sub_info, dict) else str(sub_info)
                    if sub_ip in _wildcard_sinkhole_ips:
                        logging.info(f"[WILDCARD] Dropped subdomain {sub_name} trỏ về sinkhole IP {sub_ip}")
                        logs.append(f"[WILDCARD] Dropped subdomain {sub_name} trỏ về sinkhole IP {sub_ip}")
                    else:
                        filtered_subs.append(sub_info)
                live_subs = filtered_subs
                dropped = pre_count - len(live_subs)
                if dropped > 0:
                    logs.append(f"[WILDCARD] ☣️  Dropped {dropped} fake subdomains (sinkhole filter)")
                    logging.info(f"[SubdomainHunter][WILDCARD] Dropped {dropped} fake subdomains")

            logs.append(f"[*] Subdomains còn sống sau khi lọc: {len(live_subs)}")
            return live_subs, list(urls), logs
        else:
            # Nếu không dùng stealth/filter, kiểm tra resolve DNS đơn giản
            live_subs = []
            max_resolve = 500
            process_list = list(subs)[:max_resolve]
            if len(subs) > max_resolve:
                logs.append(f"[!] Quá nhiều subdomains ({len(subs)}), chỉ resolve {max_resolve} cái đầu tiên.")
            
            for s in process_list:
                try:
                    ip = socket.gethostbyname(s)
                    # V1.0-FIX: Apply sinkhole IP filter
                    if ip in _wildcard_sinkhole_ips:
                        logging.info(f"[WILDCARD] Dropped subdomain {s} trỏ về sinkhole IP {ip}")
                        logs.append(f"[WILDCARD] Dropped subdomain {s} trỏ về sinkhole IP {ip}")
                        continue
                    live_subs.append({"sub": s, "ip": ip})
                except (socket.gaierror, socket.timeout, OSError):
                    continue

            if _wildcard_sinkhole_ips:
                logs.append(f"[WILDCARD] Sinkhole filter applied (non-stealth path). Remaining: {len(live_subs)}")

            return live_subs, list(urls), logs

    # --- INTERNAL HELPERS ---
    
    def _sanitize_input(self, s: str):
        s = s.strip()
        if s.startswith("http://") or s.startswith("https://"):
            try: return urlparse(s).netloc
            except Exception as e:
                logging.debug(f"URL parse error: {e}")
                return s.replace("http://", "").replace("https://", "").split("/")[0]
        return s

    def _filter_wildcards(self, domain: str, subdomains: list, net) -> tuple:
        """
        [V1.0] Rewritten wildcard filter:
        1. Resolve DNS via dnsx (subprocess) or asyncio — NO blocking socket loop.
        2. Wildcard calibration via random subdomain resolve.
        3. Content signature delegated to httpx-toolkit (if available).
        """
        logs = []
        wildcard_ips = set()

        # ── Calibrate wildcard IPs ──
        logs.append("  -> Calibrating wildcard IPs...")
        for _ in range(3):
            rand_str = ''.join(random.choices(string.ascii_lowercase, k=12))
            test_sub = f"{rand_str}.{domain}"
            try:
                ip = socket.gethostbyname(test_sub)
                wildcard_ips.add(ip)
            except (socket.gaierror, socket.timeout, OSError):
                pass
        if wildcard_ips:
            logs.append(f"  -> Wildcard IPs detected: {wildcard_ips}")

        # ── Phase 1: Bulk DNS resolve via dnsx or asyncio ──
        resolved = {}  # {subdomain: ip}
        has_dnsx = shutil.which("dnsx")

        if has_dnsx:
            logs.append("  -> Resolving DNS via dnsx (fast bulk)...")
            try:
                input_data = '\n'.join(subdomains)
                proc = subprocess.run(
                    ["dnsx", "-silent", "-resp", "-no-color"],
                    input=input_data, capture_output=True, text=True, timeout=60
                )
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # dnsx -resp format: "sub.domain.com [1.2.3.4]"
                    parts = line.split()
                    if len(parts) >= 2:
                        sub = parts[0].strip()
                        ip = parts[1].strip('[]')
                        if ip not in wildcard_ips:
                            resolved[sub] = ip
                    elif len(parts) == 1:
                        # dnsx without -resp just prints live subdomains
                        resolved[parts[0]] = "unresolved"
            except subprocess.TimeoutExpired:
                logs.append("  [!] dnsx timeout (60s). Using partial results.")
            except Exception as e:
                logs.append(f"  [!] dnsx error: {e}. Falling back to asyncio.")
                has_dnsx = False  # Trigger fallback

        if not has_dnsx:
            logs.append("  -> Resolving DNS via asyncio (concurrent)...")
            resolved = self._async_resolve(subdomains, wildcard_ips)

        logs.append(f"  -> DNS resolved: {len(resolved)} live subdomains (filtered {len(subdomains) - len(resolved)} wildcard/dead)")

        # ── Phase 2: Content signature via httpx-toolkit ──
        has_httpx = shutil.which("httpx-toolkit") or shutil.which("httpx")
        live_assets = []

        if has_httpx and len(resolved) > 0:
            httpx_bin = shutil.which("httpx-toolkit") or shutil.which("httpx")
            logs.append(f"  -> Running {os.path.basename(httpx_bin)} for content signature filtering...")
            try:
                input_subs = '\n'.join(resolved.keys())
                proc = subprocess.run(
                    [httpx_bin, "-silent", "-no-color", "-status-code", "-content-length", "-title",
                     "-timeout", "5", "-threads", "30", "-no-fallback"],
                    input=input_subs, capture_output=True, text=True, timeout=120
                )
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    # Parse httpx output: URL [status] [length] [title]
                    url_part = line.split()[0] if line.split() else line
                    from urllib.parse import urlparse as _up
                    parsed_host = _up(url_part).netloc or url_part
                    # Remove port from netloc
                    host_clean = parsed_host.split(':')[0] if ':' in parsed_host else parsed_host
                    ip = resolved.get(host_clean, resolved.get(parsed_host, ""))
                    if host_clean:
                        live_assets.append({"sub": host_clean, "ip": ip, "httpx_line": line})

                    if len(live_assets) >= 1000:
                        logs.append("  [!] Hit 1000 live subdomains limit.")
                        break
            except subprocess.TimeoutExpired:
                logs.append("  [!] httpx-toolkit timeout (120s). Using DNS-only results.")
            except Exception as e:
                logs.append(f"  [!] httpx-toolkit error: {e}. Using DNS-only results.")

        # Fallback: if httpx unavailable or produced no results, use DNS-resolved list
        if not live_assets:
            for sub, ip in list(resolved.items())[:1000]:
                live_assets.append({"sub": sub, "ip": ip})

        return live_assets, logs

    def _async_resolve(self, subdomains: list, wildcard_ips: set, max_concurrent: int = 100) -> dict:
        """
        [V1.0] Asyncio-based concurrent DNS resolution.
        Replaces sequential socket.gethostbyname loop.
        """
        resolved = {}
        loop = None

        async def _resolve_one(sub, sem):
            async with sem:
                try:
                    loop_inner = asyncio.get_event_loop()
                    ip = await loop_inner.run_in_executor(None, socket.gethostbyname, sub)
                    if ip not in wildcard_ips:
                        resolved[sub] = ip
                except (socket.gaierror, socket.timeout, OSError):
                    pass

        async def _resolve_all():
            sem = asyncio.Semaphore(max_concurrent)
            tasks = [_resolve_one(sub, sem) for sub in subdomains]
            await asyncio.gather(*tasks, return_exceptions=True)

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(asyncio.run, _resolve_all())
                    future.result(timeout=90)
            else:
                loop.run_until_complete(_resolve_all())
        except RuntimeError:
            asyncio.run(_resolve_all())
        except Exception:
            pass

        return resolved

    def _calc_sig(self, r):
        if not r: return {"hash": None}
        m = re.search(r'<title[^>]*>(.*?)</title>', r.text, re.I | re.S)
        title = m.group(1).strip() if m else ""
        content_len_tier = len(r.text) // 100
        # Signature hash dựa trên status, title, và độ dài xấp xỉ
        hash_str = f"{r.status_code}|{title}|{content_len_tier}".encode()
        return {"hash": hashlib.md5(hash_str).hexdigest()}
