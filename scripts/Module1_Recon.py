#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MODULE 1: RECON FRAMEWORK (V1.0 — 2026 RED TEAM DOCTRINE)
# Scanner Router Architecture: mỗi mode gọi đúng pipeline riêng.
# Nmap chỉ dùng cho Network Layer. Web/Cloud dùng Nuclei/Katana/httpx.

import os
import sys
import json
import logging
import argparse
import asyncio
import socket
import subprocess
import shutil
import urllib3
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Đảm bảo python hiểu thư mục gốc PenLabs
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Import Blacklist Engine và Plugin Registry
from utils.blacklist import BlacklistFilter
from core.registry import PluginRegistry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from utils.colors import Colors
from utils.url_dedup import URLDeduplicator
from utils.passive_data_miner import PassiveDataMiner


def _load_subdomain_scan_result(entry):
    if isinstance(entry, str) and os.path.exists(entry):
        try:
            with open(entry, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return entry if isinstance(entry, dict) else {}


def _summarize_subdomain_vulns(results) -> dict:
    summary = {
        "total_subdomains_scanned": len(results or []),
        "total_xss": 0,
        "total_nuclei": 0,
        "total_sqli": 0,
        "total_ssrf": 0,
        "total_blind_xss": 0,
        "total_mass_assignment": 0,
    }

    for entry in results or []:
        data = _load_subdomain_scan_result(entry)
        dast_findings = data.get("dast_findings", [])
        if dast_findings:
            for finding in dast_findings:
                if not isinstance(finding, dict):
                    continue
                category = str(finding.get("category", "")).lower()
                if category in ("xss", "blind_xss", "sqli", "ssrf", "mass_assignment"):
                    key = f"total_{category}"
                    if key in summary:
                        summary[key] += 1
        else:
            summary["total_xss"] += len(data.get("xss_findings", []))
            summary["total_sqli"] += len(data.get("sqli_findings", []))
            summary["total_ssrf"] += len(data.get("ssrf_findings", []))

        summary["total_nuclei"] += len(data.get("nuclei_findings", []))

    return summary




class Logger:
    def __init__(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        self.log_file = os.path.join(out_dir, "recon.log")
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s [%(levelname)s] %(message)s",
                            handlers=[logging.FileHandler(self.log_file)])
        self.console = logging.StreamHandler()
        logging.getLogger().addHandler(self.console)
        logging.getLogger("urllib3").setLevel(logging.ERROR)

    def _print(self, msg, color=Colors.ENDC):
        print(f"{color}{msg}{Colors.ENDC}")
        logging.info(msg)

    def info(self, msg): self._print(f"[*] {msg}", Colors.BLUE)
    def phase(self, msg): self._print(f"\n🚀 === {msg} ===", Colors.HEADER)
    def success(self, msg): self._print(f"✅ {msg}", Colors.GREEN)
    def warning(self, msg): self._print(f"⚠️  {msg}", Colors.WARNING)
    def error(self, msg): self._print(f"❌ {msg}", Colors.FAIL)
    def debug(self, msg): 
        print(f"{Colors.BLUE}[DEBUG] {msg}{Colors.ENDC}")
        logging.debug(msg)


class OSINTCollector:
    def __init__(self, logger, vt_key="", chaos_key=""):
        self.log = logger
        self.vt_key = vt_key
        self.chaos_key = chaos_key

    async def get_amass(self, target, out_dir):
        """[V1.0] Async wrapper cho OWASP Amass passive OSINT."""
        self.log.info(f"Querying OWASP Amass (passive) for {target}...")
        plugin = PluginRegistry.get("Amass")
        if plugin and plugin.check_installed():
            loop = asyncio.get_running_loop()
            amass_out = os.path.join(out_dir, "raw", "amass")
            
            # [HIGH-03 FIX] Wait up to 30m for Amass results
            result = await loop.run_in_executor(None, plugin.run, target, amass_out, 1800)
            if not result or not result.get("subdomains"):
                self.log.warning(f"[Amass] Không tìm thấy kết quả hoặc lỗi thực thi cho {target} sau 1800s.")
            return result
        self.log.warning("[Amass] Not installed — Skip.")
        return {}

    async def get_theharvester(self, target, out_dir):
        """[V1.0] Async wrapper cho theHarvester OSINT scraper."""
        self.log.info(f"Querying theHarvester for {target}...")
        plugin = PluginRegistry.get("TheHarvester")
        if plugin and plugin.check_installed():
            loop = asyncio.get_running_loop()
            harvester_out = os.path.join(out_dir, "raw", "theharvester")
            return await loop.run_in_executor(None, plugin.run, target, harvester_out)
        self.log.warning("[theHarvester] Not installed — Skip.")
        return {}

    async def get_shodan_internetdb(self, ip):
        """Async wrapper cho Shodan InternetDB plugin."""
        self.log.info(f"Querying Shodan InternetDB for {ip} via Plugin...")
        plugin = PluginRegistry.get("ShodanInternetDB")
        if plugin:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, plugin.run, ip)
        return {}

    async def get_virustotal(self, ip):
        """Async wrapper cho VirusTotal plugin."""
        self.log.info(f"Querying VirusTotal API for {ip} via Plugin...")
        plugin = PluginRegistry.get("VirusTotal")
        if plugin:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, plugin.run, ip, self.vt_key)
        self.log.error("VirusTotal Plugin not registered!")
        return {}

    async def start_interactsh(self, out_dir):
        """
        [V1.0] Khởi động interactsh-client chạy nền — thu thập OOB DNS/HTTP callbacks.
        
        Nuclei sử dụng Interactsh natively qua tag 'oast', nhưng method này
        cho phép chạy interactsh-client riêng để inject OOB payload thủ công
        vào headers/params trong các request tùy chỉnh.
        
        Returns:
            dict: {"url": "xxx.oast.site", "process": subprocess, "log_file": path}
        """
        if not shutil.which("interactsh-client"):
            self.log.warning("interactsh-client not installed. Đang tự động cài đặt...")
            try:
                subprocess.run(["go", "install", "-v", "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"], check=True)
                os.environ["PATH"] += os.pathsep + os.path.expanduser("~/go/bin")
            except Exception as e:
                self.log.error(f"Failed to auto-install interactsh-client: {e}")
            if not shutil.which("interactsh-client"):
                self.log.info("  → Cài đặt thủ công: go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest")
                return {}

        os.makedirs(out_dir, exist_ok=True)
        log_file = os.path.join(out_dir, "interactsh_callbacks.jsonl")
        
        self.log.info("Starting interactsh-client background daemon...")
        try:
            proc = await asyncio.create_subprocess_exec(
                "interactsh-client", "-json", "-o", log_file, "-v",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            # [BUG-002 FIX] Đọc stderr để lấy OOB URL — dùng regex chính xác cho interactsh subdomain
            import re
            oob_url = ""
            # Pattern: random-chars.oast.fun / .oast.site / .oast.live / .oast.me / .interact.sh / .oast.online
            _oob_pattern = re.compile(r'([a-z0-9]{10,}\.(oast\.(fun|site|live|me|online|pro|eu|asia|us)|interact\.sh))', re.IGNORECASE)
            try:
                for _ in range(30):
                    line = await asyncio.wait_for(proc.stderr.readline(), timeout=3)
                    output = line.decode('utf-8', errors='ignore').strip()
                    if not output:
                        continue
                    # Tìm OOB URL bằng regex chính xác
                    match = _oob_pattern.search(output)
                    if match:
                        oob_url = match.group(1)
                        break
                    # Fallback: dòng chứa "[INF]" và URL-like token (không phải projectdiscovery.io)
                    if "[INF]" in output and "version" not in output.lower():
                        for token in reversed(output.split()):
                            if "." in token and len(token) > 15 and "projectdiscovery" not in token.lower() and "github" not in token.lower():
                                oob_url = token
                                break
                        if oob_url:
                            break
            except asyncio.TimeoutError:
                pass
            
            if oob_url:
                self.log.success(f"Interactsh OOB URL: {oob_url}")
            else:
                self.log.warning("Interactsh started nhưng không lấy được OOB URL.")
            
            self._interactsh_proc = proc
            self._interactsh_log = log_file
            
            return {
                "url": oob_url,
                "process": proc,
                "log_file": log_file,
            }
        except Exception as e:
            self.log.warning(f"interactsh-client failed to start: {e}")
            return {}

    async def stop_interactsh(self):
        """[V1.0] Dừng interactsh-client daemon và parse callbacks."""
        callbacks = []
        proc = getattr(self, '_interactsh_proc', None)
        log_file = getattr(self, '_interactsh_log', None)
        
        if proc:
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=5)
            except Exception:
                proc.kill()
        
        # Parse collected callbacks
        if log_file and os.path.exists(log_file):
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            try:
                                data = json.loads(line)
                                callbacks.append({
                                    "protocol": data.get("protocol", ""),
                                    "unique_id": data.get("unique-id", ""),
                                    "full_id": data.get("full-id", ""),
                                    "raw_request": data.get("raw-request", "")[:500],
                                    "remote_address": data.get("remote-address", ""),
                                    "timestamp": data.get("timestamp", ""),
                                })
                            except json.JSONDecodeError:
                                continue
            except Exception:
                pass
        
        if callbacks:
            self.log.success(f"Interactsh thu thập được {len(callbacks)} OOB callbacks!")
        
        return callbacks


# ═══════════════════════════════════════════════════════════════════
# V1.0-FIX: ScannerRouter extracted to core/scanner_router.py
# Reduces Module1 from ~4000 lines to ~1500 lines.
# All _route_* methods and scan orchestration logic live there.
# ═══════════════════════════════════════════════════════════════════
from core.scanner_router import ScannerRouter




class ReconOrchestrator:
    def __init__(self, target, out_dir, out_file, mode, vt_key, chaos_key="", 
                 blacklist_file="", stealth_recon=False, proxy="", cookies="", headers=None,
                 visual_recon=False, rate_limit=150, delay="",
                 auth_userA="", auth_userB="",
                 subdomain_scan=True, use_internetdb=False, stealth_discovery=True, osint_enabled=True, **kwargs):
        self.target = target
        self.out_dir = out_dir
        self.out_file = out_file
        self.mode = mode
        self.stealth_recon = stealth_recon
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.delay = delay
        self.vt_key = vt_key
        self.chaos_key = chaos_key
        self.cookies = cookies
        self.headers = headers or {}
        self.visual_recon = visual_recon
        self.subdomain_scan = subdomain_scan
        self.stealth_discovery = stealth_discovery
        self.osint_enabled = osint_enabled
        self.use_internetdb = use_internetdb

        # V1.0: BOLA Engine tokens
        self.auth_userA = auth_userA
        self.auth_userB = auth_userB

        self.log = Logger(self.out_dir)
        self.osint = OSINTCollector(self.log, vt_key, chaos_key)
        # [V1.0] Core New Options
        self.proxy_file = kwargs.get("proxy_file")
        self.use_playwright = kwargs.get("use_playwright", False)
        self.sqlmap_relay = kwargs.get("sqlmap_relay", False)
        self.bola_engine = kwargs.get("bola_engine", False)
        self.chunk_size = kwargs.get("chunk_size", 20)
        self.seed_subs_file = kwargs.get("seed_subs")
        self.tor_route = kwargs.get("tor_route", False)

        #  Khởi tạo các Core Services cho tiến trình Module 1
        if self.proxy_file:
            from utils.proxy_manager import ProxyManager
            ProxyManager(proxy_file=self.proxy_file)
            
        auth_config_path = kwargs.get("auth_config") # Cần thêm vào argparse
        if auth_config_path and os.path.exists(auth_config_path):
            try:
                import json
                with open(auth_config_path, 'r') as f:
                    auth_data = json.load(f)
                from utils.auth_manager import AuthManager
                AuthManager(auth_config=auth_data)
            except Exception:
                pass

        self.log = Logger(self.out_dir)

        #  Khởi tạo Checkpoint Manager cục bộ để Resume tool-level
        from utils.scope_engine import ScopeEngine
        permissive_flag = kwargs.get('permissive', False)
        confirm_permissive_flag = kwargs.get('confirm_permissive', False)
        
        # Đảm bảo reset instance trước khi tạo mới để tránh bị dính cấu hình cũ
        ScopeEngine.reset_instance()
        
        # Nếu đã gọi explicitly, ta tạo instance mới trực tiếp thay vì dựa vào auto_load.
        if permissive_flag and confirm_permissive_flag:
            self.scope = ScopeEngine(permissive=True, confirm_permissive=True)
            ScopeEngine._instance = self.scope
        else:
            self.scope = ScopeEngine.instance()
        
        from core.checkpoint import CheckpointManager
        self.ckpt = CheckpointManager(session_dir=self.out_dir, target=self.target)

        # Support explicit Tor routing, proxy file, or direct proxy URL.
        # STEALTH-RECON no longer implies Tor; Tor must be selected explicitly.
        pf = self.proxy_file or self.proxy
        if self.tor_route:
            tor_proxy_file = os.path.join(self.out_dir, "tor_proxy.txt")
            with open(tor_proxy_file, "w", encoding="utf-8") as f:
                f.write("socks5h://127.0.0.1:9050\n")
            pf = tor_proxy_file
            self.log.info(f"  [Tor] TOR-ROUTE enabled: routing supported HTTP tooling via Tor ({pf})")
        elif self.proxy and not self.proxy.startswith(("http", "socks")) and os.path.exists(self.proxy):
            pf = self.proxy
        elif self.proxy and not self.proxy.startswith(("http", "socks")) and self.proxy == "True" and os.path.exists("proxies.txt"):
            pf = "proxies.txt"
        
        self.scanner = ScannerRouter(
            self.out_dir, self.log, cookies=self.cookies, headers=self.headers,
            proxy_file=pf, stealth_recon=self.stealth_recon, rate_limit=self.rate_limit,
            delay=self.delay, auth_userA=auth_userA, auth_userB=auth_userB,
            checkpoint=self.ckpt,
            # [V1.0] Pass new flags
            use_playwright=self.use_playwright,
            sqlmap_relay=self.sqlmap_relay,
            bola_engine=self.bola_engine,
            chunk_size=self.chunk_size,
            mode=self.mode
        )
        # V1.0: Forward use_internetdb flag to ScannerRouter for infra-smash mode
        self.scanner._use_internetdb = self.use_internetdb

        # Init Blacklist Engine
        self.blacklist = BlacklistFilter(blacklist_file)

    def check_typo(self, target):
        """[V1.0] Check for common typos in target domains (e.g. dsc.vn vs dcs.vn)."""
        typos = {
            "dsc.vn": "dcs.vn",
            "dcs.vn": "dsc.vn",
            "gov.vn": "org.vn",
        }
        for typo, correct in typos.items():
            if target.endswith(typo):
                alt_target = target.replace(typo, correct)
                # We don't return here yet, just log a warning
                self.log.warning(f"PHÁT HIỆN TYPO TIỀM NĂNG: Bạn có ý định quét '{alt_target}' (Communism Party) thay vì '{target}' (Digital Security) không?")
                return alt_target
        return None

    async def resolve(self, domain):
        """Async DNS resolution."""
        try:
            loop = asyncio.get_running_loop()
            addrinfo = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            if addrinfo:
                return addrinfo[0][4][0]
            return None
        except Exception as e:
            # logging.warning(f"DNS resolution failed for {domain}: {e}")
            return None

    async def validate_osint_with_active_scan(self, ip, osint_ports, osint_tech):
        """
        Phase 1: Cross-Check OSINT với Active Scan.
        Trả về dict chứa kết quả xác thực port & fingerprint.
        """
        validation = {
            "verified_ports": set(),
            "dead_ports": set(),
            "active_tech": {},   # {port: {"web_server": ..., "tech": [...]}}
            "version_conflicts": [],
        }

        if not osint_ports:
            return validation

        loop = asyncio.get_running_loop()

        # Step 1: Probe ports bằng httpx (ưu tiên) hoặc naabu
        httpx_plugin = PluginRegistry.get("Httpx")
        naabu_plugin = PluginRegistry.get("Naabu")

        httpx_results = []
        if httpx_plugin and httpx_plugin.check_installed():
            self.log.info(f"[VALIDATION] httpx probing {len(osint_ports)} OSINT ports...")
            httpx_dir = os.path.join(self.out_dir, "raw", "httpx_validate")
            pf = self.scanner.proxy_file
            httpx_results = await loop.run_in_executor(
                None, httpx_plugin.probe_from_ports, ip, list(osint_ports), httpx_dir, self.scanner._get_auth_headers(), pf
            )
            for r in httpx_results:
                port = r.get("port", 80)
                validation["verified_ports"].add(port)
                validation["active_tech"][port] = {
                    "web_server": r.get("web_server", ""),
                    "tech": r.get("tech", []),
                    "title": r.get("title", ""),
                    "status_code": r.get("status_code", 0),
                }

        #  Nmap fallback — array-based, không shell=True
        non_http_ports = [p for p in osint_ports if p not in validation["verified_ports"]]
        nmap_plugin = PluginRegistry.get("Nmap")
        if nmap_plugin and non_http_ports:
            clean_ports = ScannerRouter._sanitize_ports(non_http_ports)
            self.log.info(f"[VALIDATION] Nmap verifying {len(clean_ports)} remaining ports...")
            try:
                alive = await self.scanner._safe_nmap_verify(ip, clean_ports, "1m", mode=getattr(self, 'mode', 'sniper'))
            except Exception:
                alive = []
            for p in alive:
                validation["verified_ports"].add(p)

        # Mark dead ports
        validation["dead_ports"] = set(osint_ports) - validation["verified_ports"]

        # Step 2: Fingerprint Verification — So sánh OSINT tech vs Active tech
        if osint_tech and validation["active_tech"]:
            osint_versions = self._extract_versions_from_cpe(osint_tech)
            for port, active_info in validation["active_tech"].items():
                active_server = active_info.get("web_server", "").lower()
                for product, osint_ver in osint_versions.items():
                    if product in active_server:
                        # Tìm phiên bản trong Active banner
                        import re
                        active_ver_match = re.search(r'(\d+\.\d+\.?\d*)', active_server)
                        active_ver = active_ver_match.group(1) if active_ver_match else ""
                        if active_ver and osint_ver and active_ver != osint_ver:
                            validation["version_conflicts"].append({
                                "port": port,
                                "product": product,
                                "osint_version": osint_ver,
                                "active_version": active_ver,
                            })

        verified_count = len(validation["verified_ports"])
        dead_count = len(validation["dead_ports"])
        conflicts = len(validation["version_conflicts"])
        self.log.success(f"[VALIDATION] Ports: {verified_count} verified, {dead_count} dead. Version conflicts: {conflicts}")

        return validation

    def _extract_versions_from_cpe(self, cpe_list):
        """Trích xuất product:version từ danh sách CPE strings."""
        versions = {}
        for cpe in cpe_list:
            parts = cpe.lower().split(":")
            if len(parts) >= 6:
                product = parts[4]  # e.g., http_server, php, openssh
                version = parts[5] if parts[5] != "*" else ""
                if product and version:
                    versions[product] = version
        return versions

    def merge_results(self, ip, shodan_data, vt_data, osint_infra_data, scan_data, stealth_data=None, validation=None, subdomain_scan_results=None):
        """Hợp nhất dữ liệu từ tất cả sources vào profile chuẩn — V1.0 Open-Source OSINT."""
        stealth_data = stealth_data or {}
        osint_infra_data = osint_infra_data or {}
        validation = validation or {}
        subdomain_scan_results = subdomain_scan_results or []
        
        tech_stack = set(shodan_data.get("cpes", []))
        # [V1.0] Merge components từ Amass + theHarvester
        tech_stack.update(osint_infra_data.get("components", []))
        
        profile = {
            "target": self.target,
            "ip": ip,
            "open_ports": [],
            "cve_candidates": [],
            # Phase 1: Tách rõ Verified vs Historical
            "verified_findings": [],
            "historical_osint": [],
            "tech_stack": list(tech_stack),
            "device_tags": shodan_data.get("tags", []),
            "vt_organization": vt_data.get("as_owner", ""),
            "vt_reputation": vt_data.get("reputation", 0),
            # 2026 Doctrine: Nuclei findings
            "nuclei_findings": scan_data.get("nuclei_findings", []),
            "web_urls": scan_data.get("web_urls", []),
            "cloud_findings": scan_data.get("cloud_findings", {}),
            "os_detection": scan_data.get("os_detection", []),
            "scan_mode": self.mode,
            
            # [V1.0-SYNC] New Discovery Fields Integration
            "js_secrets": scan_data.get("js_secrets", []),
            "emails": scan_data.get("emails", []),
            "hidden_params": scan_data.get("hidden_params", {}),
            "metadata": scan_data.get("metadata", {}),
            "api_endpoints": scan_data.get("api_endpoints", []),
            "xss_findings": scan_data.get("xss_findings", []),
            "sqli_findings": scan_data.get("sqli_findings", []),
            "ssrf_findings": scan_data.get("ssrf_findings", []),
            "cors_findings": scan_data.get("cors_findings", scan_data.get("cors_issues", [])),
            "cors_issues": scan_data.get("cors_issues", scan_data.get("cors_findings", [])),
            "graphql_findings": scan_data.get("graphql_findings", []),
            "graphql": scan_data.get("graphql", {}),
            "open_redirect_findings": scan_data.get("open_redirect_findings", []),
            "crlf_findings": scan_data.get("crlf_findings", []),
            "secrets": scan_data.get("secrets", scan_data.get("js_secrets", [])),
            "bypass_403": scan_data.get("bypass_403", []),
            "bola_findings": scan_data.get("bola_findings", {}),
            "dast_findings": scan_data.get("dast_findings", []),
            "summary": scan_data.get("summary", {}),
            
            # Phase 1: Validation metadata
            "validation_summary": {
                "verified_ports": list(validation.get("verified_ports", set())),
                "dead_ports": list(validation.get("dead_ports", set())),
                "version_conflicts": validation.get("version_conflicts", []),
            },
            # V1.0: Recursive Subdomain Scan Results
            "subdomain_scan_results": subdomain_scan_results,
            "subdomain_vuln_summary": _summarize_subdomain_vulns(subdomain_scan_results),
        }

        # Merge Subdomains & Endpoints
        raw_subs = stealth_data.get("subdomains", []) + scan_data.get("subdomains", [])
        sub_list = []
        for s in raw_subs:
            if isinstance(s, dict):
                sub_val = s.get("sub", "") or s.get("subdomain", "")
                if sub_val and sub_val.strip():
                    sub_list.append(sub_val.strip())
            elif isinstance(s, str) and s.strip():
                sub_list.append(s.strip())
        profile["subdomains"] = list(set(sub_list))
        
        current_web_urls = profile.get("web_urls", [])
        if not isinstance(current_web_urls, list):
            current_web_urls = []
        new_endpoints = stealth_data.get("endpoints", [])
        if not isinstance(new_endpoints, list):
            new_endpoints = []
        
        # [V1.0] Smart URL Deduplication trước khi merge — loại bỏ URL trùng logic
        merged_urls = current_web_urls + new_endpoints
        raw_url_count = len(merged_urls)
        profile["web_urls"] = URLDeduplicator.deduplicate(merged_urls)
        if raw_url_count > len(profile["web_urls"]):
            logging.info(f"[URL-DEDUP] Merged web_urls: {raw_url_count} → {len(profile['web_urls'])} (loại {raw_url_count - len(profile['web_urls'])} duplicates)")
        profile["waf_info"] = stealth_data.get("waf_info", {"detected": False, "name": "None"})
        profile["tls_fingerprint"] = stealth_data.get("tls_fingerprint", "")

        verified_ports = validation.get("verified_ports", set())
        dead_ports = validation.get("dead_ports", set())
        active_tech = validation.get("active_tech", {})

        # --- CVE CANDIDATES: Phân loại theo nguồn + validation ---

        # OSINT CVEs — confidence dựa vào kết quả validation
        for cve in shodan_data.get("vulns", []):
            # Nếu có validation data: port chết → hạ confidence xuống 0.1
            if dead_ports and not verified_ports:
                # Toài bộ OSINT ports chết → OSINT data cực kỳ cũ
                entry = {"cve": cve, "confidence": 0.1, "source": "OSINT (Unverified)", "verified": False}
                profile["historical_osint"].append(entry)
            elif verified_ports:
                entry = {"cve": cve, "confidence": 0.5, "source": "OSINT", "verified": False}
                profile["cve_candidates"].append(entry)
            else:
                # Không có validation data → giữ confidence mặc định
                entry = {"cve": cve, "confidence": 0.5, "source": "OSINT", "verified": False}
                profile["cve_candidates"].append(entry)

        # NSE CVEs (từ Nmap) — Active Scan = Verified
        for nse_cve in scan_data.get("nse_cves", []):
            existing = [c['cve'] for c in profile['cve_candidates']]
            nse_cve["verified"] = True
            if nse_cve['cve'] not in existing:
                profile["cve_candidates"].append(nse_cve)
                profile["verified_findings"].append(nse_cve)
            else:
                # Upgrade existing OSINT entry to verified
                for c in profile["cve_candidates"]:
                    if c["cve"] == nse_cve["cve"]:
                        c["confidence"] = max(c["confidence"], nse_cve.get("confidence", 0.9))
                        c["verified"] = True
                        c["source"] = nse_cve.get("source", "Nmap NSE")
                profile["verified_findings"].append(nse_cve)

        # Nuclei CVEs — High confidence (0.95) = Verified
        for finding in scan_data.get("nuclei_findings", []):
            cve_id = finding.get("cve_id", "")
            template_id = finding.get("template_id", "")
            identifier = cve_id if cve_id else f"NUCLEI-{template_id}"

            if identifier and identifier not in [c['cve'] for c in profile['cve_candidates']]:
                entry = {
                    "cve": identifier,
                    "port": finding.get("port", 80),
                    "confidence": 0.95,
                    "source": "Nuclei",
                    "severity": finding.get("severity", "unknown"),
                    "matched_at": finding.get("matched_at", ""),
                    "nse_script": f"nuclei:{template_id}",
                    "verified": True,
                }
                profile["cve_candidates"].append(entry)
                profile["verified_findings"].append(entry)

        # V1.0 Custom Plugin Findings (SSRF, CRLF, SQLi, etc.) -> CVE candidates
        plugin_mappings = {
            "ssrf_findings": ("SSRF-PROBE", 0.95),
            "crlf_findings": ("CRLF-INJECTION", 0.90),
            "sqli_findings": ("SQLI-SCANNER", 0.95),
            "xss_findings": ("XSS-DALFOX", 0.90),
            "bola_findings": ("BOLA-IDOR", 0.95),
            "race_condition_findings": ("RACE-CONDITION", 0.85),
            "cors_issues": ("CORS-MISCONFIG", 0.85),
        }
        for key, (prefix, conf) in plugin_mappings.items():
            for finding in scan_data.get(key, []):
                if isinstance(finding, dict):
                    sev = finding.get("severity", "high").lower()
                    entry_conf = 0.99 if sev == "critical" else conf
                    
                    param = finding.get("param") or finding.get("payload") or "unknown"
                    if len(str(param)) > 20: param = str(param)[:20]
                    cve_name = f"{prefix}-{param}"
                    
                    entry = {
                        "cve": cve_name,
                        "port": 80,
                        "confidence": entry_conf,
                        "source": "CustomPlugin",
                        "severity": sev,
                        "matched_at": finding.get("url", finding.get("endpoint", "")),
                        "verified": True,
                    }
                    profile["cve_candidates"].append(entry)
                    profile["verified_findings"].append(entry)

        # Cloud findings → CVE candidates (Active = Verified)
        cloud = scan_data.get("cloud_findings", {})
        for bucket in cloud.get("bucket_findings", []):
            if bucket.get("status") == "PUBLIC_READ":
                entry = {
                    "cve": f"CLOUD-{bucket['provider']}-PUBLIC-BUCKET",
                    "port": 443,
                    "confidence": 0.95,
                    "source": "CloudDevops",
                    "severity": "critical",
                    "verified": True,
                }
                profile["cve_candidates"].append(entry)
                profile["verified_findings"].append(entry)
        for takeover in cloud.get("takeover_candidates", []):
            entry = {
                "cve": f"SUBDOMAIN-TAKEOVER-{takeover.get('service', 'unknown')}",
                "port": 80,
                "confidence": 0.9 if takeover.get("status") == "VULNERABLE" else 0.7,
                "source": "CloudDevops",
                "severity": "critical" if takeover.get("status") == "VULNERABLE" else "high",
                "verified": True,
            }
            profile["cve_candidates"].append(entry)
            profile["verified_findings"].append(entry)
        for devops in cloud.get("devops_exposed", []):
            entry = {
                "cve": f"DEVOPS-EXPOSED-{devops['service'].replace(' ', '-')}",
                "port": devops["port"],
                "confidence": 0.9,
                "source": "CloudDevops",
                "severity": devops.get("severity", "high"),
                "verified": True,
            }
            profile["cve_candidates"].append(entry)
            profile["verified_findings"].append(entry)

        # [V1.0] OSINT Infrastructure Data -> Merge subdomains/IPs/ASN
        osint_subs = osint_infra_data.get("subdomains", [])
        osint_emails = osint_infra_data.get("emails", [])
        osint_asn = osint_infra_data.get("asn_info", [])
        if osint_subs:
            profile["osint_subdomains"] = osint_subs[:200]  # Cap để tránh JSON quá lớn
        if osint_emails:
            profile["osint_emails"] = osint_emails[:50]
        if osint_asn:
            profile["asn_info"] = osint_asn

        # --- Fingerprint Verification: Boost hoặc hạ confidence ---
        version_conflicts = validation.get("version_conflicts", [])
        conflict_products = {vc["product"] for vc in version_conflicts}

        for candidate in profile["cve_candidates"]:
            if candidate.get("source", "").startswith("OSINT") and not candidate.get("verified"):
                # Nếu có version conflict → hạ thêm
                if conflict_products:
                    candidate["confidence"] = min(candidate["confidence"], 0.2)
                    candidate["version_conflict"] = True

        # Merge ports
        osint_ports = set(shodan_data.get("ports", []))
        osint_ports.update(osint_infra_data.get("ports", []))
        scan_ports = {p['port']: p for p in scan_data.get('ports', [])}

        merged_ports = {}
        for port, p_info in scan_ports.items():
            merged_ports[port] = {
                "port": port,
                "service": p_info['service'],
                "version": p_info.get('version', ''),
                "confidence": 1.0,
                "verified": True,
                #  Preserve tech/title từ httpx propagation cho Smart CPE Filter (M2)
                "tech": p_info.get('tech', []),
                "title": p_info.get('title', ''),
                # [BUG-009 FIX] Preserve CPEs từ Nmap cho M2 version-range matching
                "cpes": p_info.get('cpes', []),
            }
            # [BUG-009 FIX] Enrich tech_stack từ CPEs (Nmap XML)
            for cpe in p_info.get('cpes', []):
                tech_stack.add(cpe)

        for port in osint_ports:
            if port not in merged_ports:
                # Phase 1: OSINT port confidence phụ thuộc validation
                if port in dead_ports:
                    merged_ports[port] = {
                        "port": port,
                        "service": "unknown",
                        "version": "",
                        "confidence": 0.1,
                        "verified": False,
                    }
                elif port in verified_ports:
                    active_info = active_tech.get(port, {})
                    merged_ports[port] = {
                        "port": port,
                        "service": active_info.get("web_server", "unknown"),
                        "version": active_info.get("web_server", ""),
                        "confidence": 0.95,
                        "verified": True,
                    }
                else:
                    merged_ports[port] = {
                        "port": port,
                        "service": "unknown",
                        "version": "",
                        "confidence": 0.3,
                        "verified": False,
                    }

        profile["open_ports"] = list(merged_ports.values())
        return profile

    async def start(self):
        """Main async orchestrator — Scanner Router Edition."""
        self.log.phase(f"TARGET: {self.target} (MODE: {self.mode.upper()}) — 2026 Doctrine")

        # ------ [ BLACKLIST OPSEC CHECK ] ------
        if not self.blacklist.is_allowed(self.target):
            self.log.error(f"[BLACKLIST] Mục tiêu '{self.target}' nằm trong Blacklist! Đã huỷ bỏ.")
            with open(self.out_file, "w") as f: json.dump([], f)
            return

        ip = await self.resolve(self.target)
        if not ip:
            self.log.warning(f"DNS resolution failed for {self.target}. Pipeline sẽ tiếp tục với OSINT (Passive Mode).")
            # Kiểm tra typo
            alt = self.check_typo(self.target)
            if alt:
                self.log.info(f"Gợi ý: Thử chạy lại với mục tiêu '{alt}' nếu đây là lỗi nhập liệu.")
        
        if ip and not self.blacklist.is_allowed(ip):
            self.log.error(f"[BLACKLIST] IP '{ip}' nằm trong Blacklist! Đã huỷ bỏ.")
            with open(self.out_file, "w") as f: json.dump([], f)
            return

        # ------ [ OSINT GATHERING — SONG SONG ] ------
        osint_results = {}
        if self.osint_enabled:
            self.log.phase("OSINT GATHERING (parallel)")
            
            # [V1.0] Tạo danh sách các task OSINT — Open Source Only
            osint_tasks = {
                "theharvester": self.osint.get_theharvester(self.target, self.out_dir),
            }
            if ip:
                osint_tasks["shodan"] = self.osint.get_shodan_internetdb(ip)
                osint_tasks["vt"] = self.osint.get_virustotal(ip)
            
            # Bỏ qua Amass nếu đang ở chế độ stealth
            if self.mode != "stealth":
                osint_tasks["amass"] = self.osint.get_amass(self.target, self.out_dir)

            # Chạy song song và gather kết quả
            task_names = list(osint_tasks.keys())
            task_coroutines = [osint_tasks[name] for name in task_names]
            results = await asyncio.gather(*task_coroutines, return_exceptions=True)

            # Trích xuất dữ liệu an toàn
            for i, name in enumerate(task_names):
                res = results[i]
                if isinstance(res, Exception):
                    self.log.error(f"Error in OSINT Task '{name}': {res}")
                    osint_results[name] = {}
                else:
                    osint_results[name] = res or {}
        else:
            self.log.info("OSINT gathering disabled (--no-osint).")

        shodan_data = osint_results.get("shodan", {})
        vt_data = osint_results.get("vt", {})
        amass_data = osint_results.get("amass", {})
        harvester_data = osint_results.get("theharvester", {})

        # [V1.0] Merge Amass + theHarvester into unified OSINT infrastructure dict
        osint_infra_data = {
            "subdomains": list(set(
                amass_data.get("subdomains", []) + harvester_data.get("subdomains", [])
            )),
            "ips": list(set(
                amass_data.get("ips", []) + harvester_data.get("ips", [])
            )),
            "emails": harvester_data.get("emails", []),
            "asn_info": amass_data.get("asn_info", []),
            "ports": amass_data.get("ports", []),
            "components": amass_data.get("components", []),
            "interesting_urls": harvester_data.get("interesting_urls", []),
        }

        if shodan_data: self.log.success("Shodan InternetDB data retrieved.")
        if vt_data: self.log.success("VirusTotal data retrieved.")
        if amass_data.get("subdomains"): self.log.success(f"OWASP Amass: {len(amass_data['subdomains'])} subdomains, {len(amass_data.get('ips', []))} IPs")
        if harvester_data.get("subdomains"): self.log.success(f"theHarvester: {len(harvester_data['subdomains'])} hosts, {len(harvester_data.get('emails', []))} emails")

        # ------ [ INTERACTSH OOB DAEMON — Start Before Scanning ] ------
        interactsh_data = {}
        from config import Config
        if Config.INTERACTSH_ENABLED and self.mode in ("web-vuln", "full-audit", "sniper", "api-breach", "infra-smash", "asset-discovery", "api-bounty"):
            interactsh_data = await self.osint.start_interactsh(self.out_dir)
            if interactsh_data.get("url"):
                self.log.success(f"Interactsh OOB daemon running — URL: {interactsh_data['url']}")

        # ------ [ SCANNER ROUTER — MODE-BASED DISPATCH ] ------
        self.log.phase(f"SCANNER ROUTER → {self.mode.upper()} PIPELINE")
        osint_ports = shodan_data.get("ports", [])
        scan_data = await self.scanner.run_scan(ip, self.target, 0, self.mode, osint_ports, [])

        # Log summary
        if scan_data.get('ports'):
            self.log.success(f"Scanner found {len(scan_data['ports'])} open ports/services.")
        nse_cves = scan_data.get('nse_cves', [])
        if nse_cves:
            self.log.success(f"Nmap NSE detected {len(nse_cves)} CVE(s).")
            for nc in nse_cves:
                self.log.info(f"  → {nc['cve']} (Port {nc['port']}, Script: {nc.get('nse_script','N/A')})")
        nuclei_findings = scan_data.get('nuclei_findings', [])
        if nuclei_findings:
            self.log.success(f"Nuclei detected {len(nuclei_findings)} vulnerability(ies)!")
            for nf in nuclei_findings[:10]:  # Chỉ hiển thị top 10
                self.log.info(f"  → [{nf.get('severity','?').upper()}] {nf.get('cve_id') or nf.get('template_id','')} at {nf.get('matched_at','')}")

        # ------ [ PHASE 1: DYNAMIC VALIDATION ] ------
        self.log.phase("DYNAMIC VALIDATION — Cross-Check OSINT vs Active Scan")
        osint_tech = list(set(shodan_data.get("cpes", [])))
        if self.mode != "stealth" and ip:
            validation = await self.validate_osint_with_active_scan(ip, osint_ports, osint_tech)
        else:
            validation = {"live_ports": [], "dead_ports": [], "tech_stack": []}

        # ------ [ INTERACTSH OOB DAEMON — Stop & Collect Callbacks ] ------
        if interactsh_data:
            oob_callbacks = await self.osint.stop_interactsh()
            if oob_callbacks:
                self.log.success(f"Interactsh collected {len(oob_callbacks)} OOB callbacks!")
                # Inject vào scan_data để M2 thấy
                scan_data.setdefault('interactsh_callbacks', []).extend(oob_callbacks)

        # ------ [ STEALTH RECON PHASE — Subdomain Hunting by Default for Domains ] ------
        stealth_data = {}
        import re
        target_is_domain = not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", self.target)
        
        # Enable by default for domains in most modes, or if explicitly requested
        should_run_stealth = self.stealth_discovery and (
            self.stealth_recon or (target_is_domain and self.mode in [
            "sniper", "web-vuln", "full-audit", "asset-discovery", "api-breach", "infra-smash",
            "api-bounty", "cloud-native"
            ])
        )
        
        if should_run_stealth:
            self.log.phase("STEALTH RECON (WAF/Subdomains)")
            net_plugin = PluginRegistry.get("StealthNet")
            hunter_plugin = PluginRegistry.get("SubdomainHunter")

            stealth_tasks = []

            if net_plugin:
                async def _stealth_net():
                    loop = asyncio.get_running_loop()
                    await loop.run_in_executor(None, net_plugin.run, self.proxy)
                    self.log.info("Checking WAF & TLS Fingerprint...")
                    has_waf, waf_name = await loop.run_in_executor(None, net_plugin.check_waf, f"http://{self.target}")
                    tls_fp = await loop.run_in_executor(None, net_plugin.get_tls_fp, self.target)
                    return {"waf_info": {"detected": has_waf, "name": waf_name}, "tls_fingerprint": tls_fp}
                stealth_tasks.append(_stealth_net())

            if hunter_plugin:
                async def _subdomain_hunt():
                    loop = asyncio.get_running_loop()
                    self.log.info(f"Hunting subdomains for {self.target}...")
                    api_keys = {"VIRUSTOTAL_KEY": self.vt_key, "CHAOS_KEY": self.chaos_key}
                    live_subs, urls, logs = await loop.run_in_executor(
                        None, hunter_plugin.run, self.target, api_keys, True
                    )
                    for log_line in logs:
                        self.log._print(f"    {log_line}", Colors.BLUE)
                    return {"subdomains": live_subs, "endpoints": urls}
                stealth_tasks.append(_subdomain_hunt())

            if stealth_tasks:
                stealth_results = await asyncio.gather(*stealth_tasks)
                for r in stealth_results:
                    stealth_data.update(r)

        # ------ [ V1.0: RECURSIVE SUBDOMAIN ATTACK — Full Coverage ] ------
        subdomain_scan_results = []
        from config import Config as _CfgSub
        
        # Thu thập tất cả subdomains từ mọi nguồn
        all_subdomains = list(set(
            [s.get("sub", "") if isinstance(s, dict) else str(s) for s in stealth_data.get("subdomains", [])] +
            osint_infra_data.get("subdomains", [])
        ))

        #  Tích hợp thêm subdomains từ file seed (do Origin-Finder cung cấp)
        if self.seed_subs_file and os.path.exists(self.seed_subs_file):
            try:
                with open(self.seed_subs_file, 'r') as f:
                    seed_subs = [line.strip() for line in f if line.strip()]
                all_subdomains = list(set(all_subdomains + seed_subs))
                self.log.info(f"[Seed] Đã tích hợp thêm {len(seed_subs)} subdomains từ Origin-Finder.")
            except Exception as e:
                self.log.warning(f"[Seed] Không thể đọc file seed: {e}")
        
        # Normalize: loại bỏ rỗng, loại bỏ domain chính
        normalized_subs = []
        for s in all_subdomains:
            if isinstance(s, dict):
                sub = s.get("sub", "") or s.get("subdomain", "")
            else:
                sub = str(s).strip()
            if sub and sub != self.target and sub.strip():
                normalized_subs.append(sub.strip())
        normalized_subs = list(set(normalized_subs))
        
        if normalized_subs and self.subdomain_scan:
            self.log.phase(f"SUBDOMAIN ATTACK — Recursive Pipeline V1.0 ({len(normalized_subs)} subs)")
            
            from scripts.subdomain_scanner import SubdomainScanner
            sub_scanner = SubdomainScanner(self.scanner, self.log, self)
            
            subdomain_scan_results = await sub_scanner.run(normalized_subs, self.target)
            
            subdomain_summary = _summarize_subdomain_vulns(subdomain_scan_results)
            
            self.log.success(
                f"Subdomain Attack complete: {len(subdomain_scan_results)} subs scanned | "
                f"{subdomain_summary['total_xss']} XSS | "
                f"{subdomain_summary['total_blind_xss']} Blind-XSS | "
                f"{subdomain_summary['total_nuclei']} Nuclei | "
                f"{subdomain_summary['total_sqli']} SQLi | "
                f"{subdomain_summary['total_mass_assignment']} Mass-Assignment"
            )
        elif normalized_subs:
            self.log.info(f"[Subdomain] Found {len(normalized_subs)} subs but SUBDOMAIN_SCAN_ENABLED=false, skipping.")

        self.log.phase("MERGING DATA & PROFILING (V1.0 — Validated Intelligence)")
        profile = self.merge_results(ip, shodan_data, vt_data, osint_infra_data, scan_data, stealth_data, validation, subdomain_scan_results)

        # ------ [ VISUAL RECON — GOWITNESS SCREENSHOT PHASE ] ------
        if self.visual_recon:
            self.log.phase("VISUAL RECON — Camera Bằng Chứng (gowitness)")
            try:
                from utils.gowitness_wrapper import take_screenshots, export_live_urls
                
                # [BUG-008 FIX] Check gowitness installed FIRST
                if not shutil.which("gowitness"):
                    self.log.error("Visual Recon FAILED: gowitness chưa được cài đặt!")
                    self.log.info("  → Cài đặt: go install github.com/sensepost/gowitness@latest")
                    profile['screenshot_count'] = 0
                else:
                    # Thu thập tất cả live URLs từ các nguồn
                    all_live_urls = []
                    
                    # Từ scan_data (httpx probed URLs)
                    for p_info in scan_data.get('ports', []):
                        port = p_info.get('port', 80)
                        scheme = 'https' if port in [443, 8443] else 'http'
                        base_url = f"{scheme}://{self.target}" if port in [80, 443] else f"{scheme}://{self.target}:{port}"
                        all_live_urls.append(base_url)
                    
                    # Từ web_urls (katana crawled)
                    all_live_urls.extend(scan_data.get('web_urls', []))
                    
                    # Từ subdomains (stealth recon)
                    for sub in stealth_data.get('subdomains', []):
                        if isinstance(sub, dict):
                            sub = sub.get('sub', '')
                        if sub:
                            all_live_urls.append(f"https://{sub}")
                    
                    # [V1.0] Smart URL Deduplication cho Visual Recon
                    all_live_urls = URLDeduplicator.deduplicate(
                        [u for u in all_live_urls if u and u.startswith('http')]
                    )
                    # [RESOURCE-GUARD] Cap max URLs to 150 to prevent OOM
                    MAX_VISUAL_URLS = 150
                    if len(all_live_urls) > MAX_VISUAL_URLS:
                        self.log.info(f"[ResourceGuard] Capping visual recon URLs from {len(all_live_urls)} to top {MAX_VISUAL_URLS}")
                        all_live_urls = all_live_urls[:MAX_VISUAL_URLS]
                    
                    if all_live_urls:
                        # Check system memory pressure
                        from core.resource_guard import ResourceGuard
                        guard = ResourceGuard(max_memory_pct=85.0, log=self.log)
                        ok, mem_pct = guard.check_memory()
                        if not ok:
                            self.log.warning(f"[ResourceGuard] High memory usage ({mem_pct:.1f}%). Skipping visual recon.")
                            profile['screenshot_count'] = 0
                        else:
                            # Export live URLs file
                            live_urls_file = os.path.join(self.out_dir, "live_urls.txt")
                            export_live_urls(all_live_urls, live_urls_file)
                            self.log.success(f"Exported {len(all_live_urls)} live URLs → {live_urls_file}")
                            
                            # Capture screenshots
                            screenshots_output = os.path.join(self.out_dir, "screenshots")
                            screenshot_paths = take_screenshots(
                                target_list_path=live_urls_file,
                                output_dir=screenshots_output,
                            )
                            
                            profile['screenshots_dir'] = os.path.join(screenshots_output, 'screenshots')
                            profile['screenshot_count'] = len(screenshot_paths)
                            # [BUG-008 FIX] Đúng icon theo kết quả thực tế
                            if screenshot_paths:
                                self.log.success(f"Visual Recon: {len(screenshot_paths)} screenshots captured.")
                            else:
                                self.log.error("Visual Recon: 0 screenshots captured — gowitness có thể gặp lỗi.")
                    else:
                        self.log.warning("Visual Recon: No live URLs found to screenshot.")
                        profile['screenshot_count'] = 0
            except ImportError as ie:
                self.log.error(f"Visual Recon FAILED (import error): {ie}")
                profile['screenshot_count'] = 0
            except Exception as e:
                self.log.error(f"Visual Recon failed: {e}")

        # [V1.0] DATA LIFTING: Gom dữ liệu Tech/OS từ port lên level Global
        global_tech = set(profile.get("tech_stack", []))
        global_os = set(profile.get("os_detection", []))
        
        for p in profile.get("open_ports", []):
            # Nhặt tech từ port
            for t in p.get("tech", []):
                global_tech.add(t)
            # Nhặt OS/Version nếu có chữ CentOS, Ubuntu, Windows...
            version = p.get("version", "").lower()
            for os_name in ["centos", "ubuntu", "debian", "windows", "redhat", "fedora", "linux"]:
                if os_name in version:
                    global_os.add(os_name.capitalize())
        
        profile["tech_stack"] = list(global_tech)
        profile["os_detection"] = list(global_os)
        if global_tech or global_os:
            self.log.info(f"    [V1.0-DATA-LIFT] Consolidated {len(global_tech)} tech tags and {len(global_os)} OS tags to global profile.")

        with open(self.out_file, "w") as f:
            json.dump([profile], f, indent=4)

        c = Colors.GREEN if profile['open_ports'] else Colors.FAIL
        total_cves = len(profile['cve_candidates'])
        nuclei_count = len(profile.get('nuclei_findings', []))
        print(f"   [+] {profile['target']} ({profile['ip']}) -> {c}{len(profile['open_ports'])} Ports{Colors.ENDC} | CVEs: {total_cves} | Nuclei: {nuclei_count}")
        if profile.get('screenshot_count'):
            print(f"   [+] 📸 Screenshots: {profile['screenshot_count']} captured")
        self.log.success(f"Dữ liệu Recon đã lưu tại: {self.out_file}")

        # ═══════════════════════════════════════════════════════════════════
        # V1.0-FIX: EXPLICIT DATABASE PERSISTENCE
        # The profile is finalized — NOW commit everything to penlabs.db.
        # This was the MISSING LINK causing 100% empty database after scans.
        # ═══════════════════════════════════════════════════════════════════
        try:
            from core.db import persist_to_database
            db_stats = persist_to_database(
                target=self.target,
                scan_mode=self.mode,
                recon_data=profile,
            )
            if db_stats.get("assets_new", 0) or db_stats.get("vulns_new", 0):
                self.log.success(
                    f"[DB] ✅ Persisted to penlabs.db: "
                    f"{db_stats['assets_new']} new assets, "
                    f"{db_stats['ports_new']} new ports, "
                    f"{db_stats['vulns_new']} new vulns"
                )
            else:
                self.log.info("[DB] No new data to persist (all records already exist).")
        except Exception as _db_err:
            self.log.warning(f"[DB] ⚠️  Database persistence warning: {_db_err}")
            logging.debug(f"[DB] Full error: {_db_err}", exc_info=True)

        # ═══════════════════════════════════════════════════════════════════
        # V1.0-FIX: RECURSIVE DATA MERGING (TASK 3)
        # Deep-merge subdomain scan findings INTO the central profile so
        # they appear in attack_surface_report.md and are persisted to DB.
        # ═══════════════════════════════════════════════════════════════════
        if subdomain_scan_results:
            try:
                merged_stats = self._deep_merge_recursive_results(profile, subdomain_scan_results)
                self.log.success(
                    f"[MERGE] ✅ Merged recursive data: "
                    f"+{merged_stats['nuclei_merged']} nuclei, "
                    f"+{merged_stats['cves_merged']} CVEs, "
                    f"+{merged_stats['urls_merged']} URLs"
                )
                # Re-save profile with merged data
                with open(self.out_file, "w") as f:
                    json.dump([profile], f, indent=4)

                # Re-persist merged data to DB
                try:
                    from core.db import persist_to_database
                    db_stats_merged = persist_to_database(
                        target=self.target,
                        scan_mode=self.mode,
                        recon_data=profile,
                    )
                    if db_stats_merged.get("vulns_new", 0):
                        self.log.success(
                            f"[DB] ✅ Recursive merge persisted: "
                            f"+{db_stats_merged['vulns_new']} new vulns from subdomains"
                        )
                except Exception as _merge_db_err:
                    self.log.warning(f"[DB] Recursive merge persistence warning: {_merge_db_err}")
            except Exception as _merge_err:
                self.log.warning(f"[MERGE] ⚠️  Recursive merge warning: {_merge_err}")

        # ═══════════════════════════════════════════════════════════════════
        # V1.0-FIX: DISK CLEANUP (TASK 4)
        # Purge raw/ subdirectories after successful persistence.
        # Keeps: logs, m1_recon.json, attack_surface_report.md
        # ═══════════════════════════════════════════════════════════════════
        try:
            cleanup_stats = self._cleanup_raw_data()
            if cleanup_stats["files_removed"] > 0:
                self.log.info(
                    f"[CLEANUP] 🧹 Purged {cleanup_stats['files_removed']} raw files "
                    f"({cleanup_stats['bytes_freed_mb']:.1f} MB freed). "
                    f"Kept {cleanup_stats['files_kept']} core reports."
                )
        except Exception as _cleanup_err:
            self.log.warning(f"[CLEANUP] ⚠️  Disk cleanup warning: {_cleanup_err}")

    # ═══════════════════════════════════════════════════════════════════
    # V1.0-FIX: DEEP MERGE RECURSIVE RESULTS (TASK 3)
    # ═══════════════════════════════════════════════════════════════════
    @staticmethod
    def _deep_merge_recursive_results(profile: dict, subdomain_results: list) -> dict:
        """
        Recursively merge all subdomain scan findings into the central profile.
        
        Ensures that nuclei findings, CVE candidates, web URLs, XSS findings,
        SQLi findings, and SSRF findings from recursive subdomain scans are
        ingested into the main m1_recon.json profile.
        
        Returns:
            dict: {"nuclei_merged": N, "cves_merged": N, "urls_merged": N}
        """
        nuclei_merged = 0
        cves_merged = 0
        urls_merged = 0
        
        # Collect existing data sets for deduplication
        existing_nuclei_ids = set()
        for nf in profile.get("nuclei_findings", []):
            if isinstance(nf, dict):
                nf_id = f"{nf.get('template-id', '')}/{nf.get('matched-at', nf.get('matched_at', ''))}"
                existing_nuclei_ids.add(nf_id)
        
        existing_cve_ids = set()
        for cv in profile.get("cve_candidates", []):
            if isinstance(cv, dict):
                existing_cve_ids.add(cv.get("cve_id", cv.get("id", "")))
            elif isinstance(cv, str):
                existing_cve_ids.add(cv)
        
        existing_urls = set(profile.get("web_urls", []))
        
        # Generator to stream files
        def result_streamer():
            import json, os
            for item in subdomain_results:
                if isinstance(item, str) and os.path.exists(item):
                    try:
                        with open(item, "r") as f:
                            yield json.load(f)
                    except Exception:
                        pass
                elif isinstance(item, dict):
                    yield item

        for sub_result in result_streamer():
            subdomain = sub_result.get("_subdomain", sub_result.get("subdomain", "unknown"))
            
            # Merge nuclei findings (with dedup)
            for nf in sub_result.get("nuclei_findings", []):
                if isinstance(nf, dict):
                    nf_id = f"{nf.get('template-id', '')}/{nf.get('matched-at', nf.get('matched_at', ''))}"
                    if nf_id not in existing_nuclei_ids:
                        nf["_source_subdomain"] = subdomain
                        profile.setdefault("nuclei_findings", []).append(nf)
                        existing_nuclei_ids.add(nf_id)
                        nuclei_merged += 1
            
            # Merge CVE candidates from subdomain NSE/Nuclei
            for cv in sub_result.get("nse_cves", []) + sub_result.get("cve_candidates", []):
                cv_id = cv.get("cve_id", cv.get("id", "")) if isinstance(cv, dict) else str(cv)
                if cv_id and cv_id not in existing_cve_ids:
                    if isinstance(cv, dict):
                        cv["_source_subdomain"] = subdomain
                    profile.setdefault("cve_candidates", []).append(cv)
                    existing_cve_ids.add(cv_id)
                    cves_merged += 1
            
            # Merge web URLs (with dedup)
            for url in sub_result.get("web_urls", []):
                if url and url not in existing_urls:
                    profile.setdefault("web_urls", []).append(url)
                    existing_urls.add(url)
                    urls_merged += 1
        
        return {
            "nuclei_merged": nuclei_merged,
            "cves_merged": cves_merged,
            "urls_merged": urls_merged,
        }

    # ═══════════════════════════════════════════════════════════════════
    # V1.0-FIX: DISK CLEANUP (TASK 4)
    # ═══════════════════════════════════════════════════════════════════
    def _cleanup_raw_data(self) -> dict:
        """
        [USER-OVERRIDE] Keep all raw tools data intact for analysis.
        Do not purge raw/ subdirectories.
        """
        return {"files_removed": 0, "bytes_freed_mb": 0.0, "files_kept": 0}

        # Protected files/patterns that should NEVER be deleted
        protected_patterns = {
            "m1_recon.json", "m2_vuln.json", "attack_surface_report.md",
            "penlabs.db", "scan_log.txt",
        }
        protected_extensions = {".log", ".md", ".db"}
        protected_dirs = {"screenshots", "gowitness", "logs"}
        
        files_removed = 0
        bytes_freed = 0
        files_kept = 0
        
        for dirpath, dirnames, filenames in os.walk(raw_dir, topdown=False):
            # Skip protected directories
            dir_basename = os.path.basename(dirpath)
            if dir_basename in protected_dirs:
                files_kept += len(filenames)
                continue
            
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                _, ext = os.path.splitext(filename)
                
                # Keep protected files
                if filename in protected_patterns or ext in protected_extensions:
                    files_kept += 1
                    continue
                
                # Remove everything else in raw/
                try:
                    file_size = os.path.getsize(filepath)
                    os.remove(filepath)
                    files_removed += 1
                    bytes_freed += file_size
                except OSError:
                    files_kept += 1
            
            # Remove empty directories
            try:
                if not os.listdir(dirpath):
                    os.rmdir(dirpath)
            except OSError:
                pass
        
        return {
            "files_removed": files_removed,
            "bytes_freed_mb": bytes_freed / (1024 * 1024),
            "files_kept": files_kept,
        }


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("target")
    p.add_argument("--outdir", required=True)
    p.add_argument("--output", required=True)
    p.add_argument("--mode", default="sniper")
    p.add_argument("--vt-key", default="")
    # [V1.0] --hunter-key removed (replaced by free OWASP Amass + theHarvester)
    p.add_argument("--chaos-key", default="")
    p.add_argument("--blacklist", default="")
    p.add_argument("--stealth-recon", action="store_true", help="Bật các tính năng WAF bypass và Subdomain hunting nâng cao")
    p.add_argument("--proxy", default="", help="Bật Proxy cho. URL (vd: socks5://...) hoặc file (proxies.txt)")
    p.add_argument("--tor-route", action="store_true", help="Ép HTTP tooling hỗ trợ proxy đi qua Tor SOCKS5 local")
    p.add_argument("--rate-limit", type=int, default=150, help="Giới hạn requests per second")
    p.add_argument("--delay", default="", help="Delay requests (e.g. 500ms, 2s)")
    p.add_argument("--debug", action="store_true", help="In ra toàn bộ log của subprocess")
    p.add_argument("--cookie", default="", help="HTTP Cookie cho authenticated scan")
    p.add_argument("--header", action="append", help="Custom HTTP Header (e.g. 'Authorization: Bearer Token')")
    p.add_argument("--visual-recon", action="store_true", help="Chụp ảnh bằng chứng bằng gowitness cho tất cả live URLs")
    
    # [V1.0] Bug Bounty Extended
    p.add_argument("--auth-userA", default="", help="Auth token User A (BOLA Engine)")
    p.add_argument("--auth-userB", default="", help="Auth token User B (BOLA Engine)")
    p.add_argument("--subdomain-scan", dest="subdomain_scan", action="store_true", default=True, help="Bật quét đệ quy tất cả subdomains tìm thấy")
    p.add_argument("--no-subdomain-scan", dest="subdomain_scan", action="store_false", help="Tắt quét đệ quy subdomain tự động")
    p.add_argument("--no-stealth-discovery", dest="stealth_discovery", action="store_false", default=True, help="Tắt WAF/subdomain passive discovery mặc định")
    p.add_argument("--no-osint", dest="osint_enabled", action="store_false", default=True, help="Tắt OSINT passive phase (benchmark/active-only)")
    
    # [V1.0] Core New Options
    p.add_argument("--proxy-file", help="File danh sách proxies")
    p.add_argument("--auth-config", help="File JSON cấu hình tự động xác thực (Login flow)")
    p.add_argument("--use-playwright", action="store_true", help="Bật Playwright SPA Discovery")
    p.add_argument("--sqlmap-relay", action="store_true", help="Bật SQLMap Stealth Relay")
    p.add_argument("--bola-engine", action="store_true", help="Bật BOLA/IDOR Engine")
    p.add_argument("--chunk-size", type=int, default=20, help="Kích thước chunk cho Resume")
    p.add_argument("--seed-subs", help="File chứa danh sách subdomain mồi (từ Origin-Finder)")

    # [V1.0] --tactical-mode REMOVED — use --mode directly
    p.add_argument("--use-internetdb", action="store_true", default=False, help="Bật Shodan InternetDB passive port lookup (infra-smash)")
    
    p.add_argument("--permissive", action="store_true", help="Bypass scope check")
    p.add_argument("--confirm-permissive", action="store_true", help="Confirm bypass scope check")

    a = p.parse_args()
    headers_dict = {}
    if a.header:
        for h in a.header:
            if ':' in h:
                k, v = h.split(':', 1)
                headers_dict[k.strip()] = v.strip()

    # [V1.0] Pass new flags
    orchestrator = ReconOrchestrator(
        a.target, a.outdir, a.output, a.mode, a.vt_key, a.chaos_key, a.blacklist, 
        a.stealth_recon, a.proxy, cookies=a.cookie, headers=headers_dict,
        visual_recon=a.visual_recon, rate_limit=a.rate_limit, delay=a.delay,
        auth_userA=getattr(a, 'auth_userA', ''),
        auth_userB=getattr(a, 'auth_userB', ''),
        subdomain_scan=a.subdomain_scan,
        stealth_discovery=a.stealth_discovery,
        osint_enabled=a.osint_enabled,
        use_internetdb=a.use_internetdb,
        # [V1.0] Pass new flags
        proxy_file=getattr(a, 'proxy_file', None),
        tor_route=getattr(a, 'tor_route', False),
        auth_config=getattr(a, 'auth_config', None),
        use_playwright=getattr(a, 'use_playwright', False),
        sqlmap_relay=getattr(a, 'sqlmap_relay', False),
        bola_engine=getattr(a, 'bola_engine', False),
        chunk_size=getattr(a, 'chunk_size', 20),
        seed_subs=getattr(a, 'seed_subs', None),
        permissive=getattr(a, 'permissive', False),
        confirm_permissive=getattr(a, 'confirm_permissive', False)
    )
    asyncio.run(orchestrator.start())
