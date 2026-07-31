#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PENTEST FRAMEWORK — CENTRALIZED CONFIGURATION (V1.0)
Tải biến môi trường từ file .env (nếu có), fallback về os.getenv()
"""

import os

# Đường dẫn tuyệt đối tới file .env nằm ngang hàng với config.py
env_path = os.path.join(os.path.dirname(__file__), ".env")

try:
    from dotenv import load_dotenv
    # Ép load file .env từ thư mục gốc
    load_dotenv(dotenv_path=env_path)
except ImportError:
    print(f"\n[!] Thư viện 'python-dotenv' chưa được cài đặt.")
    print(f"[*] Để dùng file .env, vui lòng chạy: pip install python-dotenv\n")


class Config:
    """Singleton config — tất cả API keys & settings tập trung tại đây."""

    # --- API Keys ---
    VT_API_KEY = os.getenv("VT_API_KEY", "")
    SHODAN_KEY = os.getenv("SHODAN_KEY", "")
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
    CHAOS_KEY = os.getenv("CHAOS_KEY", "")
    SECURITYTRAILS_KEY = os.getenv("SECURITYTRAILS_KEY", "")

    # --- Timeouts ---
    MSF_TIMEOUT = int(os.getenv("MSF_TIMEOUT", "300"))       # 5 phút mặc định
    NMAP_TIMEOUT = int(os.getenv("NMAP_TIMEOUT", "1800"))  # 30 phút mặc định — tránh Nmap treo vô hạn trên target behind WAF
    HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "15"))

    # --- 2026 Doctrine: Scanner Tool Configs ---
    NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "1800"))     # 30 phút
    NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))
    NUCLEI_CONCURRENCY = int(os.getenv("NUCLEI_CONCURRENCY", "25"))
    NAABU_TIMEOUT = int(os.getenv("NAABU_TIMEOUT", "300"))        # 5 phút
    KATANA_TIMEOUT = int(os.getenv("KATANA_TIMEOUT", "600"))      # 10 phút
    HTTPX_TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", "300"))
    FFUF_TIMEOUT = int(os.getenv("FFUF_TIMEOUT", "120"))

    # [RECON-FIX] Per-mode rate limits — stealth phải chậm hơn full-audit
    RATE_LIMITS = {
        "stealth":      {"nuclei_rate": 30,  "nuclei_conc": 5,  "nmap_timing": "T2"},
        "sniper":       {"nuclei_rate": 100, "nuclei_conc": 15, "nmap_timing": "T3"},
        "fast":         {"nuclei_rate": 100, "nuclei_conc": 15, "nmap_timing": "T3"},
        "web-vuln":     {"nuclei_rate": 150, "nuclei_conc": 25, "nmap_timing": "T3"},
        "cloud-devops": {"nuclei_rate": 100, "nuclei_conc": 15, "nmap_timing": "T3"},
        "full-audit":   {"nuclei_rate": 300, "nuclei_conc": 50, "nmap_timing": "T4"},
        "api-bounty":   {"nuclei_rate": 100, "nuclei_conc": 15, "nmap_timing": "T3"},
    }

    # [V1.0-FIX] Dynamic Proxy Routing — mode-aware delay, pool sizing, and routing
    # Replaces the hardcoded time.sleep(2) in StealthNetPlugin
    # mode: "direct" (no proxy), "fast-proxy" (SOCKS5/HTTP from pool), "tor" (127.0.0.1:9050)
    # Tor is intentionally explicit via --tor-route; stealth is rate/delay/fingerprint posture.
    PROXY_ROUTING = {
        "stealth":      {"mode": "direct",     "delay": 2.0,  "pool_size": 3},
        "sniper":       {"mode": "fast-proxy", "delay": 0.5,  "pool_size": 10},
        "fast":         {"mode": "fast-proxy", "delay": 0.5,  "pool_size": 10},
        "web-vuln":     {"mode": "fast-proxy", "delay": 0.3,  "pool_size": 15},
        "cloud-devops": {"mode": "direct",     "delay": 0.2,  "pool_size": 20},
        "full-audit":   {"mode": "direct",     "delay": 0.1,  "pool_size": 25},
        "api-bounty":   {"mode": "fast-proxy", "delay": 0.3,  "pool_size": 15},
        "api-breach":   {"mode": "direct",     "delay": 0.1,  "pool_size": 25},
        "infra-smash":  {"mode": "direct",     "delay": 0.2,  "pool_size": 20},
    }

    # [V1.0-FIX] Smart Proxy Profiles — Stop forcing EVERYTHING through Tor
    # RECON_PROXY:   Direct or standard HTTP proxy (speed for passive/active recon)
    # FUZZ_PROXY:    High-speed proxy or Direct (volume for Arjun/Dalfox/Katana)
    # EXPLOIT_PROXY: Tor SOCKS5 (stealth/bypass for exploit delivery and WAF evasion)
    RECON_PROXY   = os.getenv("RECON_PROXY", "")                          # Default: direct (no proxy)
    FUZZ_PROXY    = os.getenv("FUZZ_PROXY", "")                           # Default: direct (no proxy)
    EXPLOIT_PROXY = os.getenv("EXPLOIT_PROXY", "socks5h://127.0.0.1:9050")  # Default: Tor

    # --- [P1-1] JA3/TLS spoofing for Go tools via local SOCKS5 proxy ---
    JA3_SPOOF_ENABLED = os.getenv("JA3_SPOOF_ENABLED", "true").lower() == "true"
    JA3_PROXY_HOST = os.getenv("JA3_PROXY_HOST", "127.0.0.1")
    JA3_PROXY_PORT = int(os.getenv("JA3_PROXY_PORT", "1080"))
    JA3_PROFILE = os.getenv("JA3_PROFILE", "chrome120")

    @classmethod
    def get_proxy_url(cls, proxy_mode: str) -> str:
        """
        [V1.0] Return the proxy URL for the given mode.
        
        Args:
            proxy_mode: 'recon', 'fuzz', or 'exploit'
        
        Returns:
            Proxy URL string (empty string = direct connection)
        """
        mode_map = {
            "recon": cls.RECON_PROXY,
            "fuzz": cls.FUZZ_PROXY,
            "exploit": cls.EXPLOIT_PROXY,
        }
        return mode_map.get(proxy_mode.lower(), "")

    # [V1.0] Katana crawl limit per mode — tránh bottleneck cho stealth, tăng cho full-audit
    KATANA_MAX_URLS = {
        "stealth": 5,
        "sniper": 15,
        "fast": 15,
        "asset-discovery": 30,
        "web-vuln": 30,
        "cloud-devops": 10,
        "full-audit": 50,
        "api-bounty": 50,
    }

    # [V1.0] Top-200 NMAP common ports — KHÔNG phải range(1,201)
    # Source: nmap --top-ports 200 (sorted)
    TOP_200_PORTS = [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
        513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
        1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
        2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
        5000, 5001, 5003, 5009, 5050, 5051, 5060, 5101, 5190, 5357, 5432,
        5631, 5666, 5800, 5900, 5901, 6000, 6001, 6646, 7070, 8000, 8008,
        8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
        49153, 49154, 49155, 49156, 49157,
    ]

    # --- Metasploit RPC ---
    MSF_RPC_HOST = os.getenv("MSF_RPC_HOST", "127.0.0.1")
    MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
    MSF_RPC_PASS = os.getenv("MSF_RPC_PASS", "")
    MSF_RPC_SSL = os.getenv("MSF_RPC_SSL", "true").lower() == "true"

    # --- Paths ---
    VULN_DB_PATH = os.getenv("VULN_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "vuln_db.json"))
    PROXY_FILE = os.getenv("PROXY_FILE", "proxies.txt")
    BLACKLIST_FILE = os.getenv("BLACKLIST_FILE", "")
    EXPLOITDB_PATH = os.getenv("EXPLOITDB_PATH", "/usr/share/exploitdb")

    @classmethod
    def get_api_keys(cls) -> dict:
        """Trả về dict chứa tất cả API keys (dùng cho SubdomainHunter)."""
        return {
            "VIRUSTOTAL_KEY": cls.VT_API_KEY,
            "CHAOS_KEY": cls.CHAOS_KEY,
            "SHODAN_KEY": cls.SHODAN_KEY,
            "HUNTER_API_KEY": cls.HUNTER_API_KEY,
            "SECURITYTRAILS_KEY": cls.SECURITYTRAILS_KEY,
        }

    # --- [V1.0] NVD API Key (for CVSS scores) ---
    NVD_API_KEY = os.getenv("NVD_API_KEY", "")

    # --- [V1.0] PoC Sandbox ---
    FIREJAIL_ENABLED = os.getenv("FIREJAIL_ENABLED", "true").lower() == "true"

    # --- [V1.0] Audit Remote Syslog ---
    AUDIT_SYSLOG_HOST = os.getenv("AUDIT_SYSLOG_HOST", "")
    AUDIT_SYSLOG_PORT = int(os.getenv("AUDIT_SYSLOG_PORT", "514"))

    # --- [V1.0] DNS Resolve All IPs ---
    DNS_RESOLVE_ALL = os.getenv("DNS_RESOLVE_ALL", "true").lower() == "true"

    # --- [V1.0] Visual Recon & Persistence Flags ---
    VISUAL_RECON = os.getenv("VISUAL_RECON", "false").lower() == "true"
    PERSISTENCE = os.getenv("PERSISTENCE", "false").lower() == "true"

    # Gowitness settings
    GOWITNESS_TIMEOUT = int(os.getenv("GOWITNESS_TIMEOUT", "15"))
    GOWITNESS_THREADS = int(os.getenv("GOWITNESS_THREADS", "4"))

    # --- [V1.0] Cloudflare Tunnel (Web UI / Report Server) ---
    CLOUDFLARE_TUNNEL_ENABLED = os.getenv("CLOUDFLARE_TUNNEL_ENABLED", "false").lower() == "true"

    # Persistence C2 — LHOST/LPORT (dùng cho reverse shell / backdoor callback)
    C2_LHOST = os.getenv("C2_LHOST", "")
    C2_LPORT = int(os.getenv("C2_LPORT", "4444"))

    # --- [V1.0] Stealth & Precision — Obfuscation, EDR Evasion, OOB ---
    # Obfuscator Engine
    OBFUSCATOR_ENCODING_ITERATIONS = int(os.getenv("OBFUSCATOR_ENCODING_ITERATIONS", "3"))
    OBFUSCATOR_ENCODERS = os.getenv("OBFUSCATOR_ENCODERS", "x86/shikata_ga_nai,x86/xor,x86/countdown").split(",")

    # EDR Dry-Run
    EDR_DRYRUN_TIMEOUT = float(os.getenv("EDR_DRYRUN_TIMEOUT", "3.0"))
    EDR_DRYRUN_ENABLED = os.getenv("EDR_DRYRUN_ENABLED", "true").lower() == "true"

    # Interactsh OOB (Module 1)
    INTERACTSH_ENABLED = os.getenv("INTERACTSH_ENABLED", "true").lower() == "true"
    INTERACTSH_TIMEOUT = int(os.getenv("INTERACTSH_TIMEOUT", "15"))  # Timeout lấy OOB URL (giây)

    # Smart CPE Filter (Module 2)
    SMART_CPE_FILTER = os.getenv("SMART_CPE_FILTER", "true").lower() == "true"

    # --- [V1.0] API Bug Bounty Mode ---
    KITERUNNER_WORDLIST = os.getenv("KITERUNNER_WORDLIST", os.path.join(os.path.dirname(__file__), "wordlists", "routes-small.kite"))
    KITERUNNER_MAX_CONN = int(os.getenv("KITERUNNER_MAX_CONN", "10"))
    KITERUNNER_TIMEOUT = int(os.getenv("KITERUNNER_TIMEOUT", "300"))
    ARJUN_MAX_ENDPOINTS = int(os.getenv("ARJUN_MAX_ENDPOINTS", "20"))
    ARJUN_TIMEOUT_PER_URL = int(os.getenv("ARJUN_TIMEOUT_PER_URL", "180"))
    DALFOX_TIMEOUT_PER_URL = int(os.getenv("DALFOX_TIMEOUT_PER_URL", "120"))
    DALFOX_MAX_URLS = int(os.getenv("DALFOX_MAX_URLS", "30"))
    SQLMAP_DETECT_TIMEOUT = int(os.getenv("SQLMAP_DETECT_TIMEOUT", "120"))
    SQLMAP_DETECT_MAX_URLS = int(os.getenv("SQLMAP_DETECT_MAX_URLS", "15"))
    WPSCAN_TIMEOUT = int(os.getenv("WPSCAN_TIMEOUT", "300"))
    WPSCAN_API_TOKEN = os.getenv("WPSCAN_API_TOKEN", "")

    # --- [V1.0] Extended Bug Bounty Plugins ---
    SSRF_TIMEOUT_PER_URL = int(os.getenv("SSRF_TIMEOUT_PER_URL", "10"))
    SSRF_MAX_URLS = int(os.getenv("SSRF_MAX_URLS", "50"))
    BLIND_XSS_MAX_URLS = int(os.getenv("BLIND_XSS_MAX_URLS", "30"))
    OPEN_REDIRECT_MAX_URLS = int(os.getenv("OPEN_REDIRECT_MAX_URLS", "50"))
    CRLF_MAX_URLS = int(os.getenv("CRLF_MAX_URLS", "50"))
    RACE_CONDITION_CONCURRENT = int(os.getenv("RACE_CONDITION_CONCURRENT", "30"))
    RACE_CONDITION_MAX_URLS = int(os.getenv("RACE_CONDITION_MAX_URLS", "20"))
    BOLA_MAX_ENDPOINTS = int(os.getenv("BOLA_MAX_ENDPOINTS", "50"))
    BOLA_TIMEOUT = int(os.getenv("BOLA_TIMEOUT", "10"))

    # --- [V1.0] Continuous Recon ---
    RECON_DB_PATH = os.getenv("RECON_DB_PATH", os.path.join(os.path.dirname(__file__), "output", "penlabs_history.db"))

    # --- [V1.0] Recursive Subdomain Scanning (Full Coverage) ---
    SUBDOMAIN_SCAN_ENABLED = os.getenv("SUBDOMAIN_SCAN_ENABLED", "true").lower() == "true"

    # Keywords ưu tiên (quét trước, nhưng TẤT CẢ subs đều chạy full pipeline)
    SUBDOMAIN_PRIORITY_KEYWORDS = os.getenv(
        "SUBDOMAIN_PRIORITY_KEYWORDS",
        "mail,api,admin,dev,portal,staging,test,uat,cms,login,sso,auth,vpn,remote,gateway,webmail,cpanel,panel,manage,dashboard,internal"
    ).split(",")

    # Delay giữa mỗi subdomain (giây) - tránh WAF/IDS
    SUBDOMAIN_DELAY = int(os.getenv("SUBDOMAIN_DELAY", "5"))

    # httpx timeout cho subdomain probe
    SUBDOMAIN_HTTPX_TIMEOUT = int(os.getenv("SUBDOMAIN_HTTPX_TIMEOUT", "30"))

    # Recursive depth tối đa (phát hiện subs mới trong quá trình quét)
    SUBDOMAIN_MAX_DEPTH = int(os.getenv("SUBDOMAIN_MAX_DEPTH", "2"))

    # WAF-aware throttling: rate limit khi phát hiện WAF trên subdomain
    SUBDOMAIN_WAF_THROTTLE_RATE = int(os.getenv("SUBDOMAIN_WAF_THROTTLE_RATE", "20"))

    # === [P1-4] Scan Cache Configuration ===
    NUCLEI_CACHE_TTL_HOURS = int(os.getenv("NUCLEI_CACHE_TTL_HOURS", "24"))
    HTTPX_CACHE_TTL_HOURS = int(os.getenv("HTTPX_CACHE_TTL_HOURS", "12"))

    # --- Verification pass 2 (HTTP replay) ---
    VERIFICATION_PASS2_ENABLED = os.getenv("VERIFICATION_PASS2_ENABLED", "false").lower() == "true"
    VERIFICATION_PASS2_MAX_FINDINGS = int(os.getenv("VERIFICATION_PASS2_MAX_FINDINGS", "20"))
    VERIFICATION_PASS2_TIMEOUT = int(os.getenv("VERIFICATION_PASS2_TIMEOUT", "8"))
    NMAP_CACHE_TTL_HOURS = int(os.getenv("NMAP_CACHE_TTL_HOURS", "168"))  # 1 tuần

    # === [P1-5] Metasploit Stability Settings ===
    MSF_HEARTBEAT_INTERVAL = int(os.getenv("MSF_HEARTBEAT_INTERVAL", "30"))
    MSF_AUTO_RECONNECT = os.getenv("MSF_AUTO_RECONNECT", "true").lower() == "true"
    MSF_JOB_QUEUE_MAX = int(os.getenv("MSF_JOB_QUEUE_MAX", "1000"))
    MSF_JOB_QUEUE_PATH = os.getenv("MSF_JOB_QUEUE_PATH", "/tmp/penlabs_msf_jobs.json")
    MSF_CONNECT_TIMEOUT = int(os.getenv("MSF_CONNECT_TIMEOUT", "3"))
    NMAP_MSF_SYNC_ENABLED = os.getenv("PENLABS_NMAP_MSF_SYNC", "false").lower() == "true"
