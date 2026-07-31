import os
import json
import logging
import subprocess
import shutil
import random
from core.base_plugin import BasePlugin
from core.raw_artifacts import append_manifest, write_command, write_json

# Static paths vô giá trị — lọc bỏ để giảm noise
_NOISE_PATH_SEGMENTS = frozenset([
    "/node_modules/", "/vendor/", "/bower_components/",
    "/.git/", "/__pycache__/", "/dist/", "/build/",
    "/assets/fonts/", "/assets/images/", "/favicon.ico",
    ".woff2", ".woff", ".ttf", ".eot", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".css", ".less", ".scss",
])


class KatanaPlugin(BasePlugin):
    """Katana — Next-gen web crawler hiểu JavaScript/SPA (ProjectDiscovery)."""

    def name(self) -> str:
        return "Katana"

    def description(self) -> str:
        return "Katana Web Crawler — JS-aware crawling cho SPA/React/NextJS, trích xuất URL, endpoint, JS files."

    def check_installed(self) -> bool:
        return shutil.which("katana") is not None

    def run(self, target: str, out_dir: str = "/tmp", depth: int = 3,
            js_crawl: bool = True, headless: bool = False,
            scope_filter: str = "", extra_flags: list = None,
            headers: dict = None, proxy_file: str = None,
            rate_limit: int = 0, proxy_mode: str = "fuzz") -> dict:
        """
        Chạy Katana crawler và trả về URLs + endpoints đã phát hiện.

        Args:
            target: URL mục tiêu (http://example.com)
            depth: Crawl depth (mặc định 3)
            js_crawl: Bật JS parsing & crawling
            headless: Bật headless browser mode (cho SPA nặng)
            scope_filter: Regex giới hạn scope
            extra_flags: Flags bổ sung
            rate_limit: Requests per second (0 = no limit, dùng -rl flag)
            proxy_mode: Proxy profile ('fuzz', 'recon', 'exploit')
        Returns:
            dict: {"urls": [...], "js_files": [...], "endpoints": [...],
                   "forms": [...], "vulnerable_endpoints": [...]}
        """
        if not self.check_installed():
            logging.error("Katana is not installed. Run setup.sh first.")
            return {"urls": [], "js_files": [], "endpoints": [], "forms": [],
                    "vulnerable_endpoints": []}

        os.makedirs(out_dir, exist_ok=True)
        jsonl_file = os.path.join(out_dir, "katana_output.jsonl")

        cmd = [
            "katana",
            "-u", target,
            "-jsonl",
            "-output", jsonl_file,
            "-depth", str(depth),
            "-silent",
            # === V1.0 FIX: Loại bỏ response body & raw request khỏi JSONL ===
            # Giảm dung lượng output từ ~150MB xuống <1MB
            "-ob",   # omit-body
            "-or",   # omit-raw
        ]

        # [V1.0-APEX] Tier 1 Anti-FP (Lọc thô bằng Go)
        # 1. Filter status codes: Katana v1.6.1 does not support -fxc. Use -fdc instead.
        cmd.extend(["-fdc", "status_code == 404 || status_code == 429 || status_code == 400"])
        # 2. Crawl Timeout (120s): Chống dính bẫy Infinite Crawl Loop (các trang lịch, bộ lọc vô hạn)
        cmd.extend(["-ct", "120"])
        # 3. Extension Match: Chỉ tập trung vào các định dạng có khả năng chứa lỗ hổng
        cmd.extend(["-em", "js,json,php,asp,aspx,jsp,html,xml"])

        # V1.0: Native rate limiting via Katana's -rl flag
        if rate_limit > 0:
            cmd.extend(["-rl", str(rate_limit)])
            logging.info(f"[Katana] Rate limit: {rate_limit} req/s via -rl flag")

        if js_crawl:
            cmd.append("-js-crawl")
        if headless:
            cmd.extend(["-headless", "-no-sandbox"])
        if scope_filter:
            cmd.extend(["-fs", scope_filter])
        if headers:
            SAFE_HEADERS = {"user-agent", "cookie", "authorization", "referer", "x-forwarded-for", "accept", "accept-language"}
            for k, v in headers.items():
                if k.lower() in SAFE_HEADERS:
                    clean_v = str(v).replace('"', '')
                    cmd.extend(["-H", f"{k}: {clean_v}"])

        #  Smart proxy routing — prefer Config profile over proxy_file
        from config import Config as _Cfg
        proxy_url = _Cfg.get_proxy_url(proxy_mode)
        if proxy_url:
            cmd.extend(["-proxy", proxy_url])
            logging.info(f"[Katana] Using {proxy_mode.upper()} proxy: {proxy_url}")
        elif proxy_file and os.path.exists(proxy_file):
            with open(proxy_file, "r") as f:
                proxies = [l.strip() for l in f if l.strip()]
            if proxies:
                p = random.choice(proxies)
                if not p.startswith(("http", "socks")):
                    p = f"http://{p}"
                cmd.extend(["-proxy", p])

        if extra_flags:
            cmd.extend(extra_flags)

        write_command(out_dir, "katana_command.txt", cmd)

        import sys
        try:
            if "--debug" in sys.argv:
                logging.info(f"[Katana] CMD: {' '.join(cmd)}")
                subprocess.run(cmd, timeout=600)
            else:
                # [V1.0-FIX] Capture stderr to log file even if not in debug
                res = subprocess.run(cmd, capture_output=True, timeout=600)
                if res.returncode != 0 and res.stderr:
                    logging.warning(f"[Katana] Process returned {res.returncode}. Stderr: {res.stderr.decode()[:200]}...")
        except subprocess.TimeoutExpired:
            logging.warning("[Katana] Timed out after 600 seconds.")

        parsed = self._parse_jsonl(jsonl_file)
        write_json(out_dir, "katana_parsed.json", parsed)
        append_manifest(
            out_dir,
            "katana",
            ["katana_command.txt", "katana_output.jsonl", "katana_parsed.json"],
            note=f"target={target}",
        )
        return parsed

    @staticmethod
    def _is_noise_url(url: str) -> bool:
        """Kiểm tra URL có phải static/noise path không."""
        url_lower = url.lower()
        return any(seg in url_lower for seg in _NOISE_PATH_SEGMENTS)

    def _parse_jsonl(self, jsonl_file: str) -> dict:
        """Parse Katana JSONL output, phân loại kết quả, tách vulnerable endpoints."""
        result = {
            "urls": [],
            "js_files": [],
            "endpoints": [],
            "forms": [],
            # === V1.0: Mảng riêng cho các endpoint trả mã lỗi bất thường ===
            "vulnerable_endpoints": [],
        }

        if not os.path.exists(jsonl_file):
            return result

        try:
            with open(jsonl_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        url = data.get("request", {}).get("endpoint", "") or data.get("endpoint", "")
                        if not url:
                            continue

                        # Lọc bỏ static noise
                        if self._is_noise_url(url):
                            continue

                        result["urls"].append(url)

                        # === V1.0: Tách riêng HTTP 500/403/401 ===
                        status_code = (
                            data.get("response", {}).get("status_code", 0)
                            or data.get("status_code", 0)
                        )
                        if status_code in (500, 501, 502, 503, 403, 401, 405):
                            result["vulnerable_endpoints"].append({
                                "url": url,
                                "status_code": status_code,
                                "method": data.get("request", {}).get("method", "GET"),
                            })

                        # Phân loại
                        if url.endswith(".js") or ".js?" in url:
                            result["js_files"].append(url)
                        if any(kw in url.lower() for kw in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                            result["endpoints"].append(url)
                        if data.get("request", {}).get("method", "").upper() == "POST":
                            result["forms"].append(url)
                            
                        # V1.0-FIX: SENSITIVE DATA MINER (TASK 3)
                        # Check URL and available headers for secrets
                        import re
                        import math
                        def shannon_entropy(data):
                            if not data: return 0
                            entropy = 0
                            for x in range(256):
                                p_x = float(data.count(chr(x))) / len(data)
                                if p_x > 0: entropy += - p_x * math.log(p_x, 2)
                            return entropy

                        secret_patterns = [
                            r'(?i)private[-_]?key', r'BEGIN RSA', r'(?i)secret[-_]?key', 
                            r'(?i)aws_access_key', r'(?i)db_password', r'(?i)service_account'
                        ]
                        text_to_scan = f"{url} {json.dumps(data)}"
                        is_sensitive = False
                        for pat in secret_patterns:
                            if re.search(pat, text_to_scan):
                                is_sensitive = True
                                break
                                
                        if not is_sensitive:
                            # Entropy check on query params
                            from urllib.parse import urlparse, parse_qs
                            query = parse_qs(urlparse(url).query)
                            for v_list in query.values():
                                for v in v_list:
                                    if len(v) > 20 and shannon_entropy(v) > 4.5:
                                        is_sensitive = True
                                        break
                                        
                        if is_sensitive:
                            result.setdefault("sensitive_leaks", []).append({
                                "url": url,
                                "reason": "High-Entropy or Secret Keyword Matched"
                            })

                    except json.JSONDecodeError:
                        # Fallback: plain text line (just a URL)
                        if line.startswith("http"):
                            if not self._is_noise_url(line):
                                result["urls"].append(line)
                                if line.endswith(".js") or ".js?" in line:
                                    result["js_files"].append(line)
        except Exception as e:
            logging.warning(f"[Katana] Failed to parse {jsonl_file}: {e}")

        # Deduplicate
        for key in ("urls", "js_files", "endpoints", "forms"):
            result[key] = list(set(result[key]))

        # Deduplicate vulnerable_endpoints by URL
        seen_vuln = set()
        deduped_vuln = []
        for v in result["vulnerable_endpoints"]:
            if v["url"] not in seen_vuln:
                seen_vuln.add(v["url"])
                deduped_vuln.append(v)
        result["vulnerable_endpoints"] = deduped_vuln

        if result["vulnerable_endpoints"]:
            logging.info(
                f"[Katana] ⚠️  {len(result['vulnerable_endpoints'])} endpoints trả mã lỗi bất thường "
                f"(500/403/401) — sẵn sàng cho Module khai thác."
            )

        return result
