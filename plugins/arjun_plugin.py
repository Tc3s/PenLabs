import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin


class ArjunPlugin(BasePlugin):
    """Arjun — Hidden HTTP parameter discovery (GET/POST/JSON)."""

    def name(self) -> str:
        return "Arjun"

    def description(self) -> str:
        return "Arjun — Phát hiện tham số HTTP ẩn (GET/POST/JSON) mà developer quên xóa."

    def check_installed(self) -> bool:
        return shutil.which("arjun") is not None

    def run(self, urls: list | str, out_dir: str = "/tmp",
            method: str = "GET", headers: dict = None,
            timeout_per_url: int = 60, max_urls: int = 20,
            proxy_mode: str = "fuzz") -> dict:
        """
        Chạy Arjun trên danh sách URL để phát hiện tham số ẩn.

        Args:
            urls: Danh sách URL cần kiểm tra
            method: HTTP method (GET/POST/JSON)
            headers: Custom headers
            timeout_per_url: Timeout cho mỗi URL (giây) — chống treo
            max_urls: Giới hạn số URL tối đa
            proxy_mode: Proxy profile ('fuzz', 'recon', 'exploit')

        Returns:
            dict: {"url1": ["param1", "param2"], "url2": ["param3"], ...}
        """
        if not self.check_installed():
            logging.warning("[Arjun] arjun not installed. Skip.")
            return {}

        os.makedirs(out_dir, exist_ok=True)
        if isinstance(urls, str):
            urls = [urls]
        all_params = {}

        #  Smart proxy routing — use Config profiles instead of forcing Tor
        from config import Config as _Cfg
        proxy_url = _Cfg.get_proxy_url(proxy_mode)
        if proxy_url:
            logging.info(f"[Arjun] Using {proxy_mode.upper()} proxy: {proxy_url}")

        for i, url in enumerate(urls[:max_urls]):
            url = url.strip()
            if not url or not url.startswith("http"):
                continue

            output_file = os.path.join(out_dir, f"arjun_{i}.json")
            cmd = [
                "arjun",
                "-u", url,
                "-m", method,
                "-oJ", output_file,
                "-t", "5",  # 5 threads
                "--stable",  # Stable mode — tránh false positive
                # [V1.0-APEX] Tier 1 Anti-FP: Lọc theo nội dung và tốc độ
                "--rate-limit", "10", # Giới hạn tốc độ để không kích hoạt WAF Anomaly
                "--passive", "true",  # Kết hợp OSINT để tìm param trước khi brute
            ]

            #  Apply proxy from Config profile
            if proxy_url:
                cmd.extend(["--proxy", proxy_url])


            if headers:
                SAFE_HEADERS = {"user-agent", "cookie", "authorization", "referer", "x-forwarded-for", "accept", "accept-language"}
                for k, v in headers.items():
                    if k.lower() in SAFE_HEADERS:
                        clean_v = str(v).replace('"', '')
                        cmd.extend(["--headers", f"{k}: {clean_v}"])

            try:
                subprocess.run(
                    cmd,
                    capture_output=True, text=True,
                    timeout=timeout_per_url
                )

                # Parse JSON output
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            data = json.load(f)
                        # Arjun output: [{"url": "...", "params": ["p1","p2"], "method": "GET"}]
                        if isinstance(data, list):
                            for entry in data:
                                found_url = entry.get("url", url)
                                params = entry.get("params", [])
                                if params:
                                    all_params[found_url] = params
                        elif isinstance(data, dict):
                            for found_url, params in data.items():
                                if params:
                                    all_params[found_url] = params
                    except (json.JSONDecodeError, Exception) as e:
                        logging.debug(f"[Arjun] JSON parse error for {url}: {e}")

            except subprocess.TimeoutExpired:
                logging.warning(f"[Arjun] Timeout ({timeout_per_url}s) cho {url}. Skip.")
            except Exception as e:
                logging.warning(f"[Arjun] Error for {url}: {e}")

        logging.info(f"[Arjun] Phát hiện hidden params trên {len(all_params)} URLs.")
        return all_params
