import os
import json
import logging
import subprocess
import shutil
import random
from core.base_plugin import BasePlugin
from config import Config
from core.raw_artifacts import append_manifest, write_command, write_json


class HttpxPlugin(BasePlugin):
    """httpx — HTTP probe & tech detection (ProjectDiscovery)."""

    def name(self) -> str:
        return "Httpx"

    def description(self) -> str:
        return "httpx HTTP Toolkit — Probe HTTP services, detect tech stack, filter live hosts."

    def check_installed(self) -> bool:
        return shutil.which("httpx-toolkit") is not None

    def run(self, targets: list, out_dir: str = "/tmp",
            threads: int = 50, extra_flags: list = None,
            headers: dict = None, proxy_file: str = None,
            proxy_mode: str = "recon") -> list:
        """
        Chạy httpx trên danh sách targets và trả về live HTTP services.

        Args:
            targets: List URL/IP:PORT cần probe (vd: ["1.2.3.4:80", "1.2.3.4:443"])
            threads: Số luồng song song
            extra_flags: Flags bổ sung
            proxy_mode: Proxy profile from Config ('recon', 'fuzz', 'exploit')
        Returns:
            list[dict]: [{"url": "https://...", "status_code": 200, "title": "...", "tech": [...], ...}]
        """
        if not self.check_installed():
            logging.error("httpx-toolkit is not installed. Run setup.sh first.")
            return []

        if not targets:
            logging.warning("[httpx] No targets provided. Skipping.")
            return []

        os.makedirs(out_dir, exist_ok=True)
        input_file = os.path.join(out_dir, "httpx_input.txt")
        jsonl_file = os.path.join(out_dir, "httpx_output.jsonl")

        # Ghi targets vào file input
        with open(input_file, 'w') as f:
            f.write("\n".join(targets))

        cmd = [
            "httpx-toolkit",
            "-l", input_file,
            "-json",
            "-output", jsonl_file,
            "-threads", str(threads),
            "-title",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-web-server",
            "-silent",
            "-no-color",
            "-no-stdin",
            "-http2",
            "--tls-impersonate", "chrome",
        ]
        
        header_items = {}
        header_names = {}
        if headers:
            for k, v in headers.items():
                if v is None:
                    continue
                value = str(v).strip()
                if not value or value.lower() == "none":
                    continue
                norm = str(k).lower()
                header_items[norm] = value
                header_names.setdefault(norm, str(k))

        # Thêm random UA only when caller did not already provide one.
        if "user-agent" not in header_items:
            from utils.ua_rotator import get_browser_ua
            header_items["user-agent"] = get_browser_ua()
            header_names["user-agent"] = "User-Agent"

        if extra_flags:
            cmd.extend(extra_flags)

        for norm, value in header_items.items():
            clean_value = str(value).replace('"', '')
            cmd.extend(["-H", f"{header_names[norm]}: {clean_value}"])

        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: UNIFIED PROXY LOGIC (TASK 1)
        # Priority: Config.get_proxy_url(proxy_mode) > proxy_file > direct
        # ═══════════════════════════════════════════════════════════════
        selected_proxy = None
        config_proxy = Config.get_proxy_url(proxy_mode)
        if config_proxy:
            selected_proxy = config_proxy
            cmd.extend(["-http-proxy", selected_proxy])
            logging.info(f"[httpx][PROXY] Using {proxy_mode.upper()} proxy: {selected_proxy}")
        elif proxy_file and os.path.exists(proxy_file):
            # Legacy fallback: proxy_file
            with open(proxy_file, "r") as f:
                proxies = [l.strip() for l in f if l.strip()]
            if proxies:
                random.shuffle(proxies)
                for proxy_candidate in proxies[:5]:
                    if self._test_proxy(proxy_candidate):
                        selected_proxy = proxy_candidate
                        if not selected_proxy.startswith(("http", "socks")):
                            selected_proxy = f"http://{selected_proxy}"
                        cmd.extend(["-http-proxy", selected_proxy])
                        logging.info(f"[httpx][PROXY] Using verified proxy from file: {selected_proxy}")
                        break
                    else:
                        logging.warning(f"[httpx] Proxy failed health-check: {proxy_candidate}")
                if not selected_proxy:
                    logging.warning("[httpx] ALL proxies failed health-check → falling back to DIRECT connection (no proxy)")

        write_command(out_dir, "httpx_command.txt", cmd)

        #  Thử chạy với ProjectDiscovery flags (-l), nếu lỗi (ko hỗ trợ -l) thì fallback sang positional
        try:
            logging.info(f"[httpx] Executing: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            # [BUG-001 FIX] Nếu dùng proxy mà 0 results → retry KHÔNG proxy
            if selected_proxy:
                parsed_first = self._parse_jsonl(jsonl_file)
                if not parsed_first:
                    logging.warning("[httpx] 0 results with proxy → retrying WITHOUT proxy (direct)...")
                    cmd_no_proxy = [c for c in cmd if c not in ["-http-proxy", selected_proxy]]
                    # Xóa output cũ
                    if os.path.exists(jsonl_file):
                        os.remove(jsonl_file)
                    result = subprocess.run(cmd_no_proxy, capture_output=True, text=True, timeout=300)

            if "No such option: -l" in result.stderr or "Error: No such option: -l" in result.stderr:
                logging.warning("[httpx] -l flag rejected. Falling back to positional input.")
                # Fallback: remove -l input_file and add urls directly (limited by shell length, but ok for small sets)
                cmd_fallback = [c for c in cmd if c not in ["-l", input_file]]
                if selected_proxy:
                    cmd_fallback = [c for c in cmd_fallback if c not in ["-http-proxy", selected_proxy]]
                cmd_fallback.extend(targets)
                subprocess.run(cmd_fallback, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=200)
        except subprocess.TimeoutExpired:
            logging.error("[httpx] Timeout occurred.")
        except Exception as e:
            logging.error(f"[httpx] Execution error: {e}")

        parsed = self._parse_jsonl(jsonl_file)
        write_json(out_dir, "httpx_parsed.json", parsed)
        append_manifest(
            out_dir,
            "httpx",
            ["httpx_command.txt", "httpx_input.txt", "httpx_output.jsonl", "httpx_parsed.json"],
            note=f"targets={len(targets)} proxy={selected_proxy or 'direct'}",
        )
        return parsed

    @staticmethod
    def _test_proxy(proxy_str: str, timeout: float = 5.0) -> bool:
        """[BUG-001 FIX] Test proxy connectivity via TCP connect."""
        import socket
        try:
            clean = proxy_str.replace("http://", "").replace("https://", "").replace("socks5h://", "").replace("socks5://", "")
            if ":" in clean:
                host, port_str = clean.rsplit(":", 1)
                port = int(port_str)
            else:
                host, port = clean, 8080
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            sock.close()
            return True
        except Exception:
            return False

    def _parse_jsonl(self, jsonl_file: str) -> list:
        """Parse httpx JSONL output thành structured results."""
        results = []
        if not os.path.exists(jsonl_file):
            return results

        try:
            with open(jsonl_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        results.append({
                            "url": data.get("url", ""),
                            "input": data.get("input", ""),
                            "status_code": data.get("status_code", 0),
                            "title": data.get("title", ""),
                            "tech": data.get("tech", []),
                            "web_server": data.get("webserver", ""),
                            "content_length": data.get("content_length", 0),
                            "host": data.get("host", ""),
                            "port": self._extract_port(data),
                            "scheme": data.get("scheme", ""),
                            "tls": data.get("tls", {}),
                        })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logging.warning(f"[httpx] Failed to parse {jsonl_file}: {e}")

        return results

    @staticmethod
    def _extract_port(data: dict) -> int:
        """Trích xuất port từ httpx output."""
        port = data.get("port", 0)
        if port:
            return int(port)
        url = data.get("url", "")
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            if parsed.port:
                return parsed.port
            return 443 if parsed.scheme == "https" else 80
        except Exception:
            return 80

    def probe_from_ports(self, ip: str, ports: list, out_dir: str = "/tmp", headers: dict = None,
                         proxy_file: str = None, extra_flags: list = None,
                         proxy_mode: str = "recon") -> list:
        """
        Shortcut: Tạo URL targets từ IP + ports, chạy httpx.
        Tự động tạo cả http:// và https:// variants.
        """
        targets = []
        for port in ports:
            port = int(port)
            if port in [443, 8443]:
                targets.append(f"https://{ip}:{port}")
            elif port in [80, 8080, 8081, 8180, 3000, 5000, 8000, 8008, 8888, 9000, 9090]:
                targets.append(f"http://{ip}:{port}")
            else:
                # Thử cả 2
                targets.append(f"http://{ip}:{port}")
                targets.append(f"https://{ip}:{port}")

        probe_flags = list(extra_flags or [])
        if "-nfs" not in probe_flags and "-no-fallback-scheme" not in probe_flags:
            probe_flags.append("-nfs")
        if "-timeout" not in probe_flags:
            probe_flags.extend(["-timeout", "5"])
        if "-retries" not in probe_flags:
            probe_flags.extend(["-retries", "0"])

        return self.run(targets, out_dir=out_dir, headers=headers, proxy_file=proxy_file,
                        extra_flags=probe_flags, proxy_mode=proxy_mode)
