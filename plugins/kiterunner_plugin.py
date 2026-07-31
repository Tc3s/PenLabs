import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin
from core.raw_artifacts import append_manifest, write_command, write_json


class KiterunnerPlugin(BasePlugin):
    """Kiterunner (kr) — API route discovery bằng Swagger/OpenAPI wordlists."""

    def name(self) -> str:
        return "Kiterunner"

    def description(self) -> str:
        return "Kiterunner — Brute-force API routes với contextual .kite wordlists (Assetnote)."

    def check_installed(self) -> bool:
        if shutil.which("kr"):
            return True
        go_bin = os.path.expanduser("~/go/bin/kr")
        return os.path.isfile(go_bin) and os.access(go_bin, os.X_OK)

    def run(self, targets: list, out_dir: str = "/tmp",
            wordlist: str = "", max_connections: int = 10,
            headers: dict = None, timeout: int = 300) -> list:
        """
        Chạy Kiterunner scan trên danh sách URL targets.

        Args:
            targets: List các base URL (http://target.com)
            out_dir: Thư mục output
            wordlist: Path tới file .kite (mặc định: routes-small.kite)
            max_connections: Concurrent connections (giữ thấp tránh bị block)
            headers: Custom HTTP headers (vd: Authorization)
            timeout: Timeout tổng (giây) — chống treo

        Returns:
            list: [{"url": "...", "status": 200, "length": 1234, "method": "GET"}, ...]
        """
        if not self.check_installed():
            logging.warning("[Kiterunner] kr not installed. Skip.")
            return []

        os.makedirs(out_dir, exist_ok=True)

        # Tìm wordlist
        if not wordlist or not os.path.exists(wordlist):
            try:
                from core.wordlist_registry import resolve_wordlist
                wordlist = resolve_wordlist("api_routes", out_dir=out_dir).get("path", "")
            except Exception:
                wordlist = ""
            if not wordlist:
                logging.warning("[Kiterunner] No .kite wordlist found. Using built-in.")

        results = []
        seen = set()
        for target_idx, target_url in enumerate(targets[:10]):  # Giới hạn 10 targets tránh quá tải
            target_url = target_url.strip()
            if not target_url:
                continue

            output_file = os.path.join(out_dir, f"kr_output_{target_idx}.txt")
            kr_bin = shutil.which("kr") or os.path.expanduser("~/go/bin/kr")
            cmd = [kr_bin, "scan", target_url]

            if wordlist:
                cmd.extend(["-w", wordlist])
            cmd.extend(["-x", str(max_connections)])

            # [V1.0-APEX] Tier 1 Anti-FP cho Kiterunner (Lọc thô)
            # 1. Bỏ qua các mã trạng thái không mang tính Vulnerability (Bad Request, Not Found, Rate Limit)
            # Giúp loại bỏ Soft-404 Catch-all của React/NextJS
            cmd.extend(["--ignore-status", "404,400,429,502,503"])

            if headers:
                SAFE_HEADERS = {"user-agent", "cookie", "authorization", "referer", "x-forwarded-for", "accept", "accept-language"}
                for k, v in headers.items():
                    if k.lower() in SAFE_HEADERS:
                        clean_v = str(v).replace('"', '')
                        cmd.extend(["-H", f"{k}: {clean_v}"])

            write_command(out_dir, f"kr_command_{target_idx}.txt", cmd)

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True, text=True,
                    timeout=timeout
                )
                # Parse kr text output: METHOD STATUS_CODE URL [LENGTH]
                for line in proc.stdout.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    parsed = self._parse_kr_line(line)
                    if parsed:
                        sig = (parsed.get("method"), parsed.get("url"), parsed.get("status_code"))
                        if sig in seen:
                            continue
                        seen.add(sig)
                        results.append(parsed)

                # Lưu raw output
                with open(output_file, 'w') as f:
                    f.write(proc.stdout)

            except subprocess.TimeoutExpired:
                logging.warning(f"[Kiterunner] Timeout ({timeout}s) cho {target_url}. Skip.")
            except Exception as e:
                logging.warning(f"[Kiterunner] Error scanning {target_url}: {e}")

        logging.info(f"[Kiterunner] Tìm thấy {len(results)} API endpoints.")
        write_json(out_dir, "kiterunner_parsed.json", results)
        append_manifest(
            out_dir,
            "kiterunner",
            ["kr_output_*.txt", "kr_command_*.txt", "kiterunner_parsed.json"],
            note=f"targets={min(len(targets), 10)}",
        )
        return results

    @staticmethod
    def _parse_kr_line(line: str) -> dict:
        """Parse dòng output của kr scan thành dict."""
        # Format thường: GET     200 [   1234] https://target.com/api/v1/users
        # Hoặc: GET 200 https://target.com/api/v1/users [1234,json]
        try:
            parts = line.split()
            if len(parts) < 3:
                return None

            method = parts[0].upper()
            if method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                return None

            # Tìm status code
            status = None
            url = None
            length = 0
            for p in parts[1:]:
                if p.isdigit() and status is None:
                    status = int(p)
                elif p.startswith("http") and url is None:
                    url = p
                elif p.startswith("[") and p.endswith("]"):
                    try:
                        length = int(p.strip("[]").split(",")[0])
                    except ValueError:
                        pass

            if url and status:
                # [V1.0-APEX] Tier 1.5 Anti-FP (Fallback Python Filter)
                # Loại bỏ tuyệt đối các mã 400, 404, 429, 503 nếu tool Go bỏ lọt
                if status in [400, 404, 429, 502, 503]:
                    return None
                    
                return {
                    "url": url,
                    "status": status,
                    "status_code": status,
                    "length": length,
                    "content_length": length,
                    "method": method,
                    "source": "kiterunner",
                }
        except Exception:
            pass
        return None
