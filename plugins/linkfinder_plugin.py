import os
import re
import json
import logging
import subprocess
import shutil
import requests
from core.base_plugin import BasePlugin
from core.raw_artifacts import append_manifest, write_json


class LinkFinderPlugin(BasePlugin):
    """LinkFinder + SecretFinder — Trích xuất endpoints và secrets từ JavaScript files."""

    # Regex patterns cho secret detection (từ SecretFinder)
    SECRET_PATTERNS = {
        "aws_access_key": r"(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "aws_secret_key": r"(?i)aws.{0,20}(?:secret|key).{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "stripe_live_key": r"sk_live_[0-9a-zA-Z]{24,}",
        "stripe_test_key": r"sk_test_[0-9a-zA-Z]{24,}",
        "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
        "jwt_token": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        "github_token": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,}",
        "firebase_url": r"https://[a-z0-9-]+\.firebaseio\.com",
        "generic_api_key": r"(?i)(?:api[_-]?key|apikey|api_secret|access_token)\s*[:=]\s*['\"]([a-zA-Z0-9_\-]{16,})['\"]",
        "private_key": r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        "basic_auth": r"(?i)(?:basic|bearer)\s+[a-zA-Z0-9+/=]{20,}",
        "mailgun_key": r"key-[0-9a-zA-Z]{32}",
        "twilio_sid": r"AC[0-9a-fA-F]{32}",
        "sendgrid_key": r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}",
        "heroku_key": r"(?i)heroku.*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    }

    # Regex cho endpoint extraction (từ LinkFinder)
    ENDPOINT_PATTERN = re.compile(
        r"""(?:"|')"""                      # Bắt đầu bằng " hoặc '
        r"""("""
        r"""(?:[a-zA-Z]{1,10}://|//)"""     # Protocol: http://, https://, //
        r"""[^"'/]{1,}"""                   # Domain
        r"""\.[a-zA-Z]{2,}"""              # TLD
        r"""[^"']{0,}"""                   # Rest
        r"""|"""
        r"""(?:/|\.\./|\./)"""             # Relative path
        r"""[^"'><,;| *()(%%$^/\\\[\]]"""  # Valid path chars
        r"""[^"'><,;|()]{1,}"""
        r"""|"""
        r"""(?:[a-zA-Z0-9_\-/]{1,}/"""     # Path segments
        r"""[a-zA-Z0-9_\-/]{1,}"""
        r"""\.(?:[a-zA-Z]{1,4}|action)"""  # Extension
        r"""(?:[\?|#][^"|']{0,}|))"""
        r"""|"""
        r"""(?:[a-zA-Z0-9_\-/]{1,}/"""
        r"""[a-zA-Z0-9_\-/]{3,}"""         # Longer paths
        r"""(?:[\?|#][^"|']{0,}|))"""
        r"""|"""
        r"""(?:[a-zA-Z0-9_\-]{1,}"""
        r"""\.(?:php|asp|aspx|jsp|json"""
        r"""|action|html|js|txt|xml)"""
        r"""(?:[\?|#][^"|']{0,}|))"""
        r""")"""
        r"""(?:"|')""",
        re.VERBOSE
    )

    def name(self) -> str:
        return "LinkFinder"

    def description(self) -> str:
        return "LinkFinder + SecretFinder — Trích xuất endpoints ẩn và hardcoded secrets từ JS files."

    def check_installed(self) -> bool:
        # Plugin sử dụng logic nội tuyến (regex), không cần external binary
        return True

    def run(self, js_urls: list, out_dir: str = "/tmp",
            timeout: int = 15, max_files: int = 50) -> dict:
        """
        Phân tích danh sách JS URLs để trích xuất endpoints và secrets.

        Args:
            js_urls: Danh sách URL file JavaScript
            out_dir: Thư mục output
            timeout: Timeout download mỗi JS file (giây)
            max_files: Giới hạn số file JS phân tích

        Returns:
            dict: {"endpoints": [...], "secrets": [{"type": "...", "value": "...", "source": "..."}]}
        """
        os.makedirs(out_dir, exist_ok=True)
        write_json(out_dir, "linkfinder_input_js_urls.json", js_urls[:max_files])
        all_endpoints = set()
        all_secrets = []
        seen_secrets = set()

        for js_url in js_urls[:max_files]:
            js_url = js_url.strip()
            if not js_url:
                continue

            try:
                resp = requests.get(js_url, timeout=timeout, verify=False,
                                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"})
                if resp.status_code != 200:
                    continue
                content = resp.text
                if not content or len(content) < 50:
                    continue

                # Extract endpoints
                endpoints = self._extract_endpoints(content)
                all_endpoints.update(endpoints)

                # Extract secrets
                secrets = self._extract_secrets(content, js_url)
                for s in secrets:
                    sig = f"{s['type']}:{s['value'][:30]}"
                    if sig not in seen_secrets:
                        seen_secrets.add(sig)
                        all_secrets.append(s)

            except requests.exceptions.Timeout:
                logging.debug(f"[LinkFinder] Timeout downloading {js_url}")
            except Exception as e:
                logging.debug(f"[LinkFinder] Error processing {js_url}: {e}")

        # Lưu output
        result = {
            "endpoints": sorted(list(all_endpoints)),
            "endpoint_urls": sorted(list(all_endpoints)),
            "secrets": all_secrets,
            "secret_findings": all_secrets,
            "files_analyzed": min(len(js_urls), max_files),
            "summary": {
                "endpoints": len(all_endpoints),
                "secrets": len(all_secrets),
                "files_analyzed": min(len(js_urls), max_files),
            },
        }

        output_path = os.path.join(out_dir, "linkfinder_results.json")
        try:
            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception:
            pass
        append_manifest(
            out_dir,
            "linkfinder",
            ["linkfinder_input_js_urls.json", "linkfinder_results.json"],
            note=f"js_files={min(len(js_urls), max_files)}",
        )

        logging.info(f"[LinkFinder] Trích xuất {len(all_endpoints)} endpoints, {len(all_secrets)} secrets từ {min(len(js_urls), max_files)} JS files.")
        return result

    def _extract_endpoints(self, content: str) -> set:
        """Trích xuất endpoints từ nội dung JavaScript."""
        endpoints = set()
        matches = self.ENDPOINT_PATTERN.findall(content)
        for match in matches:
            match = match.strip()
            if match and len(match) > 3 and not match.startswith("//"):
                # === V1.0: Bộ lọc noise mở rộng ===
                match_lower = match.lower()
                if any(noise in match_lower for noise in [
                    # Thư viện front-end phổ biến
                    'jquery', 'bootstrap', 'fontawesome', 'googleapis',
                    'polyfill', 'lodash', 'moment', 'react-dom',
                    # Static assets
                    '.css', '.png', '.jpg', '.gif', '.svg', '.ico',
                    '.woff', '.woff2', '.ttf', '.eot', '.map',
                    # Schema/namespace noise
                    'w3.org', 'schema.org', 'xmlns', 'xmlsoap',
                    # Node/package noise
                    'node_modules/', 'bower_components/', '/vendor/',
                    '/__pycache__/', '/dist/', '/build/',
                    # Timezone strings (hay xuất hiện trong moment.js)
                    'america/', 'europe/', 'asia/', 'pacific/',
                    'africa/', 'atlantic/', 'australia/',
                ]):
                    continue

                # Loại bỏ Flash/ActiveX UUID cổ (D27CDB6E-AE6D...)
                if match.upper().startswith("D27CDB6E"):
                    continue

                # Loại bỏ các chuỗi quá ngắn hoặc chỉ là version number
                if len(match) < 5:
                    continue
                # Bỏ qua nếu chỉ toàn số và dấu chấm (vd: "1.2.3", "2024.01")
                cleaned = match.replace("/", "").replace(".", "").replace("-", "")
                if cleaned.isdigit():
                    continue

                endpoints.add(match)
        return endpoints

    def _extract_secrets(self, content: str, source_url: str) -> list:
        """Tìm secrets (API keys, tokens, etc.) trong nội dung JavaScript."""
        secrets = []
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = re.findall(pattern, content)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                if match and len(match) >= 10:
                    secrets.append({
                        "type": secret_type,
                        "value": match[:100],  # Truncate dài
                        "source": source_url,
                    })
        return secrets
