import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence
from core.raw_artifacts import append_manifest, write_command, write_json, write_text


class WPScanPlugin(BasePlugin):
    """WPScan — WordPress vulnerability scanner (pre-installed on Kali Linux)."""

    def name(self) -> str:
        return "WPScan"

    def description(self) -> str:
        return "WPScan — Quét WordPress: enum users/plugins/themes, phát hiện CVE."

    def check_installed(self) -> bool:
        return shutil.which("wpscan") is not None

    @staticmethod
    def detect_wordpress(url: str, timeout: int = 10) -> bool:
        """Kiểm tra nhanh xem URL có phải WordPress không."""
        import requests
        try:
            resp = requests.get(url, timeout=timeout, verify=False,
                                headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
            content = resp.text.lower()
            # Check các dấu hiệu WordPress
            wp_indicators = [
                "wp-content", "wp-includes", "wp-json",
                'name="generator" content="wordpress',
                "wordpress.org", "/xmlrpc.php",
            ]
            return any(indicator in content for indicator in wp_indicators)
        except Exception:
            return False

    def run(self, url: str, out_dir: str = "/tmp",
            api_token: str = "", enumerate: str = "vp,vt,u",
            timeout: int = 300, random_agent: bool = True,
            proxy: str = "", proxy_mode: str = "exploit") -> dict:
        """
        Chạy WPScan trên một WordPress URL.
        """
        if not self.check_installed():
            logging.warning("[WPScan] wpscan not installed. Skip.")
            return {}

        #  Unified Proxy Logic
        from config import Config as _Cfg
        effective_proxy = _Cfg.get_proxy_url(proxy_mode) or proxy

        os.makedirs(out_dir, exist_ok=True)
        json_output = os.path.join(out_dir, "wpscan_output.json")

        cmd = [
            "wpscan",
            "--url", url,
            "-e", enumerate,
            "--format", "json",
            "--output", json_output,
            "--detection-mode", "mixed",
            "--max-threads", "5",
            "--request-timeout", "20",
            "--connect-timeout", "15",
            "--throttle", "200",  # 200ms delay — tránh bị block
            "--no-update",  # Không update DB để nhanh hơn
        ]

        if api_token:
            cmd.extend(["--api-token", api_token])
        if random_agent:
            cmd.append("--random-user-agent")
        if effective_proxy:
            cmd.extend(["--proxy", effective_proxy])
            logging.info(f"[WPScan] Using {proxy_mode.upper()} proxy: {effective_proxy}")

        write_command(out_dir, "wpscan_command.txt", cmd)
        # Chạy WPScan
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=timeout
            )
            write_text(out_dir, "wpscan_stdout.txt", proc.stdout)
            write_text(out_dir, "wpscan_stderr.txt", proc.stderr)
        except subprocess.TimeoutExpired:
            logging.warning(f"[WPScan] Timeout ({timeout}s) cho {url}. Đang parse partial results...")
        except Exception as e:
            logging.warning(f"[WPScan] Error: {e}")

        # Parse JSON output
        result = self._parse_wpscan_json(json_output)
        if result:
            vuln_count = len(result.get("vulnerabilities", []))
            plugin_count = len(result.get("plugins", []))
            user_count = len(result.get("users", []))
            logging.info(f"[WPScan] WordPress {result.get('version', '?')}: "
                         f"{vuln_count} vulns, {plugin_count} plugins, {user_count} users.")
        write_json(out_dir, "wpscan_parsed.json", result)
        append_manifest(
            out_dir,
            "wpscan",
            ["wpscan_command.txt", "wpscan_stdout.txt", "wpscan_stderr.txt", os.path.basename(json_output), "wpscan_parsed.json"],
            note=f"url={url} vulns={len(result.get('vulnerabilities', [])) if result else 0}",
        )
        return result

    def _with_evidence(self, finding: dict, json_path: str) -> dict:
        title = finding.get("title") or finding.get("to_s") or finding.get("type", "wpscan finding")
        return attach_evidence(
            finding,
            make_evidence(
                method="GET",
                url=finding.get("url", ""),
                payload={"source": finding.get("type", "wordpress")},
                validation=f"WPScan JSON output reported: {title}",
                raw_artifact=json_path,
                confidence="high" if finding.get("severity") in ("critical", "high") else "medium",
            ),
        )

    def _parse_wpscan_json(self, json_path: str) -> dict:
        """Parse WPScan JSON output thành format chuẩn."""
        result = {
            "detected": False,
            "version": "",
            "main_theme": {},
            "themes": [],
            "plugins": [],
            "users": [],
            "vulnerabilities": [],
            "findings": [],
            "interesting_findings": [],
            "summary": {
                "vulnerabilities": 0,
                "plugins": 0,
                "users": 0,
                "themes": 0,
            },
        }

        if not os.path.exists(json_path):
            return result

        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            return result

        # WordPress version
        version_data = data.get("version", {})
        if version_data:
            result["detected"] = True
            result["version"] = version_data.get("number", "")
            for vuln in version_data.get("vulnerabilities", []):
                result["vulnerabilities"].append(self._with_evidence({
                    "title": vuln.get("title", ""),
                    "type": "core",
                    "fixed_in": vuln.get("fixed_in", ""),
                    "references": vuln.get("references", {}),
                    "severity": self._vuln_severity(vuln),
                }, json_path))

        # Plugins
        plugins = data.get("plugins", {})
        for name, pdata in plugins.items():
            plugin_info = {
                "name": name,
                "version": pdata.get("version", {}).get("number", ""),
                "vulnerabilities": [],
            }
            for vuln in pdata.get("vulnerabilities", []):
                plugin_vuln = self._with_evidence({
                    "title": vuln.get("title", ""),
                    "type": f"plugin:{name}",
                    "fixed_in": vuln.get("fixed_in", ""),
                    "severity": self._vuln_severity(vuln),
                }, json_path)
                plugin_info["vulnerabilities"].append(plugin_vuln)
                result["vulnerabilities"].append(plugin_vuln)
            result["plugins"].append(plugin_info)

        # Themes
        themes = data.get("main_theme", {})
        if themes:
            result["detected"] = True
            theme_info = {
                "name": themes.get("slug", ""),
                "version": themes.get("version", {}).get("number", ""),
                "vulnerabilities": [],
            }
            for vuln in themes.get("vulnerabilities", []):
                theme_vuln = self._with_evidence({
                    "title": vuln.get("title", ""),
                    "type": f"theme:{themes.get('slug', '')}",
                    "severity": self._vuln_severity(vuln),
                }, json_path)
                theme_info["vulnerabilities"].append(theme_vuln)
                result["vulnerabilities"].append(theme_vuln)
            result["themes"].append(theme_info)
            result["main_theme"] = theme_info

        # Users
        users = data.get("users", {})
        for username, udata in users.items():
            result["detected"] = True
            result["users"].append({
                "username": username,
                "id": udata.get("id", ""),
            })

        # Interesting findings
        for finding in data.get("interesting_findings", []):
            result["interesting_findings"].append(self._with_evidence({
                "url": finding.get("url", ""),
                "type": finding.get("type", ""),
                "to_s": finding.get("to_s", ""),
                "severity": "info",
            }, json_path))

        result["findings"] = list(result["vulnerabilities"])
        result["summary"] = {
            "vulnerabilities": len(result["vulnerabilities"]),
            "plugins": len(result["plugins"]),
            "users": len(result["users"]),
            "themes": len(result["themes"]),
        }

        return result

    @staticmethod
    def _vuln_severity(vuln: dict) -> str:
        """Xác định severity từ vuln data."""
        title = vuln.get("title", "").lower()
        if any(kw in title for kw in ["rce", "remote code", "sql injection", "unauthenticated"]):
            return "critical"
        elif any(kw in title for kw in ["xss", "csrf", "ssrf", "lfi", "file inclusion"]):
            return "high"
        elif any(kw in title for kw in ["information disclosure", "redirect"]):
            return "medium"
        return "medium"
