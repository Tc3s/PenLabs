#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
THEHARVESTER OSINT PLUGIN — PenLabs V1.0
==========================================
Plugin tận dụng theHarvester (https://github.com/laramies/theHarvester)
để cào thông tin từ các search engines (Google, Bing, crt.sh, etc.)

Chế độ: Passive scraping (không gửi request trực tiếp tới target).
Output: Emails, Hosts/Subdomains, IPs.
"""

import logging
import os
import json
import shutil
import subprocess
import tempfile

from core.base_plugin import BasePlugin


class TheHarvesterPlugin(BasePlugin):
    """
    theHarvester — Search Engine OSINT Scraper.
    Thu thập thông tin mục tiêu từ:
    - Google, Bing, DuckDuckGo (Search Engines)
    - crt.sh, CertSpotter (Certificate Transparency)
    - DNSdumpster, ThreatMiner (DNS/Threat Intel)
    - Rapiddns, Urlscan (Passive DNS)
    """

    # Nguồn dữ liệu ưu tiên (ổn định, miễn phí, không cần API key)
    _FREE_SOURCES = [
        "crtsh",
        "dnsdumpster",
        "rapiddns",
        "threatcrowd",
        "urlscan",
        "certspotter",
        "hackertarget",
        "otx",
        "duckduckgo",
        "yahoo",
        "baidu",
    ]

    def name(self) -> str:
        return "TheHarvester"

    def description(self) -> str:
        return "theHarvester OSINT: cào subdomain, email, IP từ search engines và certificate logs."

    def check_installed(self) -> bool:
        return shutil.which("theHarvester") is not None

    def run(self, target: str, output_dir: str = None, limit: int = 500, timeout: int = 600, sources: list = None) -> dict:
        """
        Chạy theHarvester cho một domain.

        Args:
            target: Domain cần cào (vd: example.com)
            output_dir: Thư mục lưu kết quả thô
            limit: Số kết quả tối đa mỗi nguồn
            timeout: Thời gian tối đa (giây)
            sources: Danh sách nguồn tùy chỉnh (mặc định: _FREE_SOURCES)

        Returns:
            dict {
                "subdomains": [...],
                "emails": [...],
                "ips": [...],
                "interesting_urls": [...],
            }
        """
        results = {
            "subdomains": [],
            "emails": [],
            "ips": [],
            "interesting_urls": [],
        }

        if not self.check_installed():
            logging.warning("[theHarvester] Không tìm thấy theHarvester binary. Skip.")
            return results

        # Chọn nguồn dữ liệu
        active_sources = sources or self._FREE_SOURCES
        sources_str = ",".join(active_sources)

        # Chuẩn bị output
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            output_base = os.path.join(output_dir, "theharvester_result")
        else:
            fd, output_base = tempfile.mkstemp(prefix="theharvester_")
            os.close(fd)
            os.unlink(output_base)

        # Build command
        cmd = [
            "theHarvester",
            "-d", target,
            "-l", str(limit),
            "-b", sources_str,
            "-f", output_base,  # Tạo file .json và .xml
        ]

        logging.info(f"[theHarvester] Bắt đầu scraping {target} từ {len(active_sources)} nguồn (limit={limit})...")

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if proc.returncode != 0 and proc.stderr:
                stderr_clean = proc.stderr.strip()[:500]
                if stderr_clean and "error" in stderr_clean.lower():
                    logging.debug(f"[theHarvester] stderr: {stderr_clean}")

            # Parse stdout nếu có (fallback khi JSON bị lỗi)
            if proc.stdout:
                results = self._parse_stdout(proc.stdout, results, target)

        except subprocess.TimeoutExpired:
            logging.warning(f"[theHarvester] Timeout sau {timeout}s. Đọc kết quả partial.")
        except FileNotFoundError:
            logging.error("[theHarvester] Binary không tìm thấy tại runtime.")
            return results
        except Exception as e:
            logging.warning(f"[theHarvester] Lỗi thực thi: {e}")

        # Parse JSON output (ưu tiên)
        json_file = f"{output_base}.json"
        if os.path.isfile(json_file):
            results = self._parse_json(json_file, results, target)

        # Deduplicate
        results["subdomains"] = sorted(set(results["subdomains"]))
        results["emails"] = sorted(set(results["emails"]))
        results["ips"] = sorted(set(results["ips"]))
        results["interesting_urls"] = sorted(set(results["interesting_urls"]))

        logging.info(
            f"[theHarvester] Thu được: {len(results['subdomains'])} hosts, "
            f"{len(results['emails'])} emails, {len(results['ips'])} IPs"
        )
        return results

    def _parse_json(self, filepath: str, results: dict, target: str) -> dict:
        """Parse theHarvester JSON output file."""
        try:
            with open(filepath, "r") as f:
                data = json.load(f)

            # Hosts
            for host in data.get("hosts", []):
                if isinstance(host, str):
                    # Format: "host:ip" hoặc chỉ "host"
                    parts = host.split(":")
                    hostname = parts[0].strip()
                    if hostname and target in hostname:
                        results["subdomains"].append(hostname)
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if ip and self._is_valid_ip(ip):
                            results["ips"].append(ip)

            # Emails
            for email in data.get("emails", []):
                if isinstance(email, str) and "@" in email:
                    results["emails"].append(email.strip())

            # IPs
            for ip in data.get("ips", []):
                if isinstance(ip, str) and self._is_valid_ip(ip):
                    results["ips"].append(ip.strip())

            # Interesting URLs
            for url in data.get("interesting_urls", []):
                if isinstance(url, str):
                    results["interesting_urls"].append(url.strip())

        except json.JSONDecodeError:
            logging.debug(f"[theHarvester] JSON parse error cho {filepath}")
        except Exception as e:
            logging.debug(f"[theHarvester] Parse error: {e}")

        return results

    def _parse_stdout(self, stdout: str, results: dict, target: str) -> dict:
        """
        Fallback parser: trích xuất từ stdout khi JSON output không khả dụng.
        theHarvester in kết quả theo blocks: [*] Hosts found, [*] Emails found, etc.
        """
        current_section = None
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("*"):
                continue

            # Detect section headers
            lower = line.lower()
            if "hosts found" in lower or "hosts:" in lower:
                current_section = "hosts"
                continue
            elif "emails found" in lower or "emails:" in lower:
                current_section = "emails"
                continue
            elif "ips found" in lower or "ip" in lower and "found" in lower:
                current_section = "ips"
                continue
            elif "interesting" in lower:
                current_section = "urls"
                continue
            elif line.startswith("[") or line.startswith("-"):
                continue

            # Parse entries by section
            if current_section == "hosts" and target in line:
                # Dạng "hostname:ip"
                parts = line.split(":")
                hostname = parts[0].strip()
                if hostname:
                    results["subdomains"].append(hostname)
                if len(parts) > 1 and self._is_valid_ip(parts[1].strip()):
                    results["ips"].append(parts[1].strip())

            elif current_section == "emails" and "@" in line:
                results["emails"].append(line)

            elif current_section == "ips" and self._is_valid_ip(line):
                results["ips"].append(line)

            elif current_section == "urls" and ("http://" in line or "https://" in line):
                results["interesting_urls"].append(line)

        return results

    @staticmethod
    def _is_valid_ip(s: str) -> bool:
        """Kiểm tra nhanh format IPv4."""
        parts = s.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
