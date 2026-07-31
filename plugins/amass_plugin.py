#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OWASP AMASS OSINT PLUGIN — PenLabs V1.0
=========================================
Plugin tận dụng OWASP Amass (https://github.com/owasp-amass/amass)
để thu thập thông tin hạ tầng mục tiêu từ hơn 80+ nguồn OSINT.

Chế độ: Passive Enum (không gửi bất kỳ gói tin nào tới target).
Output: Subdomains, IPs, ASN, Org, và infrastructure context.
"""

import logging
import os
import json
import shutil
import subprocess
import tempfile
import re

from core.base_plugin import BasePlugin


class AmassPlugin(BasePlugin):
    """
    OWASP Amass — Gold-standard Open-Source Infrastructure OSINT.
    Chạy passive enumeration để thu thập:
    - Subdomains
    - IP addresses (Resolved)
    - ASN / Org metadata
    - Components (inferred from banner/service data)
    """

    def name(self) -> str:
        return "Amass"

    def description(self) -> str:
        return "OWASP Amass passive OSINT: subdomain, IP, ASN, infrastructure enumeration từ 80+ nguồn."

    def check_installed(self) -> bool:
        return shutil.which("amass") is not None

    def run(self, target: str, output_dir: str = None, timeout: int = 600, config_file: str = None) -> dict:
        """
        Chạy Amass passive enum cho một domain.
        
        Args:
            target: Domain cần enum (vd: example.com)
            output_dir: Thư mục lưu kết quả thô
            timeout: Thời gian tối đa (giây), mặc định 300s
            config_file: (Optional) đường dẫn tới amass config.yaml

        Returns:
            dict {
                "subdomains": [...],
                "ips": [...],
                "asn_info": [...],
                "ports": [...],          # Historical ports (nếu có)
                "components": [...],     # Tech stack (nếu có)
                "raw_count": int
            }
        """
        results = {
            "subdomains": [],
            "ips": set(),
            "asn_info": [],
            "ports": set(),
            "components": set(),
            "raw_count": 0,
        }

        if not self.check_installed():
            logging.warning("[Amass] Không tìm thấy amass binary. Skip.")
            return self._serialize(results)

        timeout = min(timeout, 600)  # Capped at 10 minutes to prevent hanging

        # Chuẩn bị output directory
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            txt_output = os.path.join(output_dir, "amass_enum.txt")
        else:
            fd, txt_output = tempfile.mkstemp(suffix=".txt", prefix="amass_")
            os.close(fd)
            os.unlink(txt_output)

        # [AMASS V5 FIX]
        # Step 1: Run enumeration to populate DB
        enum_cmd = [
            "amass", "enum",
            "-d", target,
            "-timeout", str(max(timeout // 60, 1)), # Amass dùng phút
            "-silent",
        ]
        if config_file and os.path.isfile(config_file):
            enum_cmd.extend(["-config", config_file])

        logging.info(f"[Amass] Bắt đầu passive enum cho {target} (timeout {timeout}s)...")

        try:
            # Chạy enum trước
            subprocess.run(enum_cmd, capture_output=True, timeout=timeout + 60)

            # Step 2: Extract results dùng 'amass subs'
            logging.info(f"[Amass] Đang trích xuất kết quả từ DB...")
            subs_cmd = [
                "amass", "subs",
                "-d", target,
                "-names",
                "-o", txt_output
            ]
            proc = subprocess.run(subs_cmd, capture_output=True, text=True, timeout=120)

            if proc.returncode != 0 and proc.stderr:
                logging.debug(f"[Amass] subs stderr: {proc.stderr.strip()[:200]}")
        except subprocess.TimeoutExpired:
            logging.warning(f"[Amass] Timeout sau {timeout}s. Đọc kết quả partial.")
        except FileNotFoundError:
            logging.error("[Amass] Binary không tìm thấy tại runtime.")
            return self._serialize(results)
        except Exception as e:
            logging.warning(f"[Amass] Lỗi thực thi: {e}")

        # Parse text output từ Amass v5
        if os.path.isfile(txt_output):
            results = self._parse_text_output(txt_output, results)
            logging.info(
                f"[Amass] Thu được: {len(results['subdomains'])} subdomains "
                f"(IPs/ASN sẽ được phân giải bởi module khác)"
            )
        else:
            logging.warning("[Amass] Không tạo được file output. Amass có thể đã crash hoặc không tìm thấy kết quả.")

        return self._serialize(results)

    def _parse_text_output(self, filepath: str, results: dict) -> dict:
        """
        Parse Amass v5 text output.
        Amass v5 với -o xuất mỗi dòng là một subdomain hoặc FQDN.
        """
        seen_subs = set()

        try:
            with open(filepath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    results["raw_count"] += 1

                    # Amass v5 -o chỉ xuất hostnames, mỗi dòng 1 cái
                    if line not in seen_subs and "." in line:
                        seen_subs.add(line)
                        results["subdomains"].append(line)

        except Exception as e:
            logging.warning(f"[Amass] Parse error: {e}")

        return results

    def _serialize(self, results: dict) -> dict:
        """Convert sets thành lists để tương thích JSON."""
        return {
            "subdomains": results.get("subdomains", []),
            "ips": list(results.get("ips", set())),
            "asn_info": results.get("asn_info", []),
            "ports": sorted(list(results.get("ports", set()))),
            "components": list(results.get("components", set())),
            "raw_count": results.get("raw_count", 0),
        }
