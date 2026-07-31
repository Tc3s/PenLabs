#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — EmailFinder Plugin
====================================
Email harvesting from publicly accessible sources.
Supports: Google, Bing, Baidu, LinkedIn (passive OSINT).

Covers the email enumeration GAP vs reconFTW.
"""

import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin


class EmailFinderPlugin(BasePlugin):
    """EmailFinder — Harvest email addresses from public sources."""

    def name(self) -> str:
        return "EmailFinder"

    def description(self) -> str:
        return "EmailFinder — Harvest email addresses from Google, Bing, Baidu, LinkedIn."

    def check_installed(self) -> bool:
        """Check if emailfinder is installed (pip package)."""
        return shutil.which("emailfinder") is not None

    def run(self, domain: str, out_dir: str = "/tmp",
            timeout: int = 120) -> dict:
        """
        Run emailfinder against a target domain.

        Args:
            domain: Target domain (e.g., "target.com")
            out_dir: Output directory
            timeout: Max execution time in seconds

        Returns:
            dict: {
                "emails": [...],         # List of discovered emails
                "sources": {...},        # Emails grouped by source
                "total": int
            }
        """
        if not self.check_installed():
            logging.warning("[EmailFinder] Not installed. Install: pip3 install emailfinder")
            return {"emails": [], "sources": {}, "total": 0}

        os.makedirs(out_dir, exist_ok=True)
        output_file = os.path.join(out_dir, "emailfinder_output.txt")

        cmd = [
            "emailfinder",
            "-d", domain,
        ]

        try:
            logging.info(f"[EmailFinder] Harvesting emails for {domain}...")
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )

            # Parse stdout (emailfinder prints to stdout)
            emails = set()
            for line in result.stdout.splitlines():
                line = line.strip()
                if '@' in line and '.' in line:
                    # Extract email-like strings
                    import re
                    found = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', line)
                    emails.update(found)

            # Also check stderr for any output
            for line in result.stderr.splitlines():
                line = line.strip()
                if '@' in line:
                    import re
                    found = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', line)
                    emails.update(found)

            # Filter to target domain and known providers
            domain_emails = [e for e in emails if domain in e]
            other_emails = [e for e in emails if domain not in e]

            all_emails = sorted(domain_emails + other_emails)

            # Save to file
            with open(output_file, 'w') as f:
                for email in all_emails:
                    f.write(f"{email}\n")

            logging.info(f"[EmailFinder] Found {len(all_emails)} emails ({len(domain_emails)} in-domain)")

            return {
                "emails": all_emails,
                "domain_emails": domain_emails,
                "other_emails": other_emails,
                "total": len(all_emails),
            }

        except subprocess.TimeoutExpired:
            logging.warning(f"[EmailFinder] Timeout after {timeout}s")
        except Exception as e:
            logging.error(f"[EmailFinder] Execution error: {e}")

        return {"emails": [], "sources": {}, "total": 0}
