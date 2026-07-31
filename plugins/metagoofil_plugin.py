#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — Metagoofil Plugin
===================================
Metadata extraction from public documents (PDF, DOCX, XLSX, PPTX).
Discovers: usernames, software versions, email addresses, internal paths.

Critical OSINT tool from reconFTW's arsenal — maps to social engineering
and credential gathering phases.
"""

import os
import json
import logging
import subprocess
import shutil
from urllib.parse import urlparse
from core.base_plugin import BasePlugin


class MetagoofilPlugin(BasePlugin):
    """Metagoofil — Public document metadata extraction."""

    def name(self) -> str:
        return "Metagoofil"

    def description(self) -> str:
        return "Metagoofil — Extract metadata (usernames, emails, paths) from public documents."

    def check_installed(self) -> bool:
        return shutil.which("metagoofil") is not None

    @staticmethod
    def _normalize_domain(target: str | list) -> str:
        if isinstance(target, list):
            target = target[0] if target else ""
        target = str(target or "").strip()
        if not target:
            return ""
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split(":")[0].lstrip(".")

    def run(self, domain: str, out_dir: str = "/tmp",
            file_types: list = None, limit: int = 20,
            timeout: int = 300) -> dict:
        """
        Run Metagoofil against a target domain.

        Args:
            domain: Target domain (e.g., "target.com")
            out_dir: Output directory for downloaded docs
            file_types: File extensions to search (default: pdf,doc,xls,ppt,docx,xlsx,pptx)
            limit: Max files to download per type
            timeout: Max execution time in seconds

        Returns:
            dict: {
                "users": [...],          # Discovered usernames/authors
                "emails": [...],         # Embedded email addresses
                "software": [...],       # Software versions found in metadata
                "paths": [...],          # Internal file paths
                "files_analyzed": int,
                "total_findings": int
            }
        """
        domain = self._normalize_domain(domain)
        if not domain:
            logging.warning("[Metagoofil] Empty target domain. Skip.")
            return self._empty_result()

        if not self.check_installed():
            logging.warning("[Metagoofil] Not installed. Install: pip3 install metagoofil")
            return self._empty_result()

        if file_types is None:
            file_types = ["pdf", "doc", "xls", "ppt", "docx", "xlsx", "pptx"]

        os.makedirs(out_dir, exist_ok=True)
        download_dir = os.path.join(out_dir, "downloads")
        os.makedirs(download_dir, exist_ok=True)

        all_users = set()
        all_emails = set()
        all_software = set()
        all_paths = set()
        files_analyzed = 0

        for ftype in file_types:
            cmd = [
                "metagoofil",
                "-d", domain,
                "-t", ftype,
                "-l", str(limit),
                "-o", download_dir,
                "-n", str(limit),
            ]

            try:
                logging.info(f"[Metagoofil] Searching {domain} for .{ftype} files...")
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=timeout,
                )

                # Parse output for metadata findings
                self._parse_output(result.stdout, all_users, all_emails,
                                   all_software, all_paths)
                files_analyzed += result.stdout.count("Downloading")

            except subprocess.TimeoutExpired:
                logging.warning(f"[Metagoofil] Timeout for .{ftype} files after {timeout}s")
            except Exception as e:
                logging.warning(f"[Metagoofil] Error processing .{ftype}: {e}")

        users = sorted(all_users)
        emails = sorted(all_emails)
        software = sorted(all_software)
        paths = sorted(all_paths)

        total = len(users) + len(emails) + len(software) + len(paths)
        logging.info(f"[Metagoofil] Results: {len(users)} users, {len(emails)} emails, "
                     f"{len(software)} software, {len(paths)} paths")

        # Save consolidated results
        results_file = os.path.join(out_dir, "metagoofil_results.json")
        result_data = {
            "users": users,
            "emails": emails,
            "software": software,
            "paths": paths,
            "files_analyzed": files_analyzed,
            "total_findings": total,
        }
        with open(results_file, 'w') as f:
            json.dump(result_data, f, indent=2)

        return result_data

    @staticmethod
    def _parse_output(stdout: str, users: set, emails: set,
                      software: set, paths: set):
        """Parse metagoofil stdout for metadata discoveries."""
        import re

        for line in stdout.splitlines():
            line = line.strip()

            # Users/Authors
            if any(k in line.lower() for k in ['author:', 'creator:', 'last saved by:', 'owner:']):
                parts = line.split(':', 1)
                if len(parts) == 2 and parts[1].strip():
                    user = parts[1].strip()
                    if len(user) > 2 and not user.startswith(('http', '{', '<')):
                        users.add(user)

            # Emails
            found_emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', line)
            emails.update(found_emails)

            # Software versions
            if any(k in line.lower() for k in ['producer:', 'application:', 'pdf-', 'microsoft', 'libreoffice']):
                parts = line.split(':', 1)
                if len(parts) == 2 and parts[1].strip():
                    sw = parts[1].strip()
                    if len(sw) > 3:
                        software.add(sw)

            # Internal paths (Windows/Linux)
            path_matches = re.findall(r'[A-Z]:\\[^\s"\'<>]+|/home/[^\s"\'<>]+|/Users/[^\s"\'<>]+', line)
            paths.update(path_matches)

    @staticmethod
    def _empty_result() -> dict:
        return {
            "users": [],
            "emails": [],
            "software": [],
            "paths": [],
            "files_analyzed": 0,
            "total_findings": 0,
        }
