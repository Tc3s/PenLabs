"""cloud_enum plugin wrapper for multi-cloud storage enumeration."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from typing import Dict, List, Optional

from core.base_plugin import BasePlugin


class CloudEnumPlugin(BasePlugin):
    """Wrap initstring/cloud_enum and normalize findings by provider."""

    PROVIDERS = ("aws", "azure", "gcp")

    def name(self) -> str:
        return "CloudEnum"

    def description(self) -> str:
        return "Multi-cloud storage enumeration (S3, Azure Blob, GCS)."

    def check_installed(self) -> bool:
        return self._executable() is not None

    def run(
        self,
        target: str,
        providers: Optional[List[str]] = None,
        timeout: int = 300,
        keywords: Optional[List[str]] = None,
    ):
        providers = [p for p in (providers or list(self.PROVIDERS)) if p in self.PROVIDERS]
        results: Dict[str, List[Dict]] = {provider: [] for provider in providers}
        exe = self._executable()
        if not exe:
            results["error"] = [{"error": "cloud_enum not installed"}]
            return results

        for keyword in self._keywords(target, keywords):
            cmd = self._build_command(exe, keyword, providers)
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                logging.warning("[CloudEnum] timeout for keyword=%s", keyword)
                continue
            except OSError as exc:
                logging.warning("[CloudEnum] failed for keyword=%s: %s", keyword, exc)
                continue

            parsed = self._parse_output((proc.stdout or "") + "\n" + (proc.stderr or ""))
            for provider, findings in parsed.items():
                if provider in results:
                    results[provider].extend(findings)
        return {provider: self._dedupe(findings) for provider, findings in results.items()}

    @staticmethod
    def _executable() -> Optional[str]:
        import sys
        venv_bin = os.path.dirname(sys.executable)
        return (
            shutil.which("cloud_enum")
            or shutil.which("cloud_enum.py")
            or shutil.which(os.path.join(venv_bin, "cloud_enum"))
            or shutil.which(os.path.join(venv_bin, "cloud_enum.py"))
        )

    def _build_command(self, exe: str, keyword: str, providers: List[str]) -> List[str]:
        """Build a cloud_enum command while disabling out-of-scope providers."""
        cmd = [exe, "-k", keyword]
        disabled_flags = {
            "aws": "--disable-aws",
            "azure": "--disable-azure",
            "gcp": "--disable-gcp",
        }
        for provider, flag in disabled_flags.items():
            if provider not in providers:
                cmd.append(flag)
        return cmd

    def _keywords(self, target: str, extra_keywords: Optional[List[str]] = None) -> List[str]:
        base = re.sub(r"^https?://", "", target.lower()).split("/", 1)[0].split(":", 1)[0]
        dashed = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
        company = dashed.split("-")[0] if dashed else base
        keywords = [base, dashed, company]
        keywords.extend(extra_keywords or [])
        seen = set()
        return [k for k in keywords if k and not (k in seen or seen.add(k))]

    def _parse_output(self, output: str) -> Dict[str, List[Dict]]:
        findings: Dict[str, List[Dict]] = {provider: [] for provider in self.PROVIDERS}
        provider_hint = "unknown"
        for raw in output.splitlines():
            line = raw.strip()
            if not line:
                continue
            lowered = line.lower()
            for provider in self.PROVIDERS:
                if provider in lowered or (provider == "aws" and "s3" in lowered) or (provider == "gcp" and "google" in lowered):
                    provider_hint = provider
                    break
            if "[+]" not in line and "found" not in lowered and "open" not in lowered:
                continue
            resource = self._extract_resource(line)
            if not resource:
                continue
            provider = provider_hint if provider_hint in self.PROVIDERS else self._infer_provider(resource)
            findings[provider].append({"provider": provider, "resource": resource, "raw": line})
        return findings

    @staticmethod
    def _extract_resource(line: str) -> str:
        urls = re.findall(r"https?://[^\s]+", line)
        if urls:
            return urls[-1].rstrip(",")
        cleaned = re.sub(r"\x1b\[[0-9;]*m", "", line)
        tokens = [t.strip(" ,[]()") for t in cleaned.split() if t.strip(" ,[]()")]
        return tokens[-1] if tokens else ""

    @staticmethod
    def _infer_provider(resource: str) -> str:
        lowered = resource.lower()
        if "blob.core.windows.net" in lowered:
            return "azure"
        if "storage.googleapis.com" in lowered or "google" in lowered:
            return "gcp"
        return "aws"

    @staticmethod
    def _dedupe(findings: List[Dict]) -> List[Dict]:
        seen = set()
        deduped = []
        for finding in findings:
            key = (finding.get("provider"), finding.get("resource"))
            if key not in seen:
                seen.add(key)
                deduped.append(finding)
        return deduped
