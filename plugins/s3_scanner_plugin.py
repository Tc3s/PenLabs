"""S3 bucket scanner plugin — candidate generation + anonymous permission audit."""

from __future__ import annotations

import html
import logging
import os
import re
import shutil
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

import requests

from core.base_plugin import BasePlugin


class S3ScannerPlugin(BasePlugin):
    """Enumerate likely S3 buckets and classify anonymous access safely.

    This wrapper does not write test objects. It only performs anonymous HEAD/GET
    requests against bucket endpoints to avoid target state changes.
    """

    DEFAULT_PATTERNS = (
        "backup", "data", "assets", "media", "files", "static", "uploads",
        "downloads", "images", "docs", "logs", "archive", "tmp", "test",
        "dev", "prod", "staging", "admin", "internal", "private", "public",
        "www", "web", "app", "api", "cdn",
    )

    def name(self) -> str:
        return "S3Scanner"

    def description(self) -> str:
        return "AWS S3 bucket enumeration and anonymous permissions audit."

    def check_installed(self) -> bool:
        # External s3scanner is optional; built-in anonymous HTTP checks still work.
        return True

    def run(
        self,
        target: str,
        wordlist: Optional[str] = None,
        timeout: int = 10,
        max_buckets: int = 200,
    ):
        if not wordlist:
            try:
                from core.wordlist_registry import resolve_wordlist
                wordlist = resolve_wordlist("s3_buckets").get("path", "")
            except Exception:
                wordlist = os.path.abspath(
                    os.path.join(os.path.dirname(__file__), "..", "wordlists", "s3_buckets.txt")
                )
        findings: List[Dict] = []
        for bucket in self._generate_bucket_names(target, wordlist)[:max_buckets]:
            result = self._check_bucket(bucket, timeout=timeout)
            if result.get("exists"):
                findings.append(result)
        return findings

    def _generate_bucket_names(self, target: str, wordlist: Optional[str] = None) -> List[str]:
        """Generate normalized bucket candidates from a domain/org target."""
        normalized = self._normalize_label(target)
        parts = [p for p in normalized.split("-") if p]
        company = parts[-2] if len(parts) >= 2 and parts[-1] in {"com", "net", "org", "io", "co"} else parts[0] if parts else normalized
        roots = {normalized, company, normalized.replace("www-", "")}

        patterns: List[str] = list(self.DEFAULT_PATTERNS)
        if wordlist and os.path.exists(wordlist):
            with open(wordlist, encoding="utf-8", errors="ignore") as handle:
                patterns.extend(line.strip() for line in handle if line.strip() and not line.startswith("#"))

        candidates = set()
        for root in roots:
            if root:
                candidates.add(root)
                for pat in patterns:
                    clean_pat = self._normalize_label(pat)
                    if clean_pat:
                        candidates.add(f"{root}-{clean_pat}")
                        candidates.add(f"{clean_pat}-{root}")
        return sorted(candidates)

    @staticmethod
    def _normalize_label(value: str) -> str:
        value = re.sub(r"^https?://", "", value.strip().lower())
        value = value.split("/", 1)[0].split(":", 1)[0]
        value = value.replace(".", "-")
        value = re.sub(r"[^a-z0-9.-]", "-", value)
        value = re.sub(r"-+", "-", value).strip("-.")
        return value[:63]

    def _check_bucket(self, bucket: str, timeout: int = 10) -> Dict:
        """Check bucket existence and anonymous read/list access."""
        url = f"https://{bucket}.s3.amazonaws.com/"
        result: Dict = {
            "provider": "AWS_S3",
            "bucket": bucket,
            "url": url,
            "exists": False,
            "public": False,
            "region": "unknown",
            "permissions": {},
            "severity": "info",
        }
        try:
            response = requests.get(url, timeout=timeout, allow_redirects=False)
        except requests.RequestException as exc:
            logging.debug("[S3Scanner] %s request failed: %s", bucket, exc)
            return result

        region = response.headers.get("x-amz-bucket-region")
        if region:
            result["region"] = region

        body = response.content or b""
        text = response.text or ""
        if response.status_code == 200:
            result.update({
                "exists": True,
                "public": True,
                "status": "PUBLIC_LIST",
                "severity": "critical",
                "size": len(body),
                "sample_objects": self._extract_object_keys(body)[:5],
                "permissions": {"ListBucket": "public", "GetObject": "unknown", "PutObject": "not_tested"},
            })
        elif response.status_code == 403:
            result.update({
                "exists": True,
                "public": False,
                "status": "EXISTS_NO_LIST",
                "permissions": {"ListBucket": "denied", "GetObject": "unknown", "PutObject": "not_tested"},
            })
        elif response.status_code in {301, 307, 308} and (region or "PermanentRedirect" in text):
            result.update({"exists": True, "public": False, "status": "EXISTS_REDIRECT"})
        elif response.status_code == 404 or "NoSuchBucket" in text:
            result["status"] = "NOT_FOUND"
        else:
            result["status"] = f"HTTP_{response.status_code}"
        return result

    def _extract_object_keys(self, xml_content: bytes) -> List[str]:
        if not xml_content:
            return []
        try:
            import defusedxml.ElementTree as DET
            root = DET.fromstring(xml_content)
            keys = []
            for elem in root.iter():
                if elem.tag.endswith("Key") and elem.text:
                    keys.append(html.unescape(elem.text))
            return keys
        except Exception:
            keys = re.findall(rb"<Key>([^<]+)</Key>", xml_content)
            return [html.unescape(k.decode("utf-8", errors="ignore")) for k in keys]
