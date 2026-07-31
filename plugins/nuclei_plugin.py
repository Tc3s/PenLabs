import os
import sys
import json
import logging
import subprocess
import shutil
from typing import Optional, List
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence
from config import Config
from core.raw_artifacts import append_manifest, write_command, write_json


class NucleiPlugin(BasePlugin):
    """Nuclei vulnerability scanner wrapper — chuẩn mực Bug Bounty 2026."""

    def name(self) -> str:
        return "Nuclei"

    def description(self) -> str:
        return "ProjectDiscovery Nuclei — Template-based vulnerability scanner (Web, Network, Cloud, CVE)."

    def check_installed(self) -> bool:
        return shutil.which("nuclei") is not None

    @staticmethod
    def _iter_cli_headers(headers: Optional[dict]):
        """Yield only concrete header values suitable for CLI -H flags."""
        for k, v in (headers or {}).items():
            if v is None:
                continue
            value = str(v).strip()
            if not value or value.lower() == "none":
                continue
            yield str(k), value

    @classmethod
    def _merged_cli_headers(cls, *header_sets: Optional[dict]):
        merged = {}
        original_keys = {}
        for headers in header_sets:
            for k, v in cls._iter_cli_headers(headers):
                norm = k.lower()
                if norm not in original_keys:
                    original_keys[norm] = k
                merged[norm] = v
        for norm, value in merged.items():
            yield original_keys[norm], value

    def run(self, target: str, out_dir: str = "/tmp", tags: Optional[List[str]] = None,
            templates: Optional[List[str]] = None, severity: Optional[List[str]] = None,
            rate_limit: Optional[int] = None, concurrency: Optional[int] = None,
            extra_flags: Optional[List[str]] = None,
            headers: Optional[dict] = None,
            proxy_file: Optional[str] = None,
            debug: bool = False,
            proxy_mode: str = "recon") -> list:
        """
        Chạy Nuclei và trả về list of findings (JSON parsed).

        Args:
            target: URL hoặc IP mục tiêu
            tags: List tag filter (vd: ['cve', 'sqli', 'xss', 'tomcat'])
            templates: List đường dẫn template cụ thể
            severity: List mức độ (vd: ['critical', 'high', 'medium'])
            rate_limit: Giới hạn requests/giây (mặc định từ Config)
            concurrency: Số template chạy song song (mặc định từ Config)
            extra_flags: Các flag bổ sung
            debug: In ra command đầy đủ và stdout/stderr
        Returns:
            List[dict] — mỗi dict chứa thông tin finding
        """
        if not self.check_installed():
            logging.error("Nuclei is not installed. Run setup.sh first.")
            return []

        os.makedirs(out_dir, exist_ok=True)
        #  Unique output file — tránh collision khi scan nhiều target
        import hashlib
        target_hash = hashlib.md5(target.encode()).hexdigest()[:8]
        jsonl_file = os.path.join(out_dir, f"nuclei_{target_hash}.jsonl")

        #  Dùng Config thay vì hardcode
        _rate_limit = rate_limit if rate_limit is not None else Config.NUCLEI_RATE_LIMIT
        _concurrency = concurrency if concurrency is not None else Config.NUCLEI_CONCURRENCY
        _timeout = Config.NUCLEI_TIMEOUT

        cmd = [
            "nuclei",
            "-target", target,
            "-jsonl",
            "-output", jsonl_file,
            "-rate-limit", str(_rate_limit),
            "-concurrency", str(_concurrency),
            "-silent",
        ]

        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
            
        # Throttling and Mimicry
        if proxy_mode in ["stealth", "exploit"]:
            _rate_limit = min(_rate_limit, 45) # Keep rate limit low
            cmd = [c if c != "-rate-limit" else c for c in cmd] # It's easier to just replace the whole command list's rate limit
            # Update the rate limit in cmd list
            try:
                rl_index = cmd.index("-rate-limit")
                cmd[rl_index + 1] = str(_rate_limit)
            except ValueError:
                pass

        # Inject browser native headers
        from utils.ua_rotator import get_random_headers
        random_headers = get_random_headers()
        
        # [V1.0-APEX] OPSEC: PD tools often have default UA. Force override.
        for k, v in self._merged_cli_headers(random_headers, headers):
            cmd.extend(["-H", f"{k}: {v}"])

        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: UNIFIED PROXY LOGIC (TASK 1)
        # Priority: Config.get_proxy_url(proxy_mode) > proxy_file > direct
        # ═══════════════════════════════════════════════════════════════
        config_proxy = Config.get_proxy_url(proxy_mode)
        if config_proxy:
            cmd.extend(["-proxy", config_proxy])
            logging.info(f"[Nuclei][PROXY] Using {proxy_mode.upper()} proxy: {config_proxy}")
        elif proxy_file:
            if proxy_file.startswith(("http://", "https://", "socks")):
                cmd.extend(["-proxy", proxy_file])
            else:
                cmd.extend(["-proxy-file", proxy_file])
            logging.info(f"[Nuclei][PROXY] Using legacy proxy: {proxy_file}")

        if extra_flags:
            cmd.extend(extra_flags)

        write_command(out_dir, f"nuclei_{target_hash}_command.txt", cmd)

        #  Dùng tham số debug thay vì đọc sys.argv
        # [V1.0-SYNC] Capture output to diagnose silent failures
        try:
            if debug:
                logging.info(f"[Nuclei] CMD: {' '.join(cmd)}")
                subprocess.run(cmd, timeout=_timeout)
            else:
                res = subprocess.run(cmd, capture_output=True, timeout=_timeout)
                if res.returncode != 0 and res.stderr:
                    logging.warning(f"[Nuclei] Process returned {res.returncode}. Stderr: {res.stderr.decode()[:200]}...")
        except subprocess.TimeoutExpired:
            logging.warning(f"[Nuclei] Timed out after {_timeout} seconds.")

        parsed = self._parse_jsonl(jsonl_file)
        write_json(out_dir, f"nuclei_{target_hash}_parsed.json", parsed)
        append_manifest(
            out_dir,
            "nuclei",
            [f"nuclei_{target_hash}_command.txt", os.path.basename(jsonl_file), f"nuclei_{target_hash}_parsed.json"],
            note=f"target={target}",
        )
        return parsed

    def run_batch(self, targets: list, out_dir: str = "/tmp", tags: list = None,
                  templates: list = None, severity: list = None,
                  rate_limit: int = None, concurrency: int = None,
                  extra_flags: list = None, headers: dict = None, 
                  proxy_file: str = None,
                  debug: bool = False,
                  proxy_mode: str = "recon") -> list:
        """
         Batch scan nhiều URL cùng lúc bằng `-l targets.txt`.
        Nhanh hơn 5-10x so với gọi run() sequential cho từng URL.
        """
        if not self.check_installed() or not targets:
            return []

        os.makedirs(out_dir, exist_ok=True)
        import hashlib
        batch_hash = hashlib.md5("|".join(targets).encode()).hexdigest()[:8]
        input_file = os.path.join(out_dir, f"nuclei_targets_{batch_hash}.txt")
        jsonl_file = os.path.join(out_dir, f"nuclei_batch_{batch_hash}.jsonl")

        with open(input_file, 'w') as f:
            f.write("\n".join(targets))

        _rate_limit = rate_limit if rate_limit is not None else Config.NUCLEI_RATE_LIMIT
        _concurrency = concurrency if concurrency is not None else Config.NUCLEI_CONCURRENCY
        _timeout = Config.NUCLEI_TIMEOUT

        cmd = [
            "nuclei",
            "-l", input_file,
            "-jsonl",
            "-output", jsonl_file,
            "-rate-limit", str(_rate_limit),
            "-concurrency", str(_concurrency),
            "-silent",
        ]

        if tags:
            cmd.extend(["-tags", ",".join(tags)])
        if templates:
            for t in templates:
                cmd.extend(["-t", t])
        if severity:
            cmd.extend(["-severity", ",".join(severity)])
            
        # Throttling and Mimicry
        if proxy_mode in ["stealth", "exploit"]:
            _rate_limit = min(_rate_limit, 45) # Keep rate limit low
            cmd = [c if c != "-rate-limit" else c for c in cmd] # Clean up
            try:
                rl_index = cmd.index("-rate-limit")
                cmd[rl_index + 1] = str(_rate_limit)
            except ValueError:
                pass

        # Inject browser native headers
        from utils.ua_rotator import get_random_headers
        random_headers = get_random_headers()
        
        # [V1.0-APEX] OPSEC: PD tools often have default UA. Force override.
        for k, v in self._merged_cli_headers(random_headers, headers):
            cmd.extend(["-H", f"{k}: {v}"])

        # V1.0-FIX: UNIFIED PROXY LOGIC
        config_proxy = Config.get_proxy_url(proxy_mode)
        if config_proxy:
            cmd.extend(["-proxy", config_proxy])
            logging.info(f"[Nuclei-Batch][PROXY] Using {proxy_mode.upper()} proxy: {config_proxy}")
        elif proxy_file:
            if proxy_file.startswith(("http://", "https://", "socks")):
                cmd.extend(["-proxy", proxy_file])
            elif os.path.exists(proxy_file):
                cmd.extend(["-proxy-file", proxy_file])
            logging.info(f"[Nuclei-Batch][PROXY] Using legacy proxy: {proxy_file}")

        if extra_flags:
            cmd.extend(extra_flags)

        write_command(out_dir, f"nuclei_batch_{batch_hash}_command.txt", cmd)

        try:
            if debug:
                logging.info(f"[Nuclei-Batch] CMD: {' '.join(cmd)}")
                subprocess.run(cmd, timeout=_timeout)
            else:
                # [V1.0-FIX] Capture stderr to log file for diagnosis
                res = subprocess.run(cmd, capture_output=True, timeout=_timeout)
                if res.returncode != 0 and res.stderr:
                    logging.warning(f"[Nuclei-Batch] Process returned {res.returncode}. Stderr: {res.stderr.decode()[:200]}...")
        except subprocess.TimeoutExpired:
            logging.warning(f"[Nuclei-Batch] Timed out after {_timeout} seconds.")

        parsed = self._parse_jsonl(jsonl_file)
        write_json(out_dir, f"nuclei_batch_{batch_hash}_parsed.json", parsed)
        append_manifest(
            out_dir,
            "nuclei_batch",
            [
                f"nuclei_batch_{batch_hash}_command.txt",
                os.path.basename(input_file),
                os.path.basename(jsonl_file),
                f"nuclei_batch_{batch_hash}_parsed.json",
            ],
            note=f"targets={len(targets)}",
        )
        return parsed

    def _parse_jsonl(self, jsonl_file: str) -> list:
        """Parse Nuclei JSONL output thành structured findings."""
        findings = []
        if not os.path.exists(jsonl_file):
            return findings

        try:
            with open(jsonl_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        finding = {
                            "template_id": data.get("template-id", ""),
                            "template_name": data.get("info", {}).get("name", ""),
                            "severity": data.get("info", {}).get("severity", "unknown"),
                            "matched_at": data.get("matched-at", ""),
                            "matcher_name": data.get("matcher-name", ""),
                            "type": data.get("type", ""),
                            "host": data.get("host", ""),
                            "port": self._extract_port(data),
                            "cve_id": self._extract_cve(data),
                            "description": data.get("info", {}).get("description", ""),
                            "reference": data.get("info", {}).get("reference", []),
                            "curl_command": data.get("curl-command", ""),
                            "interaction": data.get("interaction", False),
                            "source": "Nuclei",
                        }
                        request_meta = data.get("request", {})
                        request_method = request_meta.get("method", "") if isinstance(request_meta, dict) else ""
                        findings.append(attach_evidence(
                            finding,
                            make_evidence(
                                method=request_method,
                                url=finding.get("matched_at") or finding.get("host"),
                                payload={"template_id": finding.get("template_id"), "matcher": finding.get("matcher_name")},
                                status_code=data.get("response", {}).get("status_code"),
                                validation=(
                                    f"Nuclei template {finding.get('template_id') or '<unknown>'} "
                                    f"matched {finding.get('matched_at') or finding.get('host')}."
                                ),
                                raw_artifact=jsonl_file,
                                confidence="high" if finding.get("severity") in ("critical", "high") else "medium",
                            ),
                        ))
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logging.warning(f"[Nuclei] Failed to parse {jsonl_file}: {e}")

        return findings

    @staticmethod
    def _extract_cve(data: dict) -> str:
        """Trích xuất CVE ID từ Nuclei output."""
        # Check classification first
        classification = data.get("info", {}).get("classification", {})
        cve_id = classification.get("cve-id")
        if cve_id:
            if isinstance(cve_id, list):
                return cve_id[0] if cve_id else ""
            return str(cve_id)

        # Fallback: check template-id
        tid = data.get("template-id", "")
        if tid.upper().startswith("CVE-"):
            return tid.upper()

        return ""

    @staticmethod
    def _extract_port(data: dict) -> int:
        """Trích xuất port từ matched-at URL."""
        matched = data.get("matched-at", "")
        try:
            if ":" in matched:
                # Parse port from URL like http://ip:8080/path
                from urllib.parse import urlparse
                parsed = urlparse(matched)
                if parsed.port:
                    return parsed.port
                if parsed.scheme == "https":
                    return 443
                return 80
        except Exception:
            pass
        return 80
