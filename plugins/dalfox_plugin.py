import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence
from core.raw_artifacts import append_manifest, write_command, write_json, write_text


class DalfoxPlugin(BasePlugin):
    """Dalfox — Context-aware XSS scanner (Go binary)."""

    def name(self) -> str:
        return "Dalfox"

    def description(self) -> str:
        return "Dalfox — XSS scanner thông minh với context-aware injection, smart filtering."

    def check_installed(self) -> bool:
        if shutil.which("dalfox"):
            return True
        # Fallback: check Go default install path
        go_bin = os.path.expanduser("~/go/bin/dalfox")
        return os.path.isfile(go_bin) and os.access(go_bin, os.X_OK)

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, timeout_per_url: int = 120,
            max_urls: int = 30, proxy: str = "", waf_detected: bool = False,
            proxy_mode: str = "fuzz", deep_domxss: bool = False) -> list:
        """
        Quét XSS trên danh sách parameterized URLs.

        Args:
            urls: Danh sách URL có tham số (vd: http://target.com/search?q=test)
            out_dir: Thư mục output
            headers: Custom headers
            timeout_per_url: Timeout cho mỗi URL (giây) — chống treo
            max_urls: Giới hạn tối đa URL quét
            proxy: Proxy URL (vd: http://127.0.0.1:8080) — DEPRECATED, use proxy_mode
            waf_detected: Nếu True, kích hoạt chế độ WAF Evasion (auto-escalate to exploit proxy)
            proxy_mode: Proxy profile ('fuzz', 'recon', 'exploit')

        Returns:
            list: [{"url": "...", "param": "q", "type": "reflected", "payload": "...", "poc": "..."}, ...]
        """
        if not self.check_installed():
            logging.warning("[Dalfox] dalfox not installed. Skip.")
            return []

        os.makedirs(out_dir, exist_ok=True)
        findings = []

        #  Smart proxy routing — escalate to Tor only when WAF is detected
        from config import Config as _Cfg
        if waf_detected:
            effective_proxy = _Cfg.get_proxy_url("exploit")  # WAF → Tor stealth
            logging.info(f"[Dalfox] WAF detected → escalating to EXPLOIT proxy: {effective_proxy}")
        elif proxy:
            effective_proxy = proxy  # Legacy fallback
        else:
            effective_proxy = _Cfg.get_proxy_url(proxy_mode)  # Normal: use fuzz profile
            if effective_proxy:
                logging.info(f"[Dalfox] Using {proxy_mode.upper()} proxy: {effective_proxy}")

        for i, url in enumerate(urls[:max_urls]):
            url = url.strip()
            if not url or "?" not in url:
                continue  # Chỉ quét URL có tham số

            output_file = os.path.join(out_dir, f"dalfox_{i}.json")
            stdout_file = f"dalfox_{i}_stdout.txt"
            stderr_file = f"dalfox_{i}_stderr.txt"
            dalfox_bin = shutil.which("dalfox") or os.path.expanduser("~/go/bin/dalfox")
            cmd = [
                dalfox_bin, "url", url,
                "--silence",
                "--no-color",
                "--format", "json",
                "--output", output_file,
                "--timeout", str(timeout_per_url),
                # [V1.0-APEX] Tier 1 Anti-FP cho XSS
                "--ignore-return", "404,403,400,429,500", # Bỏ qua các trang lỗi hệ thống
                "--grep", "alert(1),confirm(1),prompt(1)", # Chỉ quan tâm nếu payload thực sự được thực thi/phản hồi
                "--only-discovery", # Bước 1: Chỉ tìm điểm phản hồi (reflection) trước khi exploit nặng
            ]
            
            if waf_detected:
                cmd.extend(["--waf-evasion", "--worker", "1", "--delay", "3000"]) # Aggressive evasion
                logging.info(f"[Dalfox] Ghost Mode active: Routing {url} via stealth proxy...")
            else:
                cmd.extend(["--worker", "5", "--delay", "100"]) # Normal mode
            if deep_domxss:
                cmd.append("--deep-domxss")

            if headers:
                # Safe header list + strip internal double quotes to prevent CLI flag parse errors
                SAFE_HEADERS = {"user-agent", "cookie", "authorization", "referer", "x-forwarded-for", "accept", "accept-language"}
                for k, v in headers.items():
                    if k.lower() in SAFE_HEADERS:
                        clean_v = str(v).replace('"', '')
                        cmd.extend(["-H", f"{k}: {clean_v}"])
            
            #  Apply effective proxy (smart-routed, not always Tor)
            if effective_proxy:
                cmd.extend(["--proxy", effective_proxy])

            write_command(out_dir, f"dalfox_{i}_command.txt", cmd)

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True, text=True,
                    timeout=timeout_per_url + 30  # Buffer thêm 30s cho overhead
                )
                write_text(out_dir, stdout_file, proc.stdout)
                write_text(out_dir, stderr_file, proc.stderr)

                # Parse Dalfox JSON output
                if os.path.exists(output_file):
                    try:
                        with open(output_file, 'r') as f:
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    entry = json.loads(line)
                                    finding = {
                                        "url": entry.get("url", url),
                                        "param": entry.get("param", ""),
                                        "type": entry.get("type", "reflected"),
                                        "payload": entry.get("payload", ""),
                                        "poc": entry.get("proof_of_concept", entry.get("poc", "")),
                                        "severity": entry.get("severity", "medium"),
                                        "confidence": entry.get("confidence", "MEDIUM"),
                                        "evidence": entry.get("evidence", entry.get("proof_of_concept", entry.get("poc", ""))),
                                    }
                                    findings.append(attach_evidence(
                                        finding,
                                        make_evidence(
                                            method="GET",
                                            url=finding["url"],
                                            param=finding["param"],
                                            payload=finding["payload"],
                                            validation=(
                                                f"Dalfox reported {finding['type']} XSS signal for parameter "
                                                f"{finding['param'] or '<unknown>'}."
                                            ),
                                            raw_artifact=output_file,
                                            confidence=str(finding.get("confidence", "medium")).lower(),
                                        ),
                                    ))
                                except json.JSONDecodeError:
                                    continue
                    except Exception as e:
                        logging.debug(f"[Dalfox] Parse error: {e}")

            except subprocess.TimeoutExpired:
                logging.warning(f"[Dalfox] Timeout ({timeout_per_url}s) cho {url}. Skip.")
            except Exception as e:
                logging.warning(f"[Dalfox] Error for {url}: {e}")

        logging.info(f"[Dalfox] Phát hiện {len(findings)} XSS vulnerabilities.")
        write_json(out_dir, "dalfox_parsed_findings.json", findings)
        append_manifest(
            out_dir,
            "dalfox",
            ["dalfox_parsed_findings.json"] + [
                name for name in os.listdir(out_dir)
                if name.startswith("dalfox_") and name.endswith((".txt", ".json"))
            ],
            note=f"targets={min(len(urls), max_urls)} findings={len(findings)}",
        )
        return findings
