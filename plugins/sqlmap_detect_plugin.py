import os
import json
import logging
import subprocess
import shutil
import asyncio
import threading
import time
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence
from core.raw_artifacts import append_manifest, write_command, write_json, write_text
from core.proxy_relay import ProxyRelay


class SQLMapDetectPlugin(BasePlugin):
    """SQLMap Detect-Only — Phát hiện SQL Injection qua StealthNet Proxy Relay."""

    def name(self) -> str:
        return "SQLMapDetect"

    def description(self) -> str:
        return "SQLMap Detect-Only qua StealthNet Relay — Bypass WAF và xoay IP tự động."

    def check_installed(self) -> bool:
        return shutil.which("sqlmap") is not None

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, timeout_per_url: int = 120,
            max_urls: int = 15, proxy: str = "",
            cookies: str = "", waf_detected: bool = False, use_relay: bool = False,
            risk: int = 1, level: int = 1, tamper: list | str | None = None) -> list:
        
        if not self.check_installed():
            logging.warning("[SQLMap] sqlmap not installed. Skip.")
            return []

        os.makedirs(out_dir, exist_ok=True)
        findings = []

        #  Khởi tạo Proxy Relay để bọc SQLMap qua StealthNet (nếu use_relay = True)
        effective_proxy = proxy
        relay = None
        relay_loop = None
        relay_thread = None
        if use_relay:
            relay_port = 0
            relay = ProxyRelay(port=0, scan_mode="web-vuln")
            
            def start_relay():
                nonlocal relay_loop
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                relay_loop = loop
                nonlocal relay_port
                relay_port = loop.run_until_complete(relay.start())
                loop.run_forever()

            relay_thread = threading.Thread(target=start_relay, daemon=True)
            relay_thread.start()
            
            # Đợi relay khởi động (max 5s)
            start_time = time.time()
            while relay_port == 0 and time.time() - start_time < 5:
                time.sleep(0.1)
                
            if relay_port == 0:
                logging.error("[SQLMap] Failed to start Proxy Relay. Falling back to direct scan.")
            else:
                effective_proxy = f"http://127.0.0.1:{relay_port}"
            logging.info(f"[SQLMap] Proxy Relay active on {effective_proxy}. Routing traffic through StealthNet.")

        try:
            for i, url in enumerate(urls[:max_urls]):
                url = url.strip()
                if not url or "?" not in url:
                    continue

                output_dir = os.path.join(out_dir, f"sqlmap_scan_{i}")
                os.makedirs(output_dir, exist_ok=True)

                cmd = [
                    "sqlmap",
                    "-u", url,
                    "--batch",
                    "--random-agent",
                ]
                
                #  Luôn dùng relay proxy để có JA3/JA4 spoofing
                if effective_proxy:
                    cmd.extend(["--proxy", effective_proxy])
                
                cmd.extend([
                    "--level", str(level or 1),
                    "--risk", str(risk or 1),
                    "--technique", "BEU",
                    "--threads", "3",
                    "--timeout", "15",
                    "--retries", "1",
                    "--output-dir", output_dir,
                    "--flush-session",
                    "--smart",
                    "--answers=crack=N,dict=N,follow=N,keep=N,quit=N",
                ])

                tamper_chain = tamper
                if not tamper_chain:
                    tamper_chain = ["between", "randomcase", "space2comment", "charencode", "equaltolike"] if waf_detected else ["space2comment"]
                if isinstance(tamper_chain, list):
                    tamper_chain = ",".join(str(item) for item in tamper_chain if item)
                if tamper_chain:
                    cmd.extend([f"--tamper={tamper_chain}"])

                if headers:
                    header_str = "\\n".join([f"{k}: {v}" for k, v in headers.items() if k.lower() not in ["user-agent", "host"]])
                    if header_str:
                        cmd.extend(["--headers", header_str])
                if cookies:
                    cmd.extend(["--cookie", cookies])

                write_command(output_dir, "sqlmap_command.txt", cmd)
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True, text=True,
                        timeout=timeout_per_url
                    )
                    write_text(output_dir, "sqlmap_stdout.txt", proc.stdout)
                    write_text(output_dir, "sqlmap_stderr.txt", proc.stderr)
                    
                    log_findings = self._parse_sqlmap_session_log(output_dir, url)
                    findings.extend(log_findings)
                    write_json(output_dir, "sqlmap_parsed_findings.json", log_findings)
                    append_manifest(
                        output_dir,
                        "sqlmap",
                        ["sqlmap_command.txt", "sqlmap_stdout.txt", "sqlmap_stderr.txt", "sqlmap_parsed_findings.json"],
                        note=f"url={url} findings={len(log_findings)}",
                    )

                except subprocess.TimeoutExpired:
                    logging.warning(f"[SQLMap] Timeout ({timeout_per_url}s) cho {url}.")
                except Exception as e:
                    logging.warning(f"[SQLMap] Error for {url}: {e}")
        finally:
            if relay and relay_loop:
                try:
                    relay_loop.call_soon_threadsafe(relay_loop.stop)
                except Exception:
                    pass
            if relay_thread:
                relay_thread.join(timeout=2)

        # Stop relay
        # (Vì dùng daemon thread và run_forever, chúng ta có thể dừng loop hoặc để nó tự chết khi main thread thoát)
        # Nhưng tốt nhất là stop sạch sẽ.
        
        # Deduplicate and return
        seen = set()
        unique_findings = []
        for f in findings:
            key = f"{f['url']}:{f['param']}:{f['type']}"
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    @staticmethod
    def _parse_sqlmap_session_log(output_dir: str, url: str) -> list:
        # Giữ nguyên logic parse cũ vì nó đã rất tốt
        findings = []
        log_file = None
        for root, dirs, files in os.walk(output_dir):
            if "log" in files:
                log_file = os.path.join(root, "log")
                break
        if not log_file or not os.path.exists(log_file):
            return []
        try:
            with open(log_file, 'r', errors='ignore') as f:
                content = f.read()
            if not content.strip(): return []
            current_param = ""; current_type = ""; current_title = ""; current_payload = ""
            for line in content.splitlines():
                line_stripped = line.strip()
                if line_stripped.startswith("Parameter:"):
                    current_param = line_stripped.split("Parameter:")[-1].strip().split("(")[0].strip()
                    continue
                if line_stripped.startswith("Type:"):
                    if current_type and current_param:
                        findings.append(SQLMapDetectPlugin._finding_from_log(
                            url, current_param, current_type, current_title, current_payload, "", log_file
                        ))
                    current_type = line_stripped.split("Type:")[-1].strip().lower()
                    current_title = ""; current_payload = ""
                    continue
                if line_stripped.startswith("Title:"):
                    current_title = line_stripped.split("Title:")[-1].strip()
                    continue
                if line_stripped.startswith("Payload:"):
                    current_payload = line_stripped.split("Payload:")[-1].strip()
                    continue
                if "back-end DBMS" in line_stripped and findings:
                    dbms = line_stripped.split(":")[-1].strip() if ":" in line_stripped else ""
                    for f in findings:
                        if f["param"] == current_param and not f["dbms"]: f["dbms"] = dbms
            if current_type and current_param:
                findings.append(SQLMapDetectPlugin._finding_from_log(
                    url, current_param, current_type, current_title, current_payload, "", log_file
                ))
        except Exception: pass
        return findings

    @staticmethod
    def _finding_from_log(url: str, param: str, sql_type: str, title: str, payload: str, dbms: str, log_file: str) -> dict:
        finding = {
            "url": url,
            "param": param,
            "type": sql_type,
            "title": title,
            "dbms": dbms,
            "payload": payload,
            "severity": "critical",
            "confidence": "HIGH",
            "parse_source": "session_log",
            "evidence": title or f"sqlmap detected {sql_type} SQL injection on parameter {param}",
        }
        return attach_evidence(
            finding,
            make_evidence(
                method="GET",
                url=url,
                param=param,
                payload=payload,
                validation=f"sqlmap session log reported {sql_type} injection for parameter {param}.",
                raw_artifact=log_file,
                confidence="high",
            ),
        )
