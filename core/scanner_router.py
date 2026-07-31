#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — Scanner Router (Extracted from Module1_Recon.py)
================================================================
Điều phối pipeline quét theo mode, gọi đúng plugin cho đúng tầng.
Each mode has a dedicated _route_* method with a specific tool pipeline.

Extracted to reduce Module1_Recon.py from ~4000 lines to ~1500 lines
and enable independent testing of scan routing logic.
"""

import os
import re
import sys
import json
import logging
import asyncio
import socket
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Ensure PenLabs root is in sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.registry import PluginRegistry
from core.evidence import attach_evidence, make_evidence
from core.auth_context import AuthContext
from core.performance import performance_budget, unique_http_urls_by_host


import random
from plugins.stealth_net_plugin import StealthNetPlugin
from utils.url_dedup import URLDeduplicator

import aiohttp
from utils.passive_data_miner import PassiveDataMiner

class ScannerRouter:
    """
    Scanner Router — 2026 Red Team Doctrine.
    Điều phối pipeline quét theo mode, gọi đúng plugin cho đúng tầng.
    """

    # ═══════════════════════════════════════════════════════════════════
    # V1.0-FIX: ENTERPRISE CONCURRENCY CONTROL (TASK 6)
    # MAX_CONCURRENT_TASKS: Giới hạn số lượng Target quét song song.
    # HEAVY_TASK_SEMAPHORE: Giới hạn số lượng tiến trình ngốn RAM (Headless/Full Audit).
    # ═══════════════════════════════════════════════════════════════════
    MAX_CONCURRENT_TASKS = int(os.getenv("PENLABS_MAX_CONCURRENT", "5"))
    _heavy_task_semaphore = asyncio.Semaphore(int(os.getenv("PENLABS_MAX_HEAVY_TASKS", "2")))

    @classmethod
    def get_concurrency_for_mode(cls, mode: str) -> tuple:
        """Return (max_concurrent, max_heavy) based on mode."""
        config = {
            "stealth":      (2, 1),
            "sniper":       (5, 2),
            "fast":         (5, 2),
            "web-vuln":     (8, 3),
            "cloud-devops": (5, 2),
            "full-audit":   (15, 5),  # Tăng mạnh
            "api-bounty":   (10, 4),
            "api-breach":   (10, 4),
            "cloud-native": (5, 2),
            "infra-smash":  (5, 2),
            "asset-discovery": (10, 4),
        }
        return config.get(mode, (5, 2))

    async def _send_behavioral_noise(self, stop_event: asyncio.Event, target_url: str):
        """
        [V1.0-STEALTH] Gửi các request an toàn xen kẽ để phá vỡ WAF behavioral signature.
        Sử dụng StealthNetPlugin để có cùng JA4 TLS Fingerprint.
        """
        stealth_net = StealthNetPlugin(scan_mode="fuzz")
        stealth_net.run()
        noise_endpoints = ["/", "/favicon.ico", "/robots.txt", "/sitemap.xml", "/about", "/contact"]
        
        while not stop_event.is_set():
            try:
                # Random delay 2-7s
                await asyncio.sleep(random.uniform(2, 7))
                if stop_event.is_set():
                    break
                    
                endpoint = random.choice(noise_endpoints)
                url = f"{target_url.rstrip('/')}{endpoint}"
                
                # Gửi request ẩn danh
                loop = asyncio.get_running_loop()
                await loop.run_in_executor(self._plugin_executor, stealth_net.get, url)
                self.log.debug(f"[NOISE] Sent behavioral noise to {url}")
            except Exception as e:
                self.log.debug(f"[NOISE] Failed to send noise: {e}")

    def __init__(self, out_dir, logger, cookies="", headers=None, proxy_file=None, stealth_recon=False, rate_limit=150, delay="",
                 auth_userA="", auth_userB="",
                 checkpoint: 'CheckpointManager' = None, **kwargs):
        self.out_dir = out_dir
        self.log = logger
        self.cookies = cookies
        self.headers = headers or {}
        self.auth_profile = kwargs.get("auth_profile", "")
        self.proxy_file = proxy_file
        self.stealth_recon = stealth_recon
        self.rate_limit = rate_limit
        self.delay = delay
        self.raw = os.path.join(out_dir, "raw")
        os.makedirs(self.raw, exist_ok=True)
        # V1.0: BOLA tokens
        self.auth_userA = auth_userA
        self.auth_userB = auth_userB
        self.auth_context = AuthContext.from_router(self)
        
        self.ckpt = checkpoint

        # [V1.0] Core New Flags
        self.use_playwright = kwargs.get("use_playwright", False)
        self.sqlmap_relay = kwargs.get("sqlmap_relay", False)
        self.bola_engine = kwargs.get("bola_engine", False)
        self.chunk_size = kwargs.get("chunk_size", 20)
        self.use_emailfinder = kwargs.get("use_emailfinder", False)
        self.use_metagoofil = kwargs.get("use_metagoofil", False)

        # ═══════════════════════════════════════════════════════════════════
        # V1.0-FIX: TARGET DEDUPLICATION (TASK 6)
        # Hash-based set of (domain+ip) — never scan the same asset twice.
        # ═══════════════════════════════════════════════════════════════════
        self._seen_targets: set = set()
        self.mode = kwargs.get("mode", "sniper")
        self.performance = performance_budget(self.mode)
        max_concurrent, max_heavy = self.get_concurrency_for_mode(self.mode)
        self.MAX_CONCURRENT_TASKS = max_concurrent
        self._scan_semaphore = asyncio.Semaphore(max_concurrent)
        self._heavy_task_semaphore = asyncio.Semaphore(max_heavy)
        self._plugin_executor = ThreadPoolExecutor(
            max_workers=min(16, (os.cpu_count() or 4) + 4),
            thread_name_prefix="penlabs-plugin"
        )

    def _raw_tool_dir(self, tool: str, mode: str = "", target: str = "") -> str:
        """
        Return a stable raw artifact directory for a tool/mode/target tuple.
        Keeps per-target crawler output from overwriting files like katana_output.jsonl.
        """
        import hashlib

        parts = [str(tool or "tool").strip().lower()]
        if mode:
            parts.append(str(mode).strip().lower().replace("-", "_"))
        base = "_".join(re.sub(r"[^a-z0-9_]+", "_", p).strip("_") for p in parts if p)
        if target:
            parsed = urlparse(str(target))
            host = parsed.netloc or parsed.path or str(target)
            host_slug = re.sub(r"[^a-zA-Z0-9_.-]+", "_", host).strip("_")[:48] or "target"
            digest = hashlib.md5(str(target).encode()).hexdigest()[:8]
            path = os.path.join(self.raw, base, f"{host_slug}_{digest}")
        else:
            path = os.path.join(self.raw, base)
        os.makedirs(path, exist_ok=True)
        return path

    def _run_katana(
        self,
        katana_plugin,
        url: str,
        out_dir: str,
        *,
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
        extra_flags: list | None = None,
        proxy_mode: str = "fuzz",
    ) -> dict:
        """
        Call Katana by named contract and tolerate older/fake plugin signatures.
        The real plugin uses target/proxy_file/rate_limit; older tests and local
        shims may still use url/proxy and omit newer args.
        """
        import inspect

        kwargs = {
            "target": url,
            "url": url,
            "out_dir": out_dir,
            "katana_dir": out_dir,
            "depth": depth,
            "js_crawl": js_crawl,
            "headless": headless,
            "scope_filter": "",
            "extra_flags": extra_flags,
            "cookies": None,
            "headers": self._get_auth_headers(),
            "proxy_file": self.proxy_file,
            "proxy": self.proxy_file,
            "rate_limit": self.rate_limit or 0,
            "proxy_mode": proxy_mode,
        }
        try:
            signature = inspect.signature(katana_plugin.run)
            accepted = {
                name: value
                for name, value in kwargs.items()
                if name in signature.parameters
            }
            return katana_plugin.run(**accepted)
        except (TypeError, ValueError):
            return katana_plugin.run(
                url, out_dir, depth, js_crawl, headless, "",
                None, self._get_auth_headers(), self.proxy_file,
                self.rate_limit or 0, proxy_mode,
            )

    @staticmethod
    def _append_crawl_output(
        crawl_data,
        raw_crawled: list,
        *,
        api_like_urls: list | None = None,
        js_files: list | None = None,
        js_secrets: list | None = None,
    ) -> None:
        """Merge crawler output consistently across route modes."""
        if not isinstance(crawl_data, dict):
            return
        urls = crawl_data.get("urls", []) if isinstance(crawl_data.get("urls", []), list) else []
        endpoints = crawl_data.get("endpoints", []) if isinstance(crawl_data.get("endpoints", []), list) else []
        raw_crawled.extend(urls)
        raw_crawled.extend(endpoints)
        if api_like_urls is not None:
            api_like_urls.extend(endpoints)
        if js_files is not None:
            values = crawl_data.get("js_files", [])
            if isinstance(values, list):
                js_files.extend(values)
        if js_secrets is not None:
            values = crawl_data.get("js_secrets", [])
            if isinstance(values, list):
                js_secrets.extend(values)

    async def _run_katana_many(
        self,
        katana_plugin,
        urls: list,
        mode_label: str,
        *,
        limit: int,
        depth: int = 3,
        js_crawl: bool = True,
        headless: bool = False,
        proxy_mode: str = "fuzz",
    ) -> list[dict]:
        """Run Katana across URLs with mode-aware bounded concurrency."""
        targets = []
        seen = set()
        for raw in urls or []:
            url = str(raw or "").strip()
            if not url.startswith(("http://", "https://")) or url in seen:
                continue
            seen.add(url)
            targets.append(url)
            if len(targets) >= limit:
                break

        if not targets:
            return []

        budget = getattr(self, "performance", performance_budget(self.mode))
        crawler_sem = asyncio.Semaphore(max(1, int(budget.crawler_concurrency)))
        loop = asyncio.get_running_loop()

        async def _one(target_url: str):
            katana_dir = self._raw_tool_dir("katana", mode_label, target_url)
            async with crawler_sem:
                async with self._heavy_task_semaphore:
                    return await loop.run_in_executor(
                        None,
                        partial(
                            self._run_katana,
                            katana_plugin,
                            target_url,
                            katana_dir,
                            depth=depth,
                            js_crawl=js_crawl,
                            headless=headless,
                            proxy_mode=proxy_mode,
                        ),
                    )

        results = await asyncio.gather(*[_one(target_url) for target_url in targets], return_exceptions=True)
        clean_results = []
        for item in results:
            if isinstance(item, Exception):
                self.log.warning(f"[Katana] Worker failed: {item}")
            elif isinstance(item, dict):
                clean_results.append(item)
        return clean_results

    async def run_in_chunks(self, step_name: str, targets: list, chunk_size: int, callback, *args, **kwargs):
        """
         Chạy một tác vụ theo từng chunk để hỗ trợ Resume hoàn hảo.
        Nếu hệ thống crash, lần sau chạy lại sẽ skip các chunk đã xong.
        """
        if not targets:
            return []
            
        all_results = []
        chunks = [targets[i:i + chunk_size] for i in range(0, len(targets), chunk_size)]
        
        self.log.info(f"[CHUNK] Step {step_name}: {len(targets)} targets chia làm {len(chunks)} chunks.")
        
        for idx, chunk in enumerate(chunks):
            chunk_id = f"chunk_{idx}"
            
            if self.ckpt and self.ckpt.is_chunk_completed(step_name, chunk_id):
                self.log.info(f"  [CHUNK] Skip {step_name} {chunk_id} (already done)")
                # Cố gắng khôi phục kết quả từ metadata nếu cần (tùy task)
                continue
                
            self.log.info(f"  [CHUNK] Đang xử lý {step_name} {chunk_id} ({len(chunk)} targets)...")
            
            # Thực thi callback (async)
            try:
                res = await callback(chunk, *args, **kwargs)
                if isinstance(res, list):
                    all_results.extend(res)
                elif res:
                    all_results.append(res)
                    
                if self.ckpt:
                    self.ckpt.mark_chunk_completed(step_name, chunk_id)
            except Exception as e:
                self.log.error(f"  [CHUNK] Lỗi xử lý {step_name} {chunk_id}: {e}")
                
        return all_results
        
    def _get_auth_headers(self) -> dict:
        """
        [V1.0-APEX] Unified Fingerprinting.
        Đồng bộ hóa Headers 100% cho cả Go tools và Python.
         Tích hợp AuthManager để lấy token mới nhất (auto-refresh).
        """
        from utils.ua_rotator import get_random_headers
        from utils.auth_manager import AuthManager
        
        h = get_random_headers()
        if getattr(self, "auth_context", None):
            h.update(self.auth_context.user_headers("A"))
        
        # Lấy headers từ AuthManager (token mới nhất)
        auth_headers = AuthManager.instance().get_headers()
        if auth_headers:
            h.update(auth_headers)
            self.log.debug(f"[Auth] Updated headers from AuthManager.")
        
        # Ghi đè bằng custom headers/cookies thủ công (nếu có)
        if self.headers:
            for k, v in self.headers.items():
                h[k] = v
        if self.cookies:
            h["Cookie"] = self.cookies
            
        return {k: v for k, v in h.items() if v is not None and str(v).strip() != ""}

    @staticmethod
    def _web_ports_from_services(ports: list) -> list[int]:
        """Select likely HTTP(S) ports after service fingerprinting."""
        web_ports = []
        web_services = {"http", "https", "ssl/http", "http-proxy", "http-alt"}
        web_port_numbers = {80, 443, 8000, 8008, 8080, 8081, 8180, 8443, 8888, 9000, 9090}
        for item in ports or []:
            try:
                port = int(item.get("port"))
            except Exception:
                continue
            service = str(item.get("service", "")).lower()
            version = str(item.get("version", "")).lower()
            if service in web_services or port in web_port_numbers or "http" in service or "tomcat" in version:
                web_ports.append(port)
        return sorted(set(web_ports))

    def _setup_ja3_env(self) -> dict:
        """
        P1-1: Environment variables for routing Go-based tools through the
        local JA3 SOCKS5 proxy. Backward-compatible: disabled by default.
        """
        from config import Config
        if not getattr(Config, "JA3_SPOOF_ENABLED", False):
            return {}
        if not self._ja3_proxy_available():
            return {}
        proxy_url = f"socks5h://{Config.JA3_PROXY_HOST}:{int(Config.JA3_PROXY_PORT)}"
        return {
            "ALL_PROXY": proxy_url,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "NMAP_PROXY_SOCKS5": "yes",
            "JA3_PROFILE": getattr(Config, "JA3_PROFILE", "chrome120"),
        }

    def _ja3_tool_args(self, tool: str) -> list:
        """Native proxy flags for Go tools that do not honor ALL_PROXY consistently."""
        from config import Config
        if not getattr(Config, "JA3_SPOOF_ENABLED", False):
            return []
        if not self._ja3_proxy_available():
            return []
        from proxy.ja3_proxy import build_go_tool_proxy_args
        return build_go_tool_proxy_args(tool, Config.JA3_PROXY_HOST, int(Config.JA3_PROXY_PORT))

    @staticmethod
    def _ja3_proxy_available() -> bool:
        from config import Config
        try:
            with socket.create_connection(
                (Config.JA3_PROXY_HOST, int(Config.JA3_PROXY_PORT)),
                timeout=0.25,
            ):
                return True
        except OSError:
            logging.debug(
                "[JA3] Local proxy %s:%s unavailable; running direct.",
                Config.JA3_PROXY_HOST,
                Config.JA3_PROXY_PORT,
            )
            return False

    def _subprocess_env(self) -> dict:
        env = os.environ.copy()
        env.update(self._setup_ja3_env())
        return env

    @staticmethod
    def _get_dast_findings(result: dict, category: str | None = None) -> list[dict]:
        findings = result.get("dast_findings", []) or []
        if category is None:
            return findings
        from core.dast_contract import dast_findings_by_category
        return dast_findings_by_category(findings, category)

    def _extend_dast_findings(self, result: dict, category: str, raw_output) -> None:
        from core.dast_contract import normalize_dast_findings
        from core.verification import annotate_verification
        result.setdefault("dast_findings", [])
        result["dast_findings"].extend(annotate_verification(normalize_dast_findings(category, raw_output)))

    def _strategy_profile(
        self,
        tool: str,
        mode: str | None = None,
        *,
        waf_detected: bool = False,
        tech_stack: list | None = None,
        parameterized_count: int = 0,
    ) -> dict:
        from core.plugin_strategy import build_strategy_profile
        return build_strategy_profile(
            mode=mode or self.mode,
            tool=tool,
            waf_detected=waf_detected,
            tech_stack=tech_stack or [],
            parameterized_count=parameterized_count,
        )

    def _finalize_scan_contracts(self, result: dict, target: str, mode: str, waf_detected: bool = False) -> dict:
        """Attach cross-plugin contracts consumed by report/DB/manual handoff."""
        from core.correlation import correlate_attack_paths
        from core.cloud_infra_depth import summarize_cloud_infra_depth
        from core.endpoint_store import EndpointStore
        from core.dry_run_snapshot import build_dry_run_snapshot
        from core.knowledge_base import build_knowledge_profile, enrich_dast_findings_with_knowledge
        from core.wordlist_registry import build_wordlist_profile
        from core.operational_contract import (
            normalize_asset_findings,
            normalize_cloud_findings,
            normalize_exposure_findings,
            normalize_infra_findings,
        )
        from core.plugin_strategy import build_strategy_matrix
        from core.verification import annotate_verification, bucket_findings, bucket_summary

        if not isinstance(result, dict):
            return result

        store = EndpointStore(target=target)
        store.add_many(result.get("web_urls", []), source="web")
        store.add_many(result.get("web_urls_with_params", []), source="crawler")
        store.add_many(result.get("api_endpoints", []), source="api")
        store.add_hidden_params(result.get("hidden_params", {}), source="arjun")

        endpoint_store = store.all()
        if endpoint_store:
            result["endpoint_store"] = endpoint_store
            api_like = [
                item for item in store.api_like()
                if self._endpoint_belongs_to_target_context(item.get("url", ""), target)
                if item.get("is_parameterized")
                or any(src not in {"web", "crawler", "unknown"} for src in item.get("sources", []))
            ]
            if api_like:
                result["api_endpoints"] = api_like
            if not result.get("web_urls_with_params"):
                result["web_urls_with_params"] = store.parameterized_urls()
            result.setdefault("endpoint_summary", store.summary())

        result["dast_findings"] = annotate_verification(result.get("dast_findings", []))
        try:
            from config import Config as _CfgVerify
            if getattr(_CfgVerify, "VERIFICATION_PASS2_ENABLED", False):
                from core.verification_replay import replay_verify_findings
                result["dast_findings"] = replay_verify_findings(
                    result["dast_findings"],
                    headers=self._get_auth_headers(),
                    timeout=getattr(_CfgVerify, "VERIFICATION_PASS2_TIMEOUT", 8),
                    max_findings=getattr(_CfgVerify, "VERIFICATION_PASS2_MAX_FINDINGS", 20),
                )
        except Exception as _verify_err:
            result["verification_pass2_error"] = str(_verify_err)
        result["dast_findings"] = enrich_dast_findings_with_knowledge(result.get("dast_findings", []))
        buckets = bucket_findings(result.get("dast_findings", []))
        result["verification_buckets"] = buckets
        result["verification_summary"] = bucket_summary(buckets)
        result["knowledge_profile"] = build_knowledge_profile(result, mode, target)
        result["wstg_coverage"] = result["knowledge_profile"].get("wstg_coverage", {})
        result["manual_handoff"] = result["knowledge_profile"].get("manual_handoff", [])
        result["wordlist_profile"] = build_wordlist_profile(mode)
        result["attack_chains"] = correlate_attack_paths(result)

        context = {
            "waf_detected": waf_detected,
            "tech_stack": result.get("tech_stack", []),
            "parameterized_count": len(result.get("web_urls_with_params", []) or []),
            "knowledge_profile": result.get("knowledge_profile", {}),
        }
        result["strategy_profiles"] = build_strategy_matrix(mode, context)

        asset_view = dict(result)
        asset_view.setdefault("target", target)
        result["asset_findings"] = normalize_asset_findings(asset_view)
        result["exposure_findings"] = normalize_exposure_findings(asset_view)
        result["infra_findings"] = normalize_infra_findings(asset_view)
        result["cloud_inventory_findings"] = normalize_cloud_findings(asset_view)
        result["cloud_infra_depth"] = summarize_cloud_infra_depth(result)
        result["dry_run_snapshot"] = build_dry_run_snapshot(result, mode)
        return result

    @staticmethod
    def _normalize_api_endpoint(entry, source: str = "", default_method: str = "GET") -> dict | None:
        """Canonicalize mixed endpoint shapes into a dict."""
        if isinstance(entry, str):
            url = entry.strip()
            if not url:
                return None
            return {
                "url": url,
                "path": url,
                "method": default_method,
                "status": None,
                "status_code": None,
                "length": None,
                "content_length": None,
                "source": source or "unknown",
            }
        if isinstance(entry, dict):
            url = str(entry.get("url", entry.get("path", ""))).strip()
            if not url:
                return None
            status = entry.get("status_code", entry.get("status"))
            length = entry.get("content_length", entry.get("length"))
            return {
                "url": url,
                "path": entry.get("path", url),
                "method": str(entry.get("method", default_method)).upper(),
                "status": status,
                "status_code": status,
                "length": length,
                "content_length": length,
                "source": entry.get("source", source or "unknown"),
            }
        return None

    @staticmethod
    def _endpoint_belongs_to_target_context(url: str, target: str) -> bool:
        """Keep relative URLs and same-organization hosts; drop third-party library/documentation URLs."""
        parsed = urlparse(str(url or ""))
        if not parsed.scheme and not parsed.netloc:
            return True
        host = (parsed.netloc or "").split("@")[-1].split(":")[0].lower()
        target_host = urlparse(str(target)).netloc or str(target or "")
        target_host = target_host.split("@")[-1].split(":")[0].lower()
        if not host or not target_host:
            return False
        if host == target_host or host.endswith(f".{target_host}"):
            return True
        host_parts = host.split(".")
        target_parts = target_host.split(".")
        if len(host_parts) >= 2 and len(target_parts) >= 2:
            return ".".join(host_parts[-2:]) == ".".join(target_parts[-2:])
        return False

    @classmethod
    def _normalize_api_endpoints(cls, entries: list, source: str = "", default_method: str = "GET") -> list[dict]:
        normalized = []
        by_sig = {}
        for entry in entries or []:
            item = cls._normalize_api_endpoint(entry, source=source, default_method=default_method)
            if not item:
                continue
            sig = (item.get("method"), item.get("url"))
            existing = by_sig.get(sig)
            if existing:
                existing_score = sum(1 for key in ("status_code", "content_length", "source") if existing.get(key) not in (None, "", "unknown"))
                item_score = sum(1 for key in ("status_code", "content_length", "source") if item.get(key) not in (None, "", "unknown"))
                if item_score > existing_score:
                    idx = normalized.index(existing)
                    normalized[idx] = item
                    by_sig[sig] = item
                continue
            by_sig[sig] = item
            normalized.append(item)
        return normalized

    @staticmethod
    def _sanitize_ports(ports: list) -> list:
        """ Validate port list từ OSINT — chống injection qua dữ liệu bẩn."""
        clean = []
        for p in ports:
            try:
                port = int(p)
                if 1 <= port <= 65535:
                    clean.append(port)
            except (ValueError, TypeError):
                continue
        return clean

    async def _safe_nmap_verify(self, ip: str, ports: list, timeout: str = "1m", mode: str = "sniper") -> list:
        """
         Nmap port verify — Async non-blocking.
        Parse XML output thay vì pipe qua grep.
        [F-01/F-04 FIX] Uses per-mode nmap_timing from Config.RATE_LIMITS
        instead of hardcoded -T4.
        """
        import tempfile
        import xml.etree.ElementTree as ET
        verified = []
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        try:
            ports_str = ",".join(map(str, ports))
            # [F-01 FIX] Lookup nmap_timing from Config — defaults to T3 (moderate)
            from config import Config as _CfgNmap
            nmap_timing = _CfgNmap.RATE_LIMITS.get(mode, {}).get("nmap_timing", "T3")
            cmd = [
                "nmap", "-Pn", "-p", ports_str,
                f"-{nmap_timing}", "--open", "--max-retries", "1",
                "--host-timeout", timeout,
                "-oX", xml_path, ip
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=self._subprocess_env(),
            )
            await asyncio.wait_for(proc.wait(), timeout=150)
            if os.path.exists(xml_path):
                root = ET.parse(xml_path).getroot()
                for p in root.findall(".//port"):
                    state = p.find("state")
                    if state is not None and state.get("state") == "open":
                        verified.append(int(p.get("portid", "0")))
        except (asyncio.TimeoutError, FileNotFoundError) as e:
            # [AUDIT-FIX R-01] Specific exception types instead of broad catch-all
            logging.debug(f"[ScannerRouter] Nmap port verify failed ({type(e).__name__}): {e}")
        except Exception as e:
            logging.warning(f"[ScannerRouter] Unexpected error in port verification ({type(e).__name__}): {e}")
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
        return verified

    # ═══════════════════════════════════════════════════════════════════
    # V1.0-FIX: BATCH SCAN DISPATCH (TASK 6)
    # Process multiple targets with bounded concurrency.
    # ═══════════════════════════════════════════════════════════════════
    async def run_scan_batch(self, targets: list, mode: str) -> list:
        """
        Dispatch multiple targets with bounded concurrency (MAX_CONCURRENT_TASKS).

        Args:
            targets: List of dicts: [{"ip": ..., "target": ..., "index": ..., "osint_ports": [...]}]
            mode: Scan mode string

        Returns:
            list: Results from each run_scan() call
        """
        self.log.info(
            f"[BATCH] Dispatching {len(targets)} targets with max "
            f"{self.MAX_CONCURRENT_TASKS} concurrent tasks"
        )

        async def _limited_scan(t):
            async with self._scan_semaphore:
                return await self.run_scan(
                    ip=t["ip"],
                    target=t["target"],
                    index=t.get("index", 0),
                    mode=mode,
                    osint_ports=t.get("osint_ports", []),
                    osint_urls=t.get("osint_urls"),
                )

        tasks = [_limited_scan(t) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Filter out exceptions, log them
        clean_results = []
        for i, r in enumerate(results):
            if isinstance(r, Exception):
                self.log.error(f"[BATCH] Target {targets[i].get('target', '?')} failed: {r}")
                clean_results.append({"ports": [], "nse_cves": [], "nuclei_findings": [],
                                      "web_urls": [], "cloud_findings": {}, "os_detection": [],
                                      "_error": str(r)})
            else:
                clean_results.append(r)

        self.log.success(f"[BATCH] Completed {len(clean_results)}/{len(targets)} targets")
        return clean_results

    async def run_scan(self, ip: str, target: str, index: int, mode: str,
                       osint_ports: list, osint_urls: list = None) -> dict:
        """
        Scanner Router chính — dispatch scan pipeline dựa trên mode.

        Returns:
            dict: {
                "ports": [...],
                "nse_cves": [],
                "nuclei_findings": [],
                "web_urls": [],
                "cloud_findings": {},
                "os_detection": [],
            }
        """
        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: DEDUPLICATION GATE (TASK 6)
        # Never scan the same (domain + ip) pair twice in a session.
        # ═══════════════════════════════════════════════════════════════
        import hashlib
        dedup_key = hashlib.sha256(f"{target}|{ip}".lower().encode()).hexdigest()[:16]
        if dedup_key in self._seen_targets:
            self.log.info(f"[DEDUP] Skipping duplicate target: {target} ({ip}) — already scanned this session")
            return {
                "ports": [], "nse_cves": [], "nuclei_findings": [],
                "web_urls": [], "cloud_findings": {}, "os_detection": [],
                "_dedup_skipped": True,
            }
        self._seen_targets.add(dedup_key)

        # ═══════════════════════════════════════════════════════════════
        # V1.0-FIX: SCOPE ENFORCEMENT GATE (TASK 7)
        # Block out-of-scope targets before any scan work begins.
        # ═══════════════════════════════════════════════════════════════
        try:
            from utils.scope_engine import ScopeEngine
            scope = ScopeEngine.instance()
            if not scope.is_in_scope(target) and not scope.is_in_scope(ip):
                self.log.warning(f"[OUT OF SCOPE] Skipping {target} ({ip}) — not in authorized scope")
                return {
                    "ports": [], "nse_cves": [], "nuclei_findings": [],
                    "web_urls": [], "cloud_findings": {}, "os_detection": [],
                    "_out_of_scope": True,
                }
        except Exception as _scope_err:
            # If ScopeEngine fails to load (no scope.txt), continue in permissive mode
            logging.debug(f"[Scope] ScopeEngine check skipped: {_scope_err}")

        try:
            from core.preflight import PreflightChecker
            preflight = PreflightChecker(self.log)
            report = preflight.check(mode)
            if not report.is_executable:
                self.log.warning(f"[Preflight] Critical tools missing for mode '{mode}'. Proceeding with available tools.")
        except Exception as _pf_err:
            logging.debug(f"[Preflight] Check skipped: {_pf_err}")

        result = {
            "ports": [],
            "nse_cves": [],
            "nuclei_findings": [],
            "web_urls": [],
            "cloud_findings": {},
            "os_detection": [],
        }

        if mode == "stealth":
            result = await self._route_stealth(ip, target, index, osint_ports)
        elif mode == "sniper":
            result = await self._route_sniper(ip, target, index, osint_ports)
        elif mode == "web-vuln":
            result = await self._route_web_vuln(ip, target, index, osint_ports)
        elif mode == "cloud-devops":
            result = await self._route_cloud_devops(ip, target, index, osint_ports)
        elif mode == "full-audit":
            result = await self._route_full_audit(ip, target, index, osint_ports)
        elif mode == "api-bounty":
            result = await self._route_api_bounty(ip, target, index, osint_ports)
        # ── V1.0: TACTICAL DOCTRINE 2026 MODES ──
        elif mode == "asset-discovery":
            result = await self._route_asset_discovery(ip, target, index, osint_ports)
        elif mode == "api-breach":
            result = await self._route_api_breach(ip, target, index, osint_ports)
        elif mode == "cloud-native":
            result = await self._route_cloud_native(ip, target, index, osint_ports)
        elif mode == "infra-smash":
            result = await self._route_infra_smash(ip, target, index, osint_ports)
        elif mode == "continuous":
            #  Continuous mode = lightweight diff first, full api-bounty only if significant changes
            self.log.phase("CONTINUOUS MODE — Smart Differential Recon")

            # --- Step 1: Check if we have historical data ---
            has_history = False
            try:
                from core.recon_db import ReconDB
                db = ReconDB()
                stats = db.get_stats(target)
                has_history = stats.get("total_scans", 0) > 0
                if has_history:
                    self.log.info(f"[Continuous] Historical data: {stats['total_scans']} scans, {stats['total_endpoints']} endpoints")
                db.close()
            except Exception:
                pass

            # --- Step 2: Lightweight diff scan (Subfinder + httpx + Nuclei) ---
            run_full_pipeline = not has_history  # First run always full
            if has_history:
                self.log.info("[Continuous] Running lightweight diff scan (Subfinder + httpx + Nuclei)...")
                loop = asyncio.get_running_loop()
                light_subdomains = []
                light_endpoints = []

                # Subfinder quick check
                if shutil.which("subfinder"):
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "subfinder", "-d", target, "-silent", "-timeout", "30",
                            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
                        )
                        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
                        light_subdomains = [s.strip() for s in stdout.decode('utf-8', errors='ignore').splitlines() if s.strip()]
                        self.log.success(f"[Continuous] Subfinder: {len(light_subdomains)} subdomains.")
                    except Exception:
                        pass

                # httpx quick probe
                httpx_plugin = PluginRegistry.get("Httpx")
                if httpx_plugin and httpx_plugin.check_installed():
                    probe_targets = [f"https://{target}", f"http://{target}"]
                    for sub in light_subdomains[:15]:
                        probe_targets.append(f"https://{sub}")
                    httpx_dir = os.path.join(self.raw, "httpx_continuous_light")
                    httpx_results = await loop.run_in_executor(
                        None, httpx_plugin.run, probe_targets, httpx_dir,
                        50, None, self._get_auth_headers(), None,
                        "recon"  # V1.0-FIX: proxy_mode
                    )
                    light_endpoints = [r["url"] for r in httpx_results if r.get("url")]

                # Compare with historical data
                try:
                    from core.recon_db import ReconDB
                    db = ReconDB()
                    diff = db.compute_diff(target, light_subdomains, light_endpoints)
                    db.close()

                    if diff.has_changes and (len(diff.new_endpoints) > 5 or len(diff.new_subdomains) > 3):
                        self.log.success(f"[Continuous] SIGNIFICANT DELTA: {len(diff.new_endpoints)} new endpoints, {len(diff.new_subdomains)} new subdomains → triggering FULL pipeline!")
                        run_full_pipeline = True
                    elif diff.has_changes:
                        self.log.info(f"[Continuous] Minor delta ({len(diff.new_endpoints)} endpoints, {len(diff.new_subdomains)} subs) → lightweight Nuclei scan only.")
                    else:
                        self.log.info("[Continuous] No changes detected → Nuclei-only refresh.")
                except Exception as e:
                    self.log.warning(f"[Continuous] Diff check failed, running full pipeline: {e}")
                    run_full_pipeline = True

            # --- Step 3: Run appropriate pipeline ---
            if run_full_pipeline:
                self.log.info("[Continuous] Running FULL api-bounty pipeline...")
                result = await self._route_api_bounty(ip, target, index, osint_ports)
            else:
                # Lightweight: just Nuclei on known endpoints
                result = {"ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": light_endpoints,
                          "cloud_findings": {}, "os_detection": [], "subdomains": light_subdomains}
                nuclei_plugin = PluginRegistry.get("Nuclei")
                if nuclei_plugin and nuclei_plugin.check_installed() and light_endpoints:
                    nuclei_dir = os.path.join(self.raw, "nuclei_continuous_light")
                    nuclei_results = await self._nuclei_batch_with_retry(
                        light_endpoints, nuclei_dir,
                        tags=["cve", "misconfig", "exposure", "takeover", "default-login"],
                        severity=["critical", "high"],
                        mode="api-bounty", headers=self._get_auth_headers()
                    )
                    result["nuclei_findings"] = nuclei_results
                    self.log.success(f"[Continuous] Nuclei lightweight: {len(nuclei_results)} findings.")
            
            # --- SQLite Differential Engine ---
            try:
                from core.recon_db import ReconDB
                db = ReconDB()
                session_id = db.start_session(target, "continuous")
                
                # Compute diff against historical data
                current_endpoints = [ep.get("url", "") for ep in result.get("api_endpoints", [])]
                current_endpoints += result.get("web_urls", [])
                current_subdomains = result.get("subdomains", [])
                
                diff = db.compute_diff(target, current_subdomains, current_endpoints)
                
                dast_findings = self._get_dast_findings(result)
                if dast_findings:
                    for finding in dast_findings:
                        if not isinstance(finding, dict):
                            continue
                        url = str(finding.get("matched_at") or finding.get("url") or "").strip()
                        if not url:
                            continue
                        sev = str(finding.get("severity", "MEDIUM")).upper()
                        db.upsert_finding(target, session_id, str(finding.get("category", "dast")).lower(), url, sev)
                else:
                    for finding_type, findings_list in [
                        ("ssrf", result.get("ssrf_findings", [])),
                        ("xss", result.get("xss_findings", [])),
                        ("sqli", result.get("sqli_findings", [])),
                        ("crlf", result.get("crlf_findings", [])),
                        ("open_redirect", result.get("open_redirect_findings", [])),
                    ]:
                        for f in findings_list:
                            url = f.get("url", "") if isinstance(f, dict) else str(f)
                            sev = f.get("severity", "MEDIUM") if isinstance(f, dict) else "MEDIUM"
                            db.upsert_finding(target, session_id, finding_type, url, sev)
                
                total_findings = len(dast_findings) + len(result.get("nuclei_findings", [])) if dast_findings else sum([
                    len(result.get("ssrf_findings", [])),
                    len(result.get("xss_findings", [])),
                    len(result.get("sqli_findings", [])),
                    len(result.get("open_redirect_findings", [])),
                    len(result.get("crlf_findings", [])),
                    len(result.get("nuclei_findings", [])),
                ])
                db.end_session(session_id, len(current_endpoints), total_findings)
                
                if diff.has_changes:
                    self.log.success(f"[Continuous] DELTA detected: {diff.summary}")
                else:
                    self.log.info("[Continuous] No new discoveries since last scan.")
                
                stats = db.get_stats(target)
                self.log.info(f"[Continuous] Historical: {stats['total_scans']} scans, {stats['total_endpoints']} endpoints, {stats['total_findings']} findings")
                db.close()
                
            except Exception as e:
                self.log.warning(f"[Continuous] ReconDB error (scan still succeeded): {e}")
        else:
            self.log.warning(f"Unknown mode '{mode}', falling back to sniper.")
            result = await self._route_sniper(ip, target, index, osint_ports)

        return self._finalize_scan_contracts(result, target, mode)

    async def _route_api_breach(self, ip, target, index, osint_ports) -> dict:
        from core.routes.api_breach import APIBreachRoute
        return await APIBreachRoute(self).execute(ip, target, index, osint_ports)

    async def _route_web_vuln(self, ip, target, index, osint_ports) -> dict:
        from core.routes.web_vuln import WebVulnRoute
        return await WebVulnRoute(self).execute(ip, target, index, osint_ports)

    async def _route_cloud_devops(self, ip, target, index, osint_ports) -> dict:
        from core.routes.cloud_devops import CloudDevopsRoute
        return await CloudDevopsRoute(self).execute(ip, target, index, osint_ports)

    async def _route_full_audit(self, ip, target, index, osint_ports) -> dict:
        from core.routes.full_audit import FullAuditRoute
        return await FullAuditRoute(self).execute(ip, target, index, osint_ports)

    async def _route_api_bounty(self, ip, target, index, osint_ports, waf_detected: bool = False) -> dict:
        from core.routes.api_bounty import APIBountyRoute
        return await APIBountyRoute(self).execute(ip, target, index, osint_ports, waf_detected=waf_detected)

    async def _route_cloud_native(self, ip, target, index, osint_ports) -> dict:
        from core.routes.cloud_native import CloudNativeRoute
        return await CloudNativeRoute(self).execute(ip, target, index, osint_ports)

    async def _route_infra_smash(self, ip, target, index, osint_ports) -> dict:
        from core.routes.infra_smash import InfraSmashRoute
        return await InfraSmashRoute(self).execute(ip, target, index, osint_ports)

    # ===================================================================
    # MODE 1: STEALTH — Passive EASM (External Attack Surface Mapping)
    # Pipeline: Subfinder/Amass passive → dnsx → Nmap SYN (no scripts) → httpx (rate-limited) → Nuclei passive
    # ===================================================================
    async def _route_stealth(self, ip, target, index, osint_ports) -> dict:
        from core.routes.stealth import StealthRoute
        return await StealthRoute(self).execute(ip, target, index, osint_ports)

    async def _route_sniper(self, ip, target, index, osint_ports) -> dict:
        from core.routes.sniper import SniperRoute
        return await SniperRoute(self).execute(ip, target, index, osint_ports)

    async def _route_asset_discovery(self, ip, target, index, osint_ports) -> dict:
        from core.routes.asset_discovery import AssetDiscoveryRoute
        return await AssetDiscoveryRoute(self).execute(ip, target, index, osint_ports)




    # ===================================================================
    # HELPER METHODS
    # ===================================================================

    def _derive_nuclei_tags(self, ports: list) -> list:
        """Từ service/version phát hiện được, sinh ra Nuclei tags phù hợp."""
        tags = set()
        service_tag_map = {
            "apache": ["apache", "cve"],
            "nginx": ["nginx", "cve"],
            "tomcat": ["tomcat", "apache", "cve"],
            "iis": ["iis", "microsoft", "cve"],
            "openssh": ["ssh", "openssh", "cve"],
            "vsftpd": ["ftp", "vsftpd", "cve"],
            "proftpd": ["ftp", "proftpd", "cve"],
            "mysql": ["mysql", "cve"],
            "postgres": ["postgres", "cve"],
            "redis": ["redis", "cve"],
            "mongodb": ["mongodb", "cve"],
            "jenkins": ["jenkins", "cve"],
            "gitlab": ["gitlab", "cve"],
            "jira": ["jira", "cve"],
            "confluence": ["confluence", "cve"],
            "exchange": ["exchange", "microsoft", "cve"],
            "wordpress": ["wordpress", "wp-plugin", "cve"],
            "drupal": ["drupal", "cve"],
            "joomla": ["joomla", "cve"],
            "elastic": ["elasticsearch", "cve"],
            "kibana": ["kibana", "cve"],
            "grafana": ["grafana", "cve"],
            "weblogic": ["weblogic", "oracle", "cve"],
            "jboss": ["jboss", "cve"],
            "smb": ["smb", "cve"],
            "rdp": ["rdp", "cve"],
        }

        for port_info in ports:
            service = port_info.get("service", "").lower()
            version = port_info.get("version", "").lower()
            combined = f"{service} {version}"

            for keyword, tag_list in service_tag_map.items():
                if keyword in combined:
                    tags.update(tag_list)

        return list(tags) if tags else ["cve"]

    def _resolve_wordlist(self, purpose: str, *, out_dir: str | None = None, explicit_path: str = "") -> dict:
        from core.wordlist_registry import resolve_wordlist
        return resolve_wordlist(purpose, mode=self.mode, out_dir=out_dir, explicit_path=explicit_path)

    def _ffuf_runtime_options(self) -> dict:
        budget = getattr(self, "performance", performance_budget(self.mode))
        configured_rate = int(self.rate_limit or 0)
        rate = configured_rate if configured_rate and configured_rate != 150 else budget.ffuf_rate
        return {
            "targets": max(1, int(budget.ffuf_targets)),
            "concurrency": max(1, int(budget.ffuf_concurrency)),
            "threads": max(1, int(budget.ffuf_threads)),
            "rate": max(1, int(rate)),
            "timeout": max(30, int(budget.ffuf_timeout)),
        }

    async def _run_ffuf_many(
        self,
        urls: list,
        out_dir: str,
        *,
        headers: dict | None = None,
        purpose: str = "web_content",
        wordlist: str = "",
        limit: int | None = None,
    ) -> list:
        """Run ffuf on independent hosts with bounded concurrency."""
        runtime = self._ffuf_runtime_options()
        targets = unique_http_urls_by_host(urls, limit=limit or runtime["targets"])
        if not targets:
            return []

        os.makedirs(out_dir, exist_ok=True)
        ffuf_sem = asyncio.Semaphore(runtime["concurrency"])

        async def _one(idx: int, target_url: str) -> list:
            target_dir = os.path.join(out_dir, f"{idx:02d}")
            async with ffuf_sem:
                async with self._heavy_task_semaphore:
                    return await self._run_ffuf(
                        target_url,
                        target_dir,
                        headers=headers,
                        purpose=purpose,
                        wordlist=wordlist,
                    )

        batches = await asyncio.gather(
            *[_one(i, target_url) for i, target_url in enumerate(targets)],
            return_exceptions=True,
        )
        results = []
        for item in batches:
            if isinstance(item, Exception):
                self.log.warning(f"[ffuf] Worker failed: {item}")
            elif isinstance(item, list):
                results.extend(item)
        return URLDeduplicator.deduplicate(results)

    async def _run_ffuf(self, url: str, out_dir: str, headers: dict = None, purpose: str = "web_content", wordlist: str = "") -> list:
        """Chạy ffuf tìm directory/file nhạy cảm."""
        results = []
        os.makedirs(out_dir, exist_ok=True)

        wordlist_info = self._resolve_wordlist(purpose, out_dir=out_dir, explicit_path=wordlist)
        wordlist = wordlist_info.get("path", "")
        if not wordlist:
            self.log.warning(f"[ffuf] No wordlist for purpose={purpose}; skipping {url}")
            return results
        self.log.info(
            f"ffuf using {wordlist_info.get('resolved_purpose')} wordlist "
            f"({wordlist_info.get('source')}): {wordlist}"
        )
        with open(os.path.join(out_dir, "wordlist_source.json"), "w", encoding="utf-8") as f:
            json.dump(wordlist_info, f, indent=2)

        ffuf_output = os.path.join(out_dir, "ffuf_results.json")
        runtime = self._ffuf_runtime_options()
        cmd = [
            "ffuf",
            "-u", f"{url.rstrip('/')}/FUZZ",
            "-w", wordlist,
            "-o", ffuf_output,
            "-of", "json",
            "-mc", "200,301,302,403",
            "-s",  # Silent
        ]
        if getattr(self, 'stealth_recon', False):
            cmd.extend(["-t", str(min(runtime["threads"], 3)), "-p", "0.5-2.0"])
        else:
            cmd.extend(["-t", str(runtime["threads"]), "-rate", str(runtime["rate"])])
        
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._subprocess_env(),
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=runtime["timeout"])
                if proc.returncode != 0 and stderr:
                    self.log.warning(f"[ffuf] Non-zero exit ({proc.returncode}): {stderr.decode('utf-8', errors='ignore').strip()[:200]}")
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                self.log.warning(f"[ffuf] Timed out after {runtime['timeout']}s. Partial results only.")

            if os.path.exists(ffuf_output):
                with open(ffuf_output, 'r') as f:
                    data = json.load(f)
                    for r in data.get("results", []):
                        found_url = r.get("url", "")
                        if found_url:
                            results.append(found_url)
                            # [V1.0-FIX] OpenAPI/Swagger Auto-Parser Integration:
                            # Khai thác plugin OpenAPIParser khi ffuf tìm ra tài liệu API
                            found_url_lower = found_url.lower()
                            if any(sw in found_url_lower for sw in ["swagger.json", "openapi.json", "api-docs"]):
                                oas_plugin = PluginRegistry.get("OpenAPIParser")
                                if oas_plugin:
                                    self.log.info(f"[OpenAPI] Swagger schema detected at: {found_url}. Parsing endpoints...")
                                    try:
                                        endpoints_dict = oas_plugin.run(found_url)
                                        parsed_count = 0
                                        from urllib.parse import urljoin
                                        for method, paths in endpoints_dict.items():
                                            for path in paths:
                                                full_api_url = urljoin(found_url, path)
                                                results.append(full_api_url)
                                                parsed_count += 1
                                        if parsed_count > 0:
                                            self.log.success(f"[OpenAPI] Extracted {parsed_count} API endpoints from {found_url}")
                                    except Exception as _oae:
                                        self.log.debug(f"[OpenAPI] Parse error for {found_url}: {_oae}")
        except Exception as e:
            self.log.warning(f"[ffuf] Pipeline error: {str(e)}")

        return results

    async def _scan_udp_top20(self, ip: str) -> list:
        """
         Nmap UDP scan (async) cho top 20 critical UDP services.
        SNMP(161), DNS(53), TFTP(69), NTP(123), IPMI(623), NetBIOS(137)
        """
        import tempfile
        import xml.etree.ElementTree as ET
        results = []
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
            xml_path = tmp.name
        try:
            cmd = [
                "nmap", "-sU", "-Pn", "-sV",
                "--top-ports", "20",
                "--version-intensity", "2",
                "--max-retries", "1",
                "--host-timeout", "3m",
                "-oX", xml_path, ip
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                env=self._subprocess_env(),
            )
            await asyncio.wait_for(proc.wait(), timeout=240)
            if os.path.exists(xml_path):
                root = ET.parse(xml_path).getroot()
                for p in root.findall(".//port"):
                    state = p.find("state")
                    if state is not None and state.get("state") in ["open", "open|filtered"]:
                        svc = p.find("service")
                        name = svc.get("name") if svc is not None else "unknown"
                        ver = (svc.get("product", "") + " " + svc.get("version", "")).strip() if svc is not None else ""
                        results.append({
                            "port": int(p.get("portid", "0")),
                            "service": name,
                            "version": ver,
                            "protocol": "udp",
                        })
        except Exception:
            pass
        finally:
            try:
                os.unlink(xml_path)
            except OSError:
                pass
        return results

    # ===================================================================
    #  NEW HELPER METHODS — P3 + Cross-Mode Gap Fixes
    # ===================================================================

    async def _nuclei_batch_with_retry(self, targets, out_dir, tags=None, templates=None,
                                        severity=None, mode="sniper", max_retries=2, headers=None):
        """
         Nuclei batch scan với retry on failure.
        Sử dụng per-mode rate-limit từ Config.RATE_LIMITS.
        """
        from config import Config
        nuclei_plugin = PluginRegistry.get("Nuclei")
        if not nuclei_plugin or not nuclei_plugin.check_installed() or not targets:
            return []

        from core.db import get_session, get_or_create_project, get_cached_result, save_to_cache
        
        cached_findings = []
        uncached_targets = []
        
        ttl_hours = getattr(Config, "NUCLEI_CACHE_TTL_HOURS", 24)
        cache_key_suffix = f"tags={','.join(sorted(tags or []))}:templates={','.join(sorted(templates or []))}:sev={','.join(sorted(severity or []))}"
        
        try:
            with get_session("") as session:
                for target in targets:
                    slug = target.replace(".", "-").replace(":", "-").lower()[:128]
                    project = get_or_create_project(session, name=f"PenLabs — {target}", slug=slug)
                    
                    cached = get_cached_result(session, project.id, target, "nuclei", cache_key_suffix, ttl_hours=ttl_hours)
                    if cached is not None:
                        self.log.info(f"[Nuclei Cache] HIT for {target}")
                        cached_findings.extend(cached)
                    else:
                        uncached_targets.append(target)
        except Exception as e:
            self.log.warning(f"[Nuclei Cache] Cache lookup error: {e}")
            uncached_targets = targets

        if not uncached_targets:
            self.log.success(f"[Nuclei Cache] All {len(targets)} targets hit cache. Skipping scan.")
            return cached_findings

        strategy = self._strategy_profile("nuclei", mode, parameterized_count=len(targets or []))
        from core.plugin_strategy import merge_nuclei_tags
        tags = merge_nuclei_tags(tags or [], strategy)
        rate_cfg = dict(Config.RATE_LIMITS.get(mode, Config.RATE_LIMITS["sniper"]))
        configured_rate = int(self.rate_limit or 0)
        if configured_rate and configured_rate != 150:
            rate_cfg["nuclei_rate"] = min(int(rate_cfg.get("nuclei_rate") or configured_rate), configured_rate)
            if configured_rate <= 5:
                rate_cfg["nuclei_conc"] = min(int(rate_cfg.get("nuclei_conc") or 2), 2)
        if strategy.get("rate_profile") == "low":
            rate_cfg["nuclei_rate"] = min(int(rate_cfg.get("nuclei_rate") or 30), 45)
            rate_cfg["nuclei_conc"] = min(int(rate_cfg.get("nuclei_conc") or 5), 8)
        loop = asyncio.get_running_loop()
        
        new_findings = []
        for attempt in range(1, max_retries + 1):
            try:
                merged_extra_flags = self._ja3_tool_args("nuclei")
                results = await loop.run_in_executor(
                    None,
                    lambda: nuclei_plugin.run_batch(
                        uncached_targets, out_dir,
                        tags or [], templates or [],
                        severity or ["critical", "high", "medium"],
                        rate_cfg.get("nuclei_rate"), rate_cfg.get("nuclei_conc"),
                        merged_extra_flags or None, headers,
                        proxy_mode=strategy.get("proxy_mode", "recon"),
                    )
                )
                
                from core.output_normalizer import normalize_output
                normalized_results = []
                for r in results:
                    norm = normalize_output(r, uncached_targets[0] if uncached_targets else "", force_tool="nuclei")
                    for item in norm:
                        d = item.model_dump()
                        if "discovered_at" in d and d["discovered_at"]:
                            d["discovered_at"] = d["discovered_at"].isoformat()
                        normalized_results.append(d)
                
                new_findings = normalized_results
                
                try:
                    with get_session("") as session:
                        for target in uncached_targets:
                            target_domain = target.replace("http://", "").replace("https://", "").split("/")[0].split(":")[0]
                            target_findings = []
                            for f in new_findings:
                                f_matched = f.get("matched_at", "").lower()
                                if target_domain.lower() in f_matched or target.lower() in f_matched:
                                    target_findings.append(f)
                            
                            slug = target.replace(".", "-").replace(":", "-").lower()[:128]
                            project = get_or_create_project(session, name=f"PenLabs — {target}", slug=slug)
                            save_to_cache(session, project.id, target, "nuclei", cache_key_suffix, target_findings, ttl_hours=ttl_hours)
                except Exception as cache_save_err:
                    self.log.warning(f"[Nuclei Cache] Failed to save cache: {cache_save_err}")
                
                break
            except Exception as e:
                self.log.warning(f"[Nuclei] Attempt {attempt}/{max_retries} failed: {e}")
                if attempt < max_retries:
                    import time
                    time.sleep(2)
        else:
            self.log.error("[Nuclei] All retry attempts exhausted.")

        return cached_findings + new_findings

    # ===================================================================
    # [V1.0] HELPER: Bypass403Fuzzer — Bypass 403 Forbidden via Headers
    # ===================================================================
    async def _bypass_403(self, forbidden_urls: list, timeout: int = 10) -> list:
        """
        Thử bypass 403 Forbidden bằng header manipulation và path mutation.
        
        Returns:
            list: [{"url": "...", "bypass_method": "...", "status": 200}]
        """
        import requests as _req
        bypassed = []
        
        BYPASS_HEADERS = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Original-URL": "/{path}"},
            {"X-Rewrite-URL": "/{path}"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-Host": "localhost"},
            {"X-Host": "localhost"},
            {"Forwarded": "for=127.0.0.1;by=127.0.0.1;host=localhost"},
        ]
        
        PATH_MUTATIONS = [
            lambda p: p + "/",
            lambda p: p + "/.",
            lambda p: p + "..;/",
            lambda p: p + "%20",
            lambda p: p + "%09",
            lambda p: "/%2e" + p,
            lambda p: p.upper() if p != p.upper() else p,
            lambda p: p + "?",
            lambda p: p + "#",
            lambda p: p + ";",
        ]
        
        for url in forbidden_urls[:15]:  # Giới hạn 15 URLs
            url = url.strip()
            if not url:
                continue
                
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path or "/"
            
            # Test bypass headers
            for bypass_header in BYPASS_HEADERS:
                header = {}
                for k, v in bypass_header.items():
                    header[k] = v.replace("{path}", path)
                header["User-Agent"] = "Mozilla/5.0"
                
                try:
                    resp = _req.get(url, headers=header, timeout=timeout,
                                   verify=False, allow_redirects=False)
                    if resp.status_code in (200, 301, 302):
                        bypassed.append({
                            "url": url,
                            "bypass_method": f"Header: {list(bypass_header.keys())[0]}",
                            "status": resp.status_code,
                            "severity": "high",
                        })
                        break
                except Exception:
                    continue
            
            # Test path mutations
            for mutate in PATH_MUTATIONS[:5]:  # Top 5 mutations
                try:
                    mutated_path = mutate(path)
                    mutated_url = url.replace(path, mutated_path, 1)
                    resp = _req.get(mutated_url, timeout=timeout, verify=False,
                                   headers={"User-Agent": "Mozilla/5.0"},
                                   allow_redirects=False)
                    if resp.status_code in (200, 301, 302):
                        bypassed.append({
                            "url": url,
                            "bypass_method": f"Path mutation: {mutated_path}",
                            "status": resp.status_code,
                            "severity": "high",
                        })
                        break
                except Exception:
                    continue
        
        return bypassed

    # ===================================================================
    # [V1.0] HELPER: CachePoisonProbe — Web Cache Poisoning Detection
    # ===================================================================
    async def _cache_poison_probe(self, urls: list, timeout: int = 10) -> list:
        """
        Gửi unkeyed headers và kiểm tra phản xạ trong response.
        
        Returns:
            list: [{"url": "...", "unkeyed_header": "...", "severity": "high"}]
        """
        import requests as _req
        import hashlib
        findings = []
        
        UNKEYED_HEADERS = {
            "X-Forwarded-Host": "evil-cache-test.com",
            "X-Forwarded-Scheme": "nothttps",
            "X-Forwarded-Proto": "nothttps",
            "X-Original-URL": "/cache-test-evil",
            "X-Rewrite-URL": "/cache-test-evil",
            "X-Forwarded-Port": "1337",
        }
        
        for url in urls[:10]:  # Giới hạn 10 URLs
            url = url.strip()
            if not url:
                continue
            
            # Thêm cache-buster để tránh poison cache thật
            cache_buster = hashlib.md5(url.encode()).hexdigest()[:8]
            sep = "&" if "?" in url else "?"
            test_url = f"{url}{sep}cb={cache_buster}"
            
            for header_name, header_value in UNKEYED_HEADERS.items():
                try:
                    # Gửi request với unkeyed header
                    resp = _req.get(test_url, headers={
                        header_name: header_value,
                        "User-Agent": "Mozilla/5.0",
                    }, timeout=timeout, verify=False, allow_redirects=False)
                    
                    body = resp.text
                    # Kiểm tra phản xạ
                    if header_value in body:
                        # Kiểm tra cache header
                        cache_status = resp.headers.get("X-Cache", resp.headers.get("CF-Cache-Status", ""))
                        cache_hit = "HIT" in cache_status.upper()
                        finding = {
                            "url": url,
                            "unkeyed_header": header_name,
                            "reflected_value": header_value,
                            "cache_status": cache_status,
                            "severity": "high" if cache_hit else "low",
                            "confidence": "HIGH" if cache_hit else "LOW",
                            "details": f"Header '{header_name}: {header_value}' reflected in response body. Cache: {cache_status}",
                        }
                        findings.append(attach_evidence(
                            finding,
                            make_evidence(
                                method="GET",
                                url=test_url,
                                payload={header_name: header_value},
                                status_code=resp.status_code,
                                request_headers={
                                    header_name: header_value,
                                    "User-Agent": "Mozilla/5.0",
                                },
                                response_headers=dict(resp.headers or {}),
                                response_snippet=body,
                                validation=(
                                    f"Unkeyed header {header_name} reflected in body; "
                                    f"cache status header was {cache_status or '<missing>'}; "
                                    f"cache-hit confirmation={cache_hit}."
                                ),
                                confidence="high" if cache_hit else "low",
                            ),
                        ))
                        break  # 1 finding per URL đủ rồi
                except Exception:
                    continue
        
        return findings

    # ===================================================================
    # MODE 6: API-BOUNTY — Bug Bounty Pipeline (V1.0 Tier-1)
    # Pipeline: httpx → Katana → Kiterunner → LinkFinder → WPScan
    #           → Arjun → Dalfox → Blind XSS → SQLMap → SSRF Probe
    #           → Open Redirect → CRLF → Corsy → GraphQL → 403 Bypass
    #           → Cache Poison → Race Condition → BOLA → Nuclei → Reports
    # ===================================================================
    async def _route_api_bounty(self, ip, target, index, osint_ports, waf_detected: bool = False) -> dict:
        self.log.phase("API-BOUNTY MODE — 🎯 Bug Bounty Hunting Pipeline (V1.0 — 20 Steps)")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [],
            # V1.0 bounty-specific fields
            "api_endpoints": [], "hidden_params": {}, "js_secrets": [],
            "xss_findings": [], "cors_findings": [], "cors_issues": [], "graphql_findings": [], "graphql": {},
            "bypass_403": [], "cache_poisoning": [], "sqli_findings": [],
            "mass_assignment_findings": [],
            "wpscan": {},
            # V1.0 NEW fields
            "ssrf_findings": [], "blind_xss": {}, "open_redirect_findings": [],
            "crlf_findings": [], "race_condition_findings": [],
            "bola_findings": {},
            "dast_findings": [],
        }
        loop = asyncio.get_running_loop()

        #  Tool Inventory — log what's available before starting
        _api_bounty_tools = [
            ("httpx", "Httpx", "Step 1: Live URL & Tech Fingerprint"),
            ("katana", "Katana", "Step 2: JS-Aware Crawling"),
            ("ffuf", None, "Step 3: Directory Fuzzing"),
            ("arjun", "Arjun", "Step 5: Hidden Parameter Discovery"),
            ("dalfox", "Dalfox", "Step 6: XSS Scanning"),
            ("sqlmap", None, "Step 8: SQL Injection"),
            ("kiterunner", "Kiterunner", "Step 4: API Route Discovery"),
            ("gowitness", None, "Step 3b: Visual Recon"),
            ("nuclei", "Nuclei", "Step 19: Nuclei Batch Scan"),
        ]
        _steps_available = 0
        _steps_total = 20
        self.log.info("📋 Tool Inventory for API-BOUNTY pipeline:")
        for tool_cli, plugin_name, step_desc in _api_bounty_tools:
            available = shutil.which(tool_cli) is not None
            status = "✅" if available else "❌ SKIPPED"
            self.log.info(f"  {status} {tool_cli:<16} → {step_desc}")
            if available:
                _steps_available += 1
        # Plugins without CLI (Python-based)
        for pname, desc in [("WPScan", "Step 3c: WordPress Scan"), ("Corsy", "Step 14: CORS Check")]:
            p = PluginRegistry.get(pname)
            avail = p is not None
            self.log.info(f"  {'✅' if avail else '❌ SKIPPED'} {pname:<16} → {desc}")
            if avail:
                _steps_available += 1

        from config import Config as _Cfg
        httpx_plugin = PluginRegistry.get("Httpx")
        live_urls = []
        live_urls_typed = []
        
        # Chuẩn bị targets từ OSINT ports hoặc default HTTP ports
        scan_targets = []
        if osint_ports:
            web_ports = [p for p in osint_ports if int(p) in [80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9090]]
            if not web_ports:
                web_ports = [80, 443]
            for port in web_ports:
                scheme = "https" if int(port) in [443, 8443] else "http"
                base_url = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
                scan_targets.append(base_url)
        if not scan_targets:
            scan_targets = [f"https://{target}", f"http://{target}"]
        
        if httpx_plugin and httpx_plugin.check_installed():
            self.log.info("httpx probing live URLs + tech detection...")
            httpx_dir = os.path.join(self.raw, "httpx_bounty")
            httpx_results = await loop.run_in_executor(
                None, httpx_plugin.run, scan_targets, httpx_dir, 
                50, None, self._get_auth_headers(), None,
                "recon"  # V1.0-FIX: proxy_mode
            )
            for r in httpx_results:
                url = r.get("url", "")
                if url:
                    live_urls.append(url)
                    live_urls_typed.append(r)
            self.log.success(f"httpx found {len(live_urls)} live HTTP services.")
        else:
            live_urls = scan_targets

        if not live_urls:
            self.log.warning("No live HTTP services found. Aborting api-bounty scan.")
            return result

        #  Step 1b: Playwright SPA Discovery
        if self.use_playwright:
            playwright_plugin = PluginRegistry.get("Playwright")
            if playwright_plugin:
                self.log.info(f"Playwright SPA discovery on {min(len(live_urls), 5)} URLs...")
                try:
                    pw_results = await playwright_plugin.run(
                        live_urls[:5], self.raw, timeout=30, 
                        headers=self._get_auth_headers(), proxy=self.proxy_file
                    )
                    if pw_results.get("endpoints"):
                        self.log.success(f"Playwright discovered {len(pw_results['endpoints'])} hidden API endpoints.")
                        live_urls.extend(pw_results["endpoints"])
                        live_urls = list(set(live_urls))
                except Exception as e:
                    self.log.warning(f"Playwright failed: {e}")

        # ── Step 2: Katana — JS-Aware Web Crawling ──
        katana_plugin = PluginRegistry.get("Katana")
        raw_crawled = []
        js_files = []
        api_like_urls = []
        
        if katana_plugin and katana_plugin.check_installed():
            katana_limit = _Cfg.KATANA_MAX_URLS.get("api-bounty", 50)
            self.log.info(f"Katana crawling {min(len(live_urls), katana_limit)} URLs (JS-aware, depth=3)...")
            for crawl_data in await self._run_katana_many(
                katana_plugin,
                live_urls,
                "api_bounty",
                limit=katana_limit,
                depth=3,
                js_crawl=True,
                headless=False,
                proxy_mode="fuzz",
            ):
                self._append_crawl_output(crawl_data, raw_crawled, api_like_urls=api_like_urls, js_files=js_files)
            
            base_urls, param_urls = URLDeduplicator.deduplicate_with_params(raw_crawled)
            result["web_urls"] = base_urls
            result["web_urls_with_params"] = param_urls
            self.log.success(f"Katana: {len(base_urls)} base + {len(param_urls)} parameterized + {len(js_files)} JS files.")

        # ── Step 3: Kiterunner — API Route Discovery ──
        kr_plugin = PluginRegistry.get("Kiterunner")
        if kr_plugin and kr_plugin.check_installed():
            self.log.info("Kiterunner brute-forcing API routes (Swagger wordlists)...")
            kr_dir = os.path.join(self.raw, "kiterunner")
            kr_wordlist = self._resolve_wordlist("api_routes", out_dir=kr_dir).get("path") or _Cfg.KITERUNNER_WORDLIST
            kr_targets = unique_http_urls_by_host(
                live_urls,
                limit=getattr(self.performance, "kiterunner_targets", 30),
            )
            # [V1.0-APEX] Semaphore cho Kiterunner (Heavy Wordlist Scan)
            async with self._heavy_task_semaphore:
                kr_results = await loop.run_in_executor(
                    None, kr_plugin.run, kr_targets or live_urls, kr_dir,
                    kr_wordlist, _Cfg.KITERUNNER_MAX_CONN,
                    self._get_auth_headers(), _Cfg.KITERUNNER_TIMEOUT
                )
            result["api_endpoints"] = self._normalize_api_endpoints(kr_results, source="kiterunner")
            # Thêm API endpoints vào param_urls cho DAST scan
            for ep in result["api_endpoints"]:
                if ep.get("url"):
                    api_like_urls.append(ep["url"])
            self.log.success(f"Kiterunner: {len(kr_results)} API endpoints discovered.")
        else:
            self.log.warning("[Kiterunner] Not installed — skip API route discovery.")

        # ── Step 4: LinkFinder — JS Endpoint + Secret Extraction ──
        lf_plugin = PluginRegistry.get("LinkFinder")
        if lf_plugin and js_files:
            self.log.info(f"LinkFinder analyzing {len(js_files)} JavaScript files for endpoints & secrets...")
            lf_dir = os.path.join(self.raw, "linkfinder")
            # [V1.0-APEX] Semaphore cho LinkFinder
            async with self._heavy_task_semaphore:
                lf_results = await loop.run_in_executor(
                    None, lf_plugin.run, js_files, lf_dir, 15, 50
                )
            # Thêm endpoints từ JS vào danh sách
            for ep in lf_results.get("endpoints", []):
                if ep.startswith("/"):
                    for base in live_urls[:3]:
                        api_like_urls.append(f"{base.rstrip('/')}{ep}")
            result["js_secrets"] = lf_results.get("secrets", [])
            self.log.success(f"LinkFinder: {len(lf_results.get('endpoints', []))} endpoints, {len(result['js_secrets'])} secrets found.")
        
        # ── Step 5: WPScan — WordPress Detection & Scanning ──
        wp_plugin = PluginRegistry.get("WPScan")
        if wp_plugin and wp_plugin.check_installed():
            for url in live_urls[:3]:
                if wp_plugin.detect_wordpress(url):
                    self.log.info(f"WordPress detected on {url}! Running WPScan...")
                    wp_dir = os.path.join(self.raw, "wpscan")
                    wp_strategy = self._strategy_profile("wpscan", "api-bounty", tech_stack=["wordpress"])
                    # [V1.0-APEX] Semaphore cho WPScan
                    async with self._heavy_task_semaphore:
                        wp_result = await loop.run_in_executor(
                            None, wp_plugin.run, url, wp_dir,
                            _Cfg.WPSCAN_API_TOKEN, wp_strategy.get("enumerate", "vp,vt,u"),
                            _Cfg.WPSCAN_TIMEOUT, True, ""
                        )
                    result["wpscan"] = wp_result
                    wp_result["target_url"] = url
                    self._extend_dast_findings(result, "wordpress", wp_result)
                    self.log.success(f"WPScan: WordPress {wp_result.get('version', '?')}, "
                                     f"{len(wp_result.get('vulnerabilities', []))} vulns, "
                                     f"{len(wp_result.get('users', []))} users.")
                    break

        # ── Step 6: Arjun — Hidden Parameter Discovery ──
        arjun_plugin = PluginRegistry.get("Arjun")
        if arjun_plugin and arjun_plugin.check_installed():
            # Ưu tiên quét endpoints có chứa /api/, /user/, /admin/, /account/
            priority_urls = [u for u in api_like_urls if any(
                kw in u.lower() for kw in ["/api/", "/user", "/admin", "/account", "/profile", "/order", "/v1/", "/v2/"]
            )]
            scan_urls = (priority_urls or api_like_urls)[:_Cfg.ARJUN_MAX_ENDPOINTS]
            if scan_urls:
                self.log.info(f"Arjun discovering hidden params on {len(scan_urls)} priority endpoints...")
                arjun_dir = os.path.join(self.raw, "arjun")
                # [V1.0-APEX] Semaphore cho Arjun (Heavy Parameter Fuzz)
                async with self._heavy_task_semaphore:
                    arjun_results = await loop.run_in_executor(
                        None, arjun_plugin.run, scan_urls, arjun_dir,
                        "GET", self._get_auth_headers(),
                        _Cfg.ARJUN_TIMEOUT_PER_URL, _Cfg.ARJUN_MAX_ENDPOINTS
                    )
                result["hidden_params"] = arjun_results
                self.log.success(f"Arjun: Hidden params found on {len(arjun_results)} URLs.")

        # ── Step 7: Dalfox — XSS Scanning ──
        dalfox_plugin = PluginRegistry.get("Dalfox")
        param_urls = result.get("web_urls_with_params", [])
        if dalfox_plugin and dalfox_plugin.check_installed() and param_urls:
            if waf_detected:
                self.log.info(f"[PROXY] Escalating Dalfox to EXPLOIT mode due to WAF detection")
            self.log.info(f"Dalfox XSS scanning {min(len(param_urls), _Cfg.DALFOX_MAX_URLS)} parameterized URLs...")
            dalfox_dir = os.path.join(self.raw, "dalfox")
            dalfox_strategy = self._strategy_profile(
                "dalfox", "api-bounty", waf_detected=waf_detected,
                parameterized_count=len(param_urls or []),
            )
            noise_stop = asyncio.Event()
            noise_task = asyncio.create_task(self._send_behavioral_noise(noise_stop, f"https://{target}"))
            try:
                # [V1.0-APEX] Semaphore cho Dalfox
                async with self._heavy_task_semaphore:
                    dalfox_results = await loop.run_in_executor(
                        None, dalfox_plugin.run, param_urls, dalfox_dir,
                        self._get_auth_headers(), _Cfg.DALFOX_TIMEOUT_PER_URL,
                        _Cfg.DALFOX_MAX_URLS, "", waf_detected,
                        dalfox_strategy.get("proxy_mode", "fuzz"),
                        bool(dalfox_strategy.get("deep_domxss")),
                    )
            finally:
                noise_stop.set()
                await asyncio.gather(noise_task, return_exceptions=True)
                result["xss_findings"] = dalfox_results
                self._extend_dast_findings(result, "xss", dalfox_results)
                self.log.success(f"Dalfox: {len(dalfox_results)} XSS vulnerabilities found.")
        elif not param_urls:
            self.log.info("[Dalfox] No parameterized URLs to scan.")

        # ── Step 8: SQLMap Detect-Only ──
        sqlmap_plugin = PluginRegistry.get("SQLMapDetect")
        if sqlmap_plugin and sqlmap_plugin.check_installed() and param_urls:
            # Chỉ quét URL có params kiểu id, user_id, order_id (dấu hiệu SQLi)
            sqli_candidates = [u for u in param_urls if any(
                kw in u.lower() for kw in ["id=", "uid=", "user_id=", "order=", "item=", "pid=", "cat=", "page="]
            )]
            if sqli_candidates:
                self.log.info(f"SQLMap detect-only scanning {len(sqli_candidates)} SQLi candidate URLs...")
                sqlmap_dir = os.path.join(self.raw, "sqlmap")
                sqlmap_strategy = self._strategy_profile(
                    "sqlmap", "api-bounty", waf_detected=waf_detected,
                    parameterized_count=len(sqli_candidates),
                )
                # [V1.0-APEX] Semaphore cho SQLMap (Heavy Exploitation Binary)
                async with self._heavy_task_semaphore:
                    sqli_results = await loop.run_in_executor(
                        None, sqlmap_plugin.run, sqli_candidates, sqlmap_dir,
                        self._get_auth_headers(), _Cfg.SQLMAP_DETECT_TIMEOUT,
                        _Cfg.SQLMAP_DETECT_MAX_URLS, "", "", waf_detected, self.sqlmap_relay,
                        sqlmap_strategy.get("risk", 1),
                        sqlmap_strategy.get("level", 1),
                        sqlmap_strategy.get("tamper", []),
                    )
                result["sqli_findings"] = sqli_results
                self._extend_dast_findings(result, "sqli", sqli_results)
                self.log.success(f"SQLMap: {len(sqli_results)} SQL Injection points detected (no exploit).")

        # ── Step 9: Corsy — CORS Misconfiguration Check ──
        corsy_plugin = PluginRegistry.get("Corsy")
        if corsy_plugin:
            # V1.0-FIX: Pass WAF state for proxy escalation
            _corsy_proxy_mode = "exploit" if waf_detected else "fuzz"
            if waf_detected:
                self.log.info(f"[PROXY] Escalating Corsy to EXPLOIT mode due to WAF detection")
            self.log.info(f"Corsy checking CORS on {min(len(live_urls), 30)} URLs...")
            corsy_dir = os.path.join(self.raw, "corsy")
            cors_results = await loop.run_in_executor(
                None, corsy_plugin.run, live_urls, corsy_dir,
                self._get_auth_headers(), 10, 30, waf_detected,
                _corsy_proxy_mode  # V1.0-FIX: proxy_mode
            )
            result["cors_findings"] = cors_results
            result["cors_issues"] = cors_results
            self._extend_dast_findings(result, "cors", cors_results)
            if cors_results:
                self.log.success(f"Corsy: {len(cors_results)} CORS misconfiguration issues!")

        # ── Step 10: GraphQL Probe ──
        gql_plugin = PluginRegistry.get("GraphQLProbe")
        if gql_plugin:
            self.log.info("GraphQL Probe checking for GraphQL endpoints...")
            gql_dir = os.path.join(self.raw, "graphql")
            gql_results = await loop.run_in_executor(
                None, gql_plugin.run, live_urls, gql_dir,
                self._get_auth_headers(), 10, 10
            )
            result["graphql_findings"] = gql_results.get("introspection_enabled", []) + gql_results.get("graphql_vulns", gql_results.get("findings", []))
            result["graphql"] = gql_results
            self._extend_dast_findings(result, "graphql", result["graphql_findings"])
            if gql_results.get("endpoints_found"):
                self.log.success(f"GraphQL: {len(gql_results['endpoints_found'])} endpoints, "
                                 f"{len(gql_results.get('introspection_enabled', []))} with introspection!")

        # ── Step 11: 403 Bypass Fuzzer ──
        # Thu thập URLs trả về 403
        forbidden_urls = []
        for ep in result.get("api_endpoints", []):
            if ep.get("status") == 403:
                forbidden_urls.append(ep.get("url", ""))
        # Thêm từ httpx
        for r in live_urls_typed:
            if r.get("status_code") == 403:
                forbidden_urls.append(r.get("url", ""))
        
        if forbidden_urls:
            self.log.info(f"403 Bypass Fuzzer testing {len(forbidden_urls)} forbidden URLs...")
            bypass_results = await self._bypass_403(forbidden_urls)
            result["bypass_403"] = bypass_results
            self._extend_dast_findings(result, "bypass_403", bypass_results)
            if bypass_results:
                self.log.success(f"403 Bypass: {len(bypass_results)} URLs bypassed!")

        # ── Step 12: Cache Poisoning Probe ──
        self.log.info("Cache Poisoning Probe testing unkeyed headers...")
        cache_results = await self._cache_poison_probe(live_urls)
        result["cache_poisoning"] = cache_results
        self._extend_dast_findings(result, "cache_poisoning", cache_results)
        if cache_results:
            self.log.success(f"Cache Poisoning: {len(cache_results)} potential vectors found!")

        # ── Step 13: Blind XSS Injector (V1.0 NEW) ──
        bxss_plugin = PluginRegistry.get("BlindXSS")
        if bxss_plugin and bxss_plugin.check_installed():
            self.log.info(f"Blind XSS Injector scanning {min(len(live_urls), _Cfg.BLIND_XSS_MAX_URLS)} URLs for stored/blind XSS...")
            bxss_dir = os.path.join(self.raw, "blind_xss")
            interactsh_url = getattr(self, '_interactsh_url', '') or ''
            bxss_results = await loop.run_in_executor(
                None, bxss_plugin.run, live_urls, bxss_dir,
                self._get_auth_headers(), interactsh_url,
                10, _Cfg.BLIND_XSS_MAX_URLS, "exploit" if waf_detected else "fuzz"
            )
            result["blind_xss"] = bxss_results
            self._extend_dast_findings(result, "blind_xss", bxss_results)
            self.log.success(f"Blind XSS: Injected {bxss_results.get('injected_count', 0)} payloads into {bxss_results.get('forms_found', 0)} forms.")

        # ── Step 14: Mass Assignment Probe ──
        mass_assignment_plugin = PluginRegistry.get("MassAssignment")
        if mass_assignment_plugin:
            mass_assignment_targets = []
            for url, params in result.get("hidden_params", {}).items():
                if any(any(keyword in str(param).lower() for keyword in ["role", "admin", "privilege", "staff", "permission", "verified", "balance", "credit"]) for param in params or []):
                    mass_assignment_targets.append(url)
            if not mass_assignment_targets:
                for ep in result.get("api_endpoints", []):
                    ep_url = ep.get("url", "")
                    if any(keyword in ep_url.lower() for keyword in ["/user", "/users", "/account", "/profile", "/admin", "/member"]):
                        mass_assignment_targets.append(ep_url)
            if not mass_assignment_targets:
                for ep_url in api_like_urls:
                    if any(keyword in ep_url.lower() for keyword in ["/user", "/users", "/account", "/profile", "/admin", "/member"]):
                        mass_assignment_targets.append(ep_url)
            mass_assignment_targets = URLDeduplicator.deduplicate(mass_assignment_targets)[:10]
            if mass_assignment_targets:
                self.log.info(f"Mass Assignment testing {len(mass_assignment_targets)} API targets...")
                mass_assignment_results = await loop.run_in_executor(
                    None,
                    lambda: mass_assignment_plugin.run(
                        urls=mass_assignment_targets,
                        auth_token=self.auth_userA or "",
                        method="POST",
                        headers=self._get_auth_headers(),
                        timeout=15,
                    ),
                )
                result["mass_assignment_findings"] = mass_assignment_results
                self._extend_dast_findings(result, "mass_assignment", mass_assignment_results)
                if mass_assignment_results:
                    self.log.success(f"Mass Assignment: {len(mass_assignment_results)} potential privilege-assignment findings!")

        # ── Step 15: SSRF Probe (V1.0 NEW) ──
        ssrf_plugin = PluginRegistry.get("SSRFProbe")
        if ssrf_plugin and ssrf_plugin.check_installed():
            # Ưu tiên URLs có params (SSRF qua param injection)
            ssrf_targets = param_urls[:_Cfg.SSRF_MAX_URLS] if param_urls else live_urls[:10]
            if ssrf_targets:
                self.log.info(f"SSRF Probe testing {len(ssrf_targets)} URLs for Server-Side Request Forgery...")
                ssrf_dir = os.path.join(self.raw, "ssrf")
                interactsh_url = getattr(self, '_interactsh_url', '') or ''
                ssrf_results = await loop.run_in_executor(
                    None, ssrf_plugin.run, ssrf_targets, ssrf_dir,
                    self._get_auth_headers(), interactsh_url,
                    _Cfg.SSRF_TIMEOUT_PER_URL, _Cfg.SSRF_MAX_URLS
                )
                result["ssrf_findings"] = ssrf_results
                self._extend_dast_findings(result, "ssrf", ssrf_results)
                if ssrf_results:
                    self.log.success(f"SSRF Probe: {len(ssrf_results)} SSRF vulnerabilities found!")
                else:
                    self.log.info("[SSRF] No SSRF detected.")

        # ── Step 16: Open Redirect Scanner (V1.0 NEW) ──
        redirect_plugin = PluginRegistry.get("OpenRedirect")
        if redirect_plugin and redirect_plugin.check_installed():
            redirect_targets = param_urls[:_Cfg.OPEN_REDIRECT_MAX_URLS] if param_urls else live_urls[:20]
            self.log.info(f"Open Redirect Scanner testing {len(redirect_targets)} URLs...")
            redirect_dir = os.path.join(self.raw, "open_redirect")
            redirect_results = await loop.run_in_executor(
                None, redirect_plugin.run, redirect_targets, redirect_dir,
                self._get_auth_headers(), 10, _Cfg.OPEN_REDIRECT_MAX_URLS
            )
            result["open_redirect_findings"] = redirect_results
            self._extend_dast_findings(result, "open_redirect", redirect_results)
            if redirect_results:
                self.log.success(f"Open Redirect: {len(redirect_results)} redirect vulnerabilities found!")

        # ── Step 17: CRLF Injection Scanner (V1.0 NEW) ──
        crlf_plugin = PluginRegistry.get("CRLFScan")
        if crlf_plugin and crlf_plugin.check_installed():
            self.log.info(f"CRLF Scanner testing {min(len(live_urls), _Cfg.CRLF_MAX_URLS)} URLs for header injection...")
            crlf_dir = os.path.join(self.raw, "crlf")
            crlf_results = await loop.run_in_executor(
                None, crlf_plugin.run, live_urls, crlf_dir,
                self._get_auth_headers(), 10, _Cfg.CRLF_MAX_URLS
            )
            result["crlf_findings"] = crlf_results
            self._extend_dast_findings(result, "crlf", crlf_results)
            if crlf_results:
                self.log.success(f"CRLF: {len(crlf_results)} CRLF injection points found!")

        # ── Step 18: Race Condition Tester (V1.0 NEW) ──
        race_plugin = PluginRegistry.get("RaceTest")
        all_discovered_urls = list(set(live_urls + api_like_urls + param_urls))
        if race_plugin and race_plugin.check_installed() and all_discovered_urls:
            self.log.info(f"Race Condition Tester checking {len(all_discovered_urls)} endpoints for TOCTOU...")
            race_dir = os.path.join(self.raw, "race_condition")
            race_results = await loop.run_in_executor(
                None, race_plugin.run, all_discovered_urls, race_dir,
                self._get_auth_headers(), _Cfg.RACE_CONDITION_CONCURRENT,
                15, _Cfg.RACE_CONDITION_MAX_URLS
            )
            result["race_condition_findings"] = race_results
            self._extend_dast_findings(result, "race_condition", race_results)
            if race_results:
                self.log.success(f"Race Condition: {len(race_results)} potential race conditions found!")

        # ── Step 19: BOLA/IDOR Engine (V1.0 NEW — requires bola_engine flag + 2 tokens) ──
        bola_plugin = PluginRegistry.get("BOLAEngine")
        if bola_plugin and bola_plugin.check_installed() and self.bola_engine and self.auth_userA and self.auth_userB:
            bola_targets = api_like_urls[:_Cfg.BOLA_MAX_ENDPOINTS] if api_like_urls else live_urls[:20]
            self.log.info(f"BOLA Engine cross-testing {len(bola_targets)} endpoints with 2 user tokens...")
            bola_dir = os.path.join(self.raw, "bola")
            bola_results = await loop.run_in_executor(
                None, bola_plugin.run, bola_targets, bola_dir,
                self.auth_userA, self.auth_userB,
                _Cfg.BOLA_TIMEOUT, _Cfg.BOLA_MAX_ENDPOINTS
            )
            result["bola_findings"] = bola_results
            self._extend_dast_findings(result, "bola", bola_results)
            high_bola = len(bola_results.get("high_confidence_bola", []))
            if high_bola:
                self.log.success(f"BOLA Engine: {high_bola} CRITICAL BOLA/IDOR findings!")
        elif bola_plugin and not self.bola_engine:
            self.log.info("[BOLA] Skipped — enable via --bola-engine flag or Tactical Menu.")
        elif bola_plugin and not self.auth_userA:
            self.log.info("[BOLA] Skipped — need --auth-userA and --auth-userB arguments.")

        # ── Step 20: Nuclei — Targeted Bounty Templates (enhanced) ──
        nuclei_plugin = PluginRegistry.get("Nuclei")
        if nuclei_plugin and nuclei_plugin.check_installed():
            self.log.info("Nuclei scanning with bounty-critical templates + OAST...")
            nuclei_dir = os.path.join(self.raw, "nuclei_bounty")
            bounty_tags = ["misconfig", "default-login", "exposure", "takeover",
                           "cors", "token", "cve", "ssrf", "redirect", "oast",
                           "xss", "lfi", "rfi", "crlf", "sqli"]
            nuclei_targets = list(live_urls)
            if param_urls:
                nuclei_targets.extend(param_urls[:30])
                nuclei_targets = URLDeduplicator.deduplicate(nuclei_targets)
            
            extra_flags = []
            if self.delay: extra_flags.extend(["-delay", self.delay])
            nuclei_strategy = self._strategy_profile(
                "nuclei", "api-bounty", waf_detected=waf_detected,
                parameterized_count=len(param_urls or []),
            )
            from core.plugin_strategy import merge_nuclei_tags
            bounty_tags = merge_nuclei_tags(bounty_tags, nuclei_strategy)
            
            noise_stop = asyncio.Event()
            noise_task = asyncio.create_task(self._send_behavioral_noise(noise_stop, f"https://{target}"))
            #  Nuclei với CHUNKING
            self.log.info("Nuclei full batch scan with CHUNKING...")
            
            async def _scan_nuclei_chunk_bounty(chunk_targets):
                return await loop.run_in_executor(
                    None,
                    lambda: nuclei_plugin.run_batch(
                        chunk_targets, nuclei_dir,
                        bounty_tags, None, None, self.rate_limit, None,
                        extra_flags, self._get_auth_headers() or {}, self.proxy_file,
                        proxy_mode=nuclei_strategy.get("proxy_mode", "fuzz"),
                    )
                )

            chunked_results = await self.run_in_chunks(
                f"nuclei_api_bounty_{target}", nuclei_targets, self.chunk_size, _scan_nuclei_chunk_bounty
            )
            result["nuclei_findings"] = chunked_results
            self.log.success(f"Nuclei found {len(result['nuclei_findings'])} total findings.")

        result = self._finalize_scan_contracts(result, target, "api-bounty", waf_detected=waf_detected)

        # ── Step 21: Generate Handoff Reports + Attack Surface Report ──
        await self._generate_bounty_reports(result, target)

        #  Coverage Summary
        _executed_steps = sum([
            1 if result.get("web_urls") else 0,          # httpx
            1 if result.get("api_endpoints") else 0,     # katana/kiterunner
            1 if result.get("hidden_params") else 0,     # arjun
            1 if self._get_dast_findings(result, "xss") else 0,      # dalfox
            1 if self._get_dast_findings(result, "sqli") else 0,     # sqlmap
            1 if self._get_dast_findings(result, "ssrf") else 0,     # ssrf_probe
            1 if self._get_dast_findings(result, "cors") else 0,       # corsy
            1 if result.get("nuclei_findings") else 0,   # nuclei
            1 if self._get_dast_findings(result, "open_redirect") else 0,
            1 if self._get_dast_findings(result, "crlf") else 0,
            1 if result.get("secrets", result.get("js_secrets")) else 0,
            1 if self._get_dast_findings(result, "bypass_403") else 0,
            1 if self._get_dast_findings(result, "graphql") else 0,
            1 if self._get_dast_findings(result, "bola") else 0,
            1 if self._get_dast_findings(result, "race_condition") else 0,
            1 if result.get("wpscan") else 0,
            1 if self._get_dast_findings(result, "blind_xss") else 0,
            1 if self._get_dast_findings(result, "cache_poisoning") else 0,
        ])
        self.log.phase(f"📊 API-BOUNTY COVERAGE: {_executed_steps}/{_steps_total} steps produced findings")
        self.log.info(f"  🔍 Nuclei: {len(result.get('nuclei_findings', []))} findings")
        self.log.info(f"  🕷️  XSS: {len(self._get_dast_findings(result, 'xss'))}")
        self.log.info(f"  💉 SQLi: {len(self._get_dast_findings(result, 'sqli'))}")
        self.log.info(f"  🌐 SSRF: {len(self._get_dast_findings(result, 'ssrf'))}")
        self.log.info(f"  🔗 CORS: {len(self._get_dast_findings(result, 'cors'))}")
        self.log.info(f"  📡 API Endpoints: {len(result.get('api_endpoints', []))}")
        self.log.info(f"  🔑 JS Secrets: {len(result.get('secrets', result.get('js_secrets', [])))}")

        return result

    async def _generate_bounty_reports(self, result: dict, target: str):
        """Sinh file handoff cho manual testing (Burp Suite) + Attack Surface Report."""
        from datetime import datetime
        
        # ── potential_logic_bugs.txt ──
        bugs_path = os.path.join(self.out_dir, "potential_logic_bugs.txt")
        try:
            with open(bugs_path, 'w') as f:
                f.write(f"# PenLabs V1.0 — Potential Logic Bugs Report\n")
                f.write(f"# Target: {target}\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write("=" * 70 + "\n\n")
                
                # IDOR/BOLA candidates (endpoints với hidden params kiểu id)
                for url, params in result.get("hidden_params", {}).items():
                    idor_params = [p for p in params if any(kw in p.lower() for kw in ["id", "uid", "user", "account", "order"])]
                    if idor_params:
                        f.write(f"[IDOR CANDIDATE] {url} → Params: {', '.join(idor_params)}\n")
                    role_params = [p for p in params if any(kw in p.lower() for kw in ["role", "admin", "is_admin", "privilege", "type"])]
                    if role_params:
                        f.write(f"[MASS ASSIGNMENT] {url} → Hidden params: {', '.join(role_params)}\n")
                
                # GraphQL
                gql = result.get("graphql", {})
                for finding in self._get_dast_findings(result, "graphql"):
                    f.write(f"[GRAPHQL] {finding.get('url', '')} → {finding.get('evidence', finding.get('title', 'GraphQL finding'))}\n")
                for mut in gql.get("mutations", []):
                    f.write(f"[GRAPHQL MUTATION] {mut['endpoint']} → {mut['type']}.{mut['field']}({', '.join(mut.get('args', []))})\n")
                
                # 403 Bypass
                for finding in self._get_dast_findings(result, "bypass_403"):
                    raw = finding.get("raw", {})
                    f.write(f"[403 BYPASS] {finding['url']} → {raw.get('bypass_method', finding.get('evidence', ''))} (status: {raw.get('status', '?')})\n")
                
                # Cache Poisoning
                for finding in self._get_dast_findings(result, "cache_poisoning"):
                    raw = finding.get("raw", {})
                    f.write(f"[CACHE POISON] {finding['url']} → {raw.get('unkeyed_header', '?')} reflected (cache: {raw.get('cache_status', 'unknown')})\n")

                # Mass Assignment
                for finding in self._get_dast_findings(result, "mass_assignment"):
                    f.write(f"[MASS ASSIGNMENT] {finding['url']} → {finding.get('evidence', '')} [{finding.get('severity', 'medium').upper()}]\n")
                
                # CORS
                for finding in self._get_dast_findings(result, "cors"):
                    f.write(f"[CORS] {finding['url']} → {finding.get('finding_type', finding.get('title', 'cors'))} [{finding['severity'].upper()}]\n")
                
                # XSS
                for finding in self._get_dast_findings(result, "xss"):
                    f.write(f"[XSS] {finding['url']} → param: {finding.get('param', '?')} [{finding.get('finding_type', 'xss')}]\n")
                
                # V1.0: SSRF
                for finding in self._get_dast_findings(result, "ssrf"):
                    f.write(f"[SSRF] {finding['url']} → param: {finding.get('param', '?')} | payload: {finding.get('payload', '')} [{finding.get('severity', 'HIGH').upper()}]\n")

                # V1.0: Blind XSS
                blind_xss_findings = self._get_dast_findings(result, "blind_xss")
                if blind_xss_findings:
                    f.write(f"\n[BLIND XSS] {len(blind_xss_findings)} injection events recorded — check Interactsh for callbacks.\n")

                # V1.0: Open Redirect
                for finding in self._get_dast_findings(result, "open_redirect"):
                    chain = finding.get("raw", {}).get("chain_potential", "LOW")
                    f.write(f"[OPEN REDIRECT] {finding['url']} → param: {finding.get('param', '?')} | type: {finding.get('finding_type', '?')} | chain: {chain}\n")

                # V1.0: CRLF
                for finding in self._get_dast_findings(result, "crlf"):
                    f.write(f"[CRLF] {finding['url']} → {finding.get('finding_type', 'crlf_injection')} [{finding.get('severity', 'medium').upper()}]\n")

                # V1.0: Race Condition
                for finding in self._get_dast_findings(result, "race_condition"):
                    f.write(f"[RACE CONDITION] {finding['url']} → {finding.get('confidence', '?')} confidence | {finding.get('evidence', '')}\n")

                # V1.0: BOLA findings
                for finding in self._get_dast_findings(result, "bola"):
                    raw = finding.get("raw", {})
                    f.write(f"[BOLA] {raw.get('method', finding.get('method', 'GET'))} {finding.get('url', '')} → {finding.get('evidence', '')}\n")

                # SQLi
                for finding in self._get_dast_findings(result, "sqli"):
                    raw = finding.get("raw", {})
                    f.write(f"[SQLI DETECTED] {finding['url']} → param: {finding.get('param', '?')} [{finding.get('finding_type', raw.get('type', 'unknown'))}] DBMS: {raw.get('dbms', '?')}\n")
                
                # WPScan
                for finding in self._get_dast_findings(result, "wordpress"):
                    raw = finding.get("raw", {})
                    f.write(f"[WORDPRESS] {finding.get('title', '')} [{finding.get('severity', '')}] (type: {raw.get('type', finding.get('finding_type', 'wordpress'))})\n")
                
                # API endpoints (summary)
                api_eps = result.get("api_endpoints", [])
                if api_eps:
                    f.write(f"\n# API ENDPOINTS DISCOVERED ({len(api_eps)} total)\n")
                    for ep in api_eps[:50]:
                        f.write(f"  {ep.get('method', 'GET')} [{ep.get('status', '?')}] {ep.get('url', '')}\n")
                
            self.log.success(f"Generated: {bugs_path}")
        except Exception as e:
            self.log.warning(f"Failed to generate logic bugs report: {e}")
        
        # ── secrets_found.txt ──
        secrets = result.get("secrets", result.get("js_secrets", []))
        if secrets:
            secrets_path = os.path.join(self.out_dir, "secrets_found.txt")
            try:
                with open(secrets_path, 'w') as f:
                    f.write(f"# PenLabs V1.0 — Secrets Found in JavaScript\n")
                    f.write(f"# Target: {target}\n")
                    f.write("=" * 70 + "\n\n")
                    for s in secrets:
                        f.write(f"[{s['type'].upper()}] {s['value']} → Found in: {s['source']}\n")
                self.log.success(f"Generated: {secrets_path}")
            except Exception as e:
                self.log.warning(f"Failed to generate secrets report: {e}")

        # ── V1.0: attack_surface_report.md (Nhóm 3 — Manual Testing Guidance) ──
        await self._generate_attack_surface_report(result, target)

    async def _generate_web_vuln_reports(self, result: dict, target: str):
        """Generate focused handoff for web-vuln mode using canonical DAST findings."""
        from datetime import datetime

        handoff_path = os.path.join(self.out_dir, "web_vuln_handoff.md")
        try:
            with open(handoff_path, "w") as f:
                f.write(f"# PenLabs Web-Vuln Handoff\n\n")
                f.write(f"**Target:** `{target}`  \n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
                f.write(f"**Mode:** `web-vuln`  \n\n")

                summary = result.get("summary", {})
                f.write("## Summary\n\n")
                f.write("| Category | Count |\n")
                f.write("|:---------|------:|\n")
                for label, key in [
                    ("Nuclei", "nuclei_findings"),
                    ("XSS", "xss"),
                    ("CORS", "cors"),
                    ("Blind XSS", "blind_xss"),
                    ("Mass Assignment", "mass_assignment"),
                    ("Parameterized URLs", "parameterized_urls"),
                    ("VHosts", "vhosts"),
                ]:
                    f.write(f"| {label} | {summary.get(key, 0)} |\n")
                f.write("\n")

                f.write("## Manual Follow-up\n\n")
                for category, title in [
                    ("blind_xss", "Blind XSS"),
                    ("mass_assignment", "Mass Assignment"),
                    ("xss", "Reflected XSS"),
                    ("cors", "CORS Misconfiguration"),
                ]:
                    findings = self._get_dast_findings(result, category)
                    if not findings:
                        continue
                    f.write(f"### {title} ({len(findings)})\n\n")
                    for finding in findings[:25]:
                        f.write(f"- `{finding.get('url', '')}`")
                        evidence = finding.get("evidence", "")
                        if evidence:
                            f.write(f" — {evidence}")
                        f.write("\n")
                    f.write("\n")

                param_urls = result.get("web_urls_with_params", []) or []
                if param_urls:
                    f.write("## Parameterized URLs\n\n")
                    for url in param_urls[:50]:
                        f.write(f"- `{url}`\n")
                    f.write("\n")

            self.log.success(f"Generated: {handoff_path}")
        except Exception as e:
            self.log.warning(f"Failed to generate web-vuln handoff: {e}")

    async def _generate_attack_surface_report(self, result: dict, target: str):
        """Sinh Attack Surface Report chi tiết cho Nhóm 3 (manual testing)."""
        from datetime import datetime
        import re as _re
        
        report_path = os.path.join(self.out_dir, "attack_surface_report.md")
        try:
            with open(report_path, 'w') as f:
                f.write(f"# 🎯 PenLabs V1.0 — Attack Surface Report\n\n")
                f.write(f"**Target:** `{target}`  \n")
                f.write(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  \n")
                f.write(f"**Mode:** api-bounty (V1.0 Tier-1 Pipeline)  \n\n")
                f.write("---\n\n")

                # === Section 1: Business Logic Targets ===
                f.write("## 1. 💰 Business Logic Targets Matrix\n\n")
                f.write("Endpoints liên quan đến business logic cao giá trị. **Đánh tay bằng Burp Suite.**\n\n")
                f.write("| Endpoint | Keywords | Risk | Recommended Test |\n")
                f.write("|:---------|:---------|:-----|:-----------------|\n")
                
                biz_keywords = {
                    "checkout": ("CRITICAL", "Thay đổi price/quantity → giá 0"),
                    "payment": ("CRITICAL", "Double-submit race condition → trả tiền 1 lần, nhận 2 lần"),
                    "transfer": ("CRITICAL", "Thay đổi amount/recipient → chuyển sang tài khoản khác"),
                    "redeem": ("HIGH", "Race condition → sử dụng coupon nhiều lần"),
                    "coupon": ("HIGH", "Replay coupon code → unlimited discount"),
                    "upgrade": ("HIGH", "Thay đổi plan_id → downgrade billing, upgrade features"),
                    "role": ("HIGH", "Mass Assignment → is_admin=true"),
                    "permission": ("HIGH", "BOLA → truy cập quyền user khác"),
                    "invite": ("MEDIUM", "Self-invite → escalate access"),
                    "delete": ("MEDIUM", "BOLA → xóa data user khác"),
                    "archive": ("MEDIUM", "BOLA → archive/restore data user khác"),
                    "admin": ("HIGH", "Path traversal → access admin panel"),
                    "signup": ("MEDIUM", "Race condition → duplicate account creation"),
                    "login": ("MEDIUM", "Brute force → 2FA bypass"),
                }
                
                all_eps = set()
                for ep in result.get("api_endpoints", []):
                    all_eps.add(ep.get("url", ""))
                all_eps.update(result.get("web_urls", []))
                all_eps.update(result.get("web_urls_with_params", []) or [])
                
                biz_found = 0
                for ep_url in sorted(all_eps):
                    for kw, (risk, test) in biz_keywords.items():
                        if kw in ep_url.lower():
                            f.write(f"| `{ep_url[:100]}` | `{kw}` | **{risk}** | {test} |\n")
                            biz_found += 1
                            break
                
                if biz_found == 0:
                    f.write("| _(Không phát hiện endpoint business logic rõ ràng)_ | — | — | Kiểm tra thủ công |\n")
                f.write("\n")

                # === Section 2: Authentication Flow Map ===
                f.write("## 2. 🔐 Authentication Flow Map\n\n")
                
                oauth_endpoints = [url for url in all_eps if any(
                    kw in url.lower() for kw in ["oauth", "authorize", "callback", "sso", "token", "oidc", "login", "redirect_uri"]
                )]
                
                if oauth_endpoints:
                    f.write("### OAuth/SSO Endpoints Detected:\n\n")
                    for ep in sorted(set(oauth_endpoints)):
                        f.write(f"- `{ep}`\n")
                    f.write("\n### 🚨 Test Scenarios:\n")
                    f.write("1. **Open Redirect → Token Theft:** Thay `redirect_uri` bằng `https://attacker.com`\n")
                    f.write("2. **CSRF on OAuth callback:** Forge state param → Account Takeover\n")
                    f.write("3. **Token Leakage:** Kiểm tra Referer header khi redirect → token trong URL\n\n")
                else:
                    f.write("_(Không phát hiện OAuth/SSO endpoints)_\n\n")

                # === Section 3: Race Condition Hotspots ===
                f.write("## 3. ⚡ Race Condition Hotspots\n\n")
                
                race_findings = self._get_dast_findings(result, "race_condition")
                if race_findings:
                    f.write("| Endpoint | Confidence | Evidence |\n")
                    f.write("|:---------|:-----------|:---------|\n")
                    for rc in race_findings:
                        f.write(f"| `{rc['url'][:100]}` | **{rc.get('confidence', '')}** | {rc.get('evidence', '')[:100]} |\n")
                else:
                    f.write("_(Race condition automated testing không phát hiện bất thường. Kiểm tra thủ công với Burp Turbo Intruder các POST endpoints.)_\n")
                f.write("\n")

                # === Section 4: BOLA/IDOR Candidate Endpoints ===
                f.write("## 4. 🆔 BOLA/IDOR Candidate Endpoints\n\n")
                
                bola_findings = self._get_dast_findings(result, "bola")
                high_bola = [finding for finding in bola_findings if finding.get("severity") == "critical"]
                if high_bola:
                    f.write("### 🔴 HIGH CONFIDENCE (Auto-detected):\n\n")
                    for b in high_bola:
                        raw = b.get("raw", {})
                        f.write(f"- **{raw.get('method', b.get('method', 'GET'))} `{b.get('url', '')}`** — {b.get('evidence', '')}\n")
                    f.write("\n")

                # Tìm endpoints có ID trong path
                id_pattern = _re.compile(r'/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)')
                idor_candidates = [url for url in all_eps if id_pattern.search(url)]
                
                if idor_candidates:
                    f.write("### 🟡 Endpoints với ID/UUID (cần test thủ công):\n\n")
                    f.write("| Endpoint | ID Found | Recommended Test |\n")
                    f.write("|:---------|:---------|:-----------------|\n")
                    for url in sorted(set(idor_candidates))[:30]:
                        ids = id_pattern.findall(url)
                        f.write(f"| `{url[:100]}` | `{ids[0] if ids else '?'}` | Thay ID bằng ID user khác → check 200 OK |\n")
                    f.write("\n")
                else:
                    f.write("_(Không phát hiện endpoints có ID/UUID trong path. Kiểm tra JSON responses.)_\n\n")

                # === Section 5: Bug Chaining Opportunities ===
                f.write("## 5. 🔗 Bug Chaining Opportunities\n\n")
                
                has_open_redirect = bool(self._get_dast_findings(result, "open_redirect"))
                has_cors = bool(self._get_dast_findings(result, "cors"))
                has_xss = bool(self._get_dast_findings(result, "xss"))
                has_blind_xss = bool(self._get_dast_findings(result, "blind_xss"))
                has_ssrf = bool(self._get_dast_findings(result, "ssrf"))
                has_crlf = bool(self._get_dast_findings(result, "crlf"))
                has_cache_poisoning = bool(self._get_dast_findings(result, "cache_poisoning"))
                
                chains = []
                if has_open_redirect and oauth_endpoints:
                    chains.append("- **Open Redirect + OAuth** → SSO Token theft (redirect_uri manipulation) → Account Takeover 💰")
                if has_cors and has_xss:
                    chains.append("- **CORS Wildcard + XSS** → Cross-Origin data theft → Full API takeover 💰")
                if has_ssrf:
                    chains.append("- **SSRF + Cloud Metadata** → AWS/GCP credential theft → Infrastructure takeover 💰💰")
                if has_crlf and has_cache_poisoning:
                    chains.append("- **CRLF + Cache Poisoning** → Stored response splitting → Mass XSS on CDN 💰")
                if has_xss and oauth_endpoints:
                    chains.append("- **XSS + OAuth flow** → Steal authorization code → Account Takeover 💰")
                if has_blind_xss:
                    chains.append("- **Blind XSS + Admin workflow** → Session theft from privileged reviewer → Account/Panel takeover 💰")
                if has_open_redirect:
                    chains.append("- **Open Redirect + Phishing** → Credential harvest via trusted domain 💰")
                
                if chains:
                    for chain in chains:
                        f.write(f"{chain}\n")
                else:
                    f.write("_(Không phát hiện chain rõ ràng. Xem xét manual combo testing.)_\n")
                f.write("\n")

                # === Section 6: Summary Stats ===
                f.write("## 6. 📊 Scan Statistics\n\n")
                f.write("| Category | Count | Severity |\n")
                f.write("|:---------|:------|:---------|\n")
                stats = [
                    ("SSRF", len(self._get_dast_findings(result, "ssrf")), "CRITICAL"),
                    ("SQL Injection", len(self._get_dast_findings(result, "sqli")), "CRITICAL"),
                    ("XSS (Reflected)", len(self._get_dast_findings(result, "xss")), "HIGH"),
                    ("Blind XSS Injected", len(self._get_dast_findings(result, "blind_xss")), "HIGH"),
                    ("Mass Assignment", len(self._get_dast_findings(result, "mass_assignment")), "HIGH"),
                    ("Open Redirect", len(self._get_dast_findings(result, "open_redirect")), "MEDIUM"),
                    ("CRLF Injection", len(self._get_dast_findings(result, "crlf")), "MEDIUM"),
                    ("CORS Misconfiguration", len(self._get_dast_findings(result, "cors")), "MEDIUM"),
                    ("403 Bypass", len(self._get_dast_findings(result, "bypass_403")), "MEDIUM"),
                    ("Cache Poisoning", len(self._get_dast_findings(result, "cache_poisoning")), "MEDIUM"),
                    ("Race Condition", len(self._get_dast_findings(result, "race_condition")), "HIGH"),
                    ("BOLA/IDOR (High)", len([finding for finding in self._get_dast_findings(result, "bola") if finding.get("severity") == "critical"]), "CRITICAL"),
                    ("WordPress", len(self._get_dast_findings(result, "wordpress")), "VARIES"),
                    ("API Endpoints", len(result.get("api_endpoints", [])), "INFO"),
                    ("JS Secrets", len(result.get("secrets", result.get("js_secrets", []))), "HIGH"),
                    ("Nuclei Findings", len(result.get("nuclei_findings", [])), "VARIES"),
                ]
                for name, count, sev in stats:
                    if count > 0:
                        f.write(f"| **{name}** | **{count}** | {sev} |\n")
                    else:
                        f.write(f"| {name} | {count} | {sev} |\n")
                f.write("\n---\n")
                f.write(f"\n*Generated by PenLabs V1.0 Tier-1 Bug Bounty Pipeline*\n")

            self.log.success(f"Generated Attack Surface Report: {report_path}")
        except Exception as e:
            self.log.warning(f"Failed to generate attack surface report: {e}")


    async def _run_gowitness(self, urls: list, out_dir: str) -> str:
        """
         Screenshot tất cả URLs bằng gowitness.
        Returns: đường dẫn thư mục chứa screenshots.
        """
        if not shutil.which("gowitness"):
            self.log.warning("[gowitness] Not installed. Đang tự động cài đặt...")
            try:
                subprocess.run(["go", "install", "github.com/sensepost/gowitness@latest"], check=True)
                os.environ["PATH"] += os.pathsep + os.path.expanduser("~/go/bin")
            except Exception as e:
                self.log.error(f"Failed to auto-install gowitness: {e}")
            if not shutil.which("gowitness"):
                self.log.warning("[gowitness] Not installed after auto-install. Skipping screenshots.")
                return ""

        screenshots_dir = os.path.join(out_dir, "screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)

        # Ghi URLs vào file input
        input_file = os.path.join(out_dir, "gowitness_urls.txt")
        with open(input_file, 'w') as f:
            f.write("\n".join(urls))

        try:
            proc = await asyncio.create_subprocess_exec(
                "gowitness", "scan", "file", "-f", input_file,
                "--screenshot-path", screenshots_dir,
                "--timeout", "10",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=120)
            # Count screenshots
            screenshots = [f for f in os.listdir(screenshots_dir) if f.endswith(".png")]
            self.log.success(f"[gowitness] Captured {len(screenshots)} screenshots → {screenshots_dir}")
        except Exception as e:
            self.log.warning(f"[gowitness] Failed: {e}")

        return screenshots_dir

    async def _run_dnsx(self, domain: str, out_dir: str) -> dict:
        """
         DNS enumeration bằng dnsx — A, AAAA, CNAME, MX, NS, TXT, SOA.
        """
        result = {"a": [], "aaaa": [], "cname": [], "mx": [], "ns": [], "txt": []}
        if not shutil.which("dnsx"):
            self.log.warning("[dnsx] Not installed. Skipping DNS enum.")
            return result

        os.makedirs(out_dir, exist_ok=True)
        dnsx_output = os.path.join(out_dir, "dnsx_output.jsonl")

        try:
            proc = await asyncio.create_subprocess_exec(
                "dnsx", "-json", "-output", dnsx_output,
                "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-resp", "-silent",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            proc.stdin.write(f"{domain}\n".encode())
            await proc.stdin.drain()
            proc.stdin.close()
            await asyncio.wait_for(proc.wait(), timeout=60)

            if os.path.exists(dnsx_output):
                with open(dnsx_output, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            data = json.loads(line)
                            for key in result:
                                if key in data:
                                    val = data[key]
                                    if isinstance(val, list):
                                        result[key].extend(val)
                                    elif val:
                                        result[key].append(str(val))
                        except json.JSONDecodeError:
                            continue

            total = sum(len(v) for v in result.values())
            if total:
                self.log.success(f"[dnsx] Found {total} DNS records for {domain}")
        except Exception as e:
            self.log.warning(f"[dnsx] Failed: {e}")

        return result

    async def _run_vhost_discovery(self, ip: str, target: str, out_dir: str) -> list:
        """
         Virtual Host discovery bằng ffuf Host header brute-force.
        Phát hiện web apps ẩn chạy trên cùng IP nhưng khác vHost.
        """
        vhosts = []
        if not shutil.which("ffuf"):
            self.log.warning("[VHost] ffuf not installed. Skipping vhost discovery.")
            return vhosts

        os.makedirs(out_dir, exist_ok=True)
        ffuf_output = os.path.join(out_dir, "vhost_results.json")

        # Build wordlist từ domain parts
        import tldextract
        ext = tldextract.extract(target)
        base = ext.domain if ext.domain else target
        vhost_names = [
            f"admin.{target}", f"api.{target}", f"dev.{target}", f"staging.{target}",
            f"test.{target}", f"mail.{target}", f"vpn.{target}", f"portal.{target}",
            f"internal.{target}", f"intranet.{target}", f"dashboard.{target}",
            f"cms.{target}", f"app.{target}", f"beta.{target}", f"demo.{target}",
            f"blog.{target}", f"docs.{target}", f"wiki.{target}", f"git.{target}",
            f"jenkins.{target}", f"grafana.{target}", f"monitor.{target}",
            f"status.{target}", f"cdn.{target}", f"static.{target}",
        ]

        vhost_wordlist = os.path.join(out_dir, "vhost_wordlist.txt")
        with open(vhost_wordlist, 'w') as f:
            f.write("\n".join(vhost_names))

        try:
            cmd = [
                "ffuf",
                "-u", f"http://{ip}",
                "-w", vhost_wordlist,
                "-H", "Host: FUZZ",
                "-o", ffuf_output,
                "-of", "json",
                "-mc", "200,301,302,401,403",
                "-fs", "0",  # Filter empty responses
                "-s"
            ]
            if getattr(self, 'stealth_recon', False):
                cmd.extend(["-t", "3", "-p", "0.5-2.0"])
            else:
                cmd.extend(["-t", "10"])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.wait(), timeout=60)
            except asyncio.TimeoutError:
                self.log.warning("[VHost] ffuf timed out after 60s.")
                try: proc.kill()
                except Exception: pass

            if os.path.exists(ffuf_output):
                with open(ffuf_output, 'r') as f:
                    data = json.load(f)
                    for r in data.get("results", []):
                        vhost = r.get("input", {}).get("FUZZ", "")
                        status = r.get("status", 0)
                        length = r.get("length", 0)
                        if vhost:
                            vhosts.append({
                                "vhost": vhost,
                                "status_code": status,
                                "content_length": length,
                                "url": f"http://{vhost}",
                            })

            if vhosts:
                # [HIGH-02 FIX] Detect Wildcard DNS
                # Nếu phần lớn (>60%) vhost trả về cùng status code và content_length xấp xỉ nhau
                # Khả năng cao mục tiêu catch-all / wildcard DNS
                status_counts = {}
                length_groups = {}
                for v in vhosts:
                    status_counts[v['status_code']] = status_counts.get(v['status_code'], 0) + 1
                    # Nhóm length chênh lệch +-10 bytes
                    group_len = (v['content_length'] // 10) * 10
                    length_groups[group_len] = length_groups.get(group_len, 0) + 1
                
                total_v = len(vhosts)
                is_wildcard = False
                if total_v >= 5:
                    max_status = max(status_counts.values())
                    max_length = max(length_groups.values())
                    if max_status >= (total_v * 0.6) and max_length >= (total_v * 0.6):
                        is_wildcard = True

                if is_wildcard:
                    self.log.warning(f"[VHost] Wildcard DNS detected! (ignored {total_v} false positives)")
                    vhosts = [] # Clear giả mạo
                else:
                    self.log.success(f"[VHost] Discovered {len(vhosts)} virtual hosts!")
                    for v in vhosts:
                        self.log.info(f"  → {v['vhost']} (HTTP {v['status_code']}, {v['content_length']}B)")
        except Exception as e:
            self.log.warning(f"[VHost] Discovery failed: {e}")

        return vhosts

    async def _run_katana_auth(self, url: str, out_dir: str, cookies: str = "",
                               headers: dict = None) -> dict:
        """
         Katana headless crawl với authentication (cookie/header).
        Cho phép crawl post-login attack surface.
        """
        katana_plugin = PluginRegistry.get("Katana")
        if not katana_plugin or not katana_plugin.check_installed():
            return {"urls": [], "js_files": [], "endpoints": [], "forms": []}

        extra_flags = []
        if cookies:
            extra_flags.extend(["-H", f"Cookie: {cookies}"])
        if headers:
            for k, v in headers.items():
                extra_flags.extend(["-H", f"{k}: {v}"])
        extra_flags.extend(self._ja3_tool_args("katana"))

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None,
            partial(self._run_katana, katana_plugin, url, out_dir, depth=3, js_crawl=True, headless=True, extra_flags=extra_flags, proxy_mode="fuzz"),
        )

    async def _run_rustscan(self, ip: str) -> list:
        """Chạy RustScan quét toàn bộ 65535 ports."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "rustscan", "-a", ip, "-r", "1-65535", "--ulimit", "5000", "-g",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                env=self._subprocess_env(),
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
            output = stdout.decode('utf-8', errors='ignore').strip()

            # RustScan output format: ip -> [port1, port2, ...]
            ports = []
            import re
            port_matches = re.findall(r'(\d+)/(?:tcp|udp)', output)
            if port_matches:
                ports = [int(p) for p in port_matches]
            else:
                # Alternative: parse "ip -> [80,443,...]" format
                bracket_match = re.search(r'\[([^\]]+)\]', output)
                if bracket_match:
                    ports = [int(p.strip()) for p in bracket_match.group(1).split(',') if p.strip().isdigit()]

            return ports
        except Exception as e:
            logging.warning(f"[RustScan] Failed: {e}")
            return []
