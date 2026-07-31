#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — API Breach Route Handler
===================================
Origin Bypass → Parameter Fuzz → CVE Hunt.
"""

import asyncio
import json
import os
import shutil

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry
from utils.url_dedup import URLDeduplicator


class APIBreachRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("API-BREACH MODE — Origin Bypass → Parameter Fuzz → CVE Hunt")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [],
            "api_endpoints": [], "hidden_params": {}, "js_secrets": [],
            "xss_findings": [], "sqli_findings": [], "ssrf_findings": [],
        }
        loop = asyncio.get_running_loop()

        # Step 1: Httpx probe — Tìm live HTTP services trên target
        httpx_plugin = PluginRegistry.get("Httpx")
        live_urls = []
        web_ports = osint_ports if osint_ports else [80, 443, 8080, 8443, 3000, 5000, 8000, 9090]
        if httpx_plugin and httpx_plugin.check_installed():
            self.log.info(f"Httpx probing {len(web_ports)} ports trên {ip or target}...")
            httpx_dir = os.path.join(self.raw, "httpx_api_breach")
            httpx_results = await loop.run_in_executor(
                self._plugin_executor, httpx_plugin.probe_from_ports, ip or target, web_ports, httpx_dir,
                self._get_auth_headers(), None, None,
                "recon"
            )
            live_urls = [r["url"] for r in httpx_results if r.get("url")]
            for r in httpx_results:
                result["ports"].append({
                    "port": r.get("port", 80), "service": "http",
                    "version": r.get("web_server", ""), "tech": r.get("tech", []),
                    "title": r.get("title", ""),
                })
            self.log.success(f"Httpx found {len(live_urls)} live HTTP services.")
        else:
            for port in web_ports:
                scheme = "https" if port in [443, 8443] else "http"
                base_url = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
                live_urls.append(base_url)

        if not live_urls:
            self.log.warning("No live HTTP services found.")
            return result
        result["web_urls"] = live_urls

        # Step 2: Katana — Crawl API endpoints + JS analysis
        katana_plugin = PluginRegistry.get("Katana")
        if katana_plugin and katana_plugin.check_installed():
            self.log.info(f"Katana crawling {min(len(live_urls), 20)} URLs for API endpoints...")
            raw_crawled = []
            for crawl_data in await self._run_katana_many(
                katana_plugin,
                live_urls,
                "api_breach",
                limit=20,
                depth=3,
                js_crawl=True,
                headless=False,
                proxy_mode="recon",
            ):
                self._append_crawl_output(crawl_data, raw_crawled, js_secrets=result["js_secrets"])
            if raw_crawled:
                _, param_urls = URLDeduplicator.deduplicate_with_params(raw_crawled)
                result["web_urls_with_params"] = param_urls
                self.log.success(f"Katana discovered {len(param_urls)} parameterized API endpoints.")

        # Step 3: Arjun — Hidden Parameter Discovery
        arjun_plugin = PluginRegistry.get("Arjun")
        if arjun_plugin and arjun_plugin.check_installed():
            self.log.info(f"Arjun fuzzing hidden parameters trên {min(len(live_urls), 15)} URLs...")
            arjun_dir = os.path.join(self.raw, "arjun_api_breach")
            os.makedirs(arjun_dir, exist_ok=True)
            for url in live_urls[:15]:
                try:
                    arjun_result = await loop.run_in_executor(self._plugin_executor, arjun_plugin.run, [url], arjun_dir)
                    params = arjun_result.get(url, []) or next(iter(arjun_result.values()), [])
                    if params:
                        result["hidden_params"][url] = params
                        self.log.success(f"  Arjun [{url}]: {len(params)} hidden params → {', '.join(params[:5])}")
                except Exception as e:
                    self.log.warning(f"  Arjun [{url}]: {e}")
        elif shutil.which("arjun"):
            self.log.info("Arjun (CLI) fuzzing hidden parameters...")
            arjun_dir = os.path.join(self.raw, "arjun_api_breach")
            os.makedirs(arjun_dir, exist_ok=True)
            for url in live_urls[:15]:
                try:
                    arjun_out = os.path.join(arjun_dir, f"arjun_{url.replace('/', '_').replace(':', '_')}.json")
                    proc = await asyncio.create_subprocess_exec(
                        "arjun", "-u", url, "-oJ", arjun_out, "-t", "5",
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=120)
                    if os.path.exists(arjun_out):
                        with open(arjun_out, "r") as _af:
                            arjun_data = json.load(_af)
                            for arj_url, arj_params in arjun_data.items():
                                if arj_params:
                                    result["hidden_params"][arj_url] = arj_params
                                    self.log.success(f"  Arjun [{arj_url}]: {len(arj_params)} hidden params")
                except Exception as e:
                    self.log.warning(f"  Arjun CLI [{url}]: {e}")

        # Step 4: Nuclei — CVE + OSINT + Misconfig scan
        nuclei_targets = list(live_urls)
        param_extras = result.get("web_urls_with_params", [])
        if param_extras:
            nuclei_targets.extend(param_extras[:50])
            nuclei_targets = URLDeduplicator.deduplicate(nuclei_targets)

        self.log.info(f"Nuclei scanning {len(nuclei_targets)} targets (tags: cves,osint,misconfig,api,injection)...")
        nuclei_dir = os.path.join(self.raw, "nuclei_api_breach")
        nuclei_results = await self._nuclei_batch_with_retry(
            nuclei_targets, nuclei_dir,
            tags=["cve", "osint", "misconfig", "api", "injection", "sqli", "xss",
                  "ssrf", "rce", "default-login", "exposure", "token"],
            severity=["critical", "high", "medium"],
            mode="api-breach", headers=self._get_auth_headers()
        )
        result["nuclei_findings"] = nuclei_results
        self.log.success(f"Nuclei found {len(nuclei_results)} findings.")

        return result
