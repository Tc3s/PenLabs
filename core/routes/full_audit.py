#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Full Audit Route Handler
===================================
Nuke Mode (All Ports → Nmap → Nuclei + UDP).
"""

import asyncio
import os
import shutil
from functools import partial

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry
from core.performance import unique_http_urls_by_host
from utils.url_dedup import URLDeduplicator


class FullAuditRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("FULL-AUDIT MODE — Nuke Mode (All Ports → Nmap → Nuclei + UDP)")
        result = {"ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [], "cloud_findings": {}, "os_detection": [], "screenshots_dir": "", "dns_records": {}, "vhosts": []}
        loop = asyncio.get_running_loop()

        # Step 1: RustScan hoặc Naabu — Quét toàn bộ 65535 TCP ports
        all_open_ports = []
        if shutil.which("rustscan"):
            self.log.info("RustScan scanning all 65535 ports...")
            all_open_ports = await self._run_rustscan(ip)
            self.log.success(f"RustScan found {len(all_open_ports)} open ports.")
        else:
            naabu_plugin = PluginRegistry.get("Naabu")
            if naabu_plugin and naabu_plugin.check_installed():
                self.log.info("Naabu scanning all 65535 ports...")
                naabu_dir = os.path.join(self.raw, "naabu_fullscan")
                all_open_ports = await loop.run_in_executor(
                    self._plugin_executor, naabu_plugin.get_open_ports, ip, None,
                )
                if not all_open_ports:
                    all_results = await loop.run_in_executor(
                        self._plugin_executor, naabu_plugin.run, ip, None, "", True, 5000, naabu_dir
                    )
                    all_open_ports = [r["port"] for r in all_results]
                self.log.success(f"Naabu found {len(all_open_ports)} open ports.")
            else:
                self.log.warning("Neither RustScan nor Naabu available. Using Nmap top-500 fallback.")

        # Step 1b: UDP scan
        self.log.info("Nmap UDP scan (top 20 critical services)...")
        udp_ports = await self._scan_udp_top20(ip)
        if udp_ports:
            result["ports"].extend(udp_ports)
            self.log.success(f"UDP scan found {len(udp_ports)} open UDP services.")

        # Step 2: Nmap Full NSE
        nmap_plugin = PluginRegistry.get("Nmap")
        if nmap_plugin:
            ports_to_scan = all_open_ports if all_open_ports else []
            self.log.info(f"Nmap full-audit NSE on {len(ports_to_scan) if ports_to_scan else 'top-500'} ports...")
            nmap_data = await loop.run_in_executor(
                self._plugin_executor,
                partial(
                    nmap_plugin.run, ip, self.out_dir, index, "full-audit", ports_to_scan,
                    strategy_profile=self._strategy_profile("nmap", "full-audit"),
                ),
            )
            result["ports"].extend(nmap_data.get("ports", []))
            result["nse_cves"] = nmap_data.get("nse_cves", [])
            result["os_detection"] = nmap_data.get("os_detection", [])
            self.log.success(f"Nmap found {len(nmap_data.get('ports', []))} services, {len(result['nse_cves'])} NSE CVEs.")

        # Step 3: httpx probe → Nuclei batch scan
        web_ports = [p["port"] for p in result.get("ports", [])
                     if p.get("service") in ["http", "ssl/http", "https", "http-proxy"] or
                     p.get("port") in [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090]]
        web_ports = list(set(web_ports))
        scan_urls = []
        if web_ports:
            httpx_plugin = PluginRegistry.get("Httpx")
            if httpx_plugin and httpx_plugin.check_installed():
                self.log.info(f"httpx probing {len(web_ports[:100])} web ports...")
                httpx_dir = os.path.join(self.raw, "httpx_fullaudit")
                httpx_results = await loop.run_in_executor(
                    self._plugin_executor, httpx_plugin.probe_from_ports, ip, web_ports[:100], httpx_dir, self._get_auth_headers(), self.proxy_file
                )
                scan_urls = [r["url"] for r in httpx_results if r.get("url")]
                for r in httpx_results:
                    for p in result["ports"]:
                        if p["port"] == r.get("port"):
                            p["tech"] = r.get("tech", [])
                            p["title"] = r.get("title", "")
                            
            if not scan_urls:
                for port in web_ports[:100]:
                    scheme = "https" if port in [443, 8443] else "http"
                    base_url = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
                    scan_urls.append(base_url)

        # Step 3b: Playwright SPA Discovery
        if self.use_playwright:
            playwright_plugin = PluginRegistry.get("Playwright")
            if playwright_plugin:
                self.log.info(f"Playwright SPA discovery on {min(len(scan_urls), 5)} URLs...")
                try:
                    pw_results = await playwright_plugin.run(
                        scan_urls[:5], self.raw, timeout=30, 
                        headers=self._get_auth_headers(), proxy=self.proxy_file
                    )
                    if pw_results.get("endpoints"):
                        self.log.success(f"Playwright discovered {len(pw_results['endpoints'])} hidden API endpoints.")
                        scan_urls.extend(pw_results["endpoints"])
                        scan_urls = list(set(scan_urls))
                except Exception as e:
                    self.log.warning(f"Playwright failed: {e}")

        # Step 3c: Katana web crawl
        katana_plugin = PluginRegistry.get("Katana")
        crawled_param_urls = []
        if katana_plugin and katana_plugin.check_installed() and scan_urls:
            from config import Config as _CfgFA
            katana_limit = _CfgFA.KATANA_MAX_URLS.get("full-audit", 50)
            self.log.info(f"Katana JS-aware crawling {min(len(scan_urls), katana_limit)} web URLs...")
            raw_crawled = []
            for crawl_data in await self._run_katana_many(
                katana_plugin,
                scan_urls,
                "full_audit",
                limit=katana_limit,
                depth=3,
                js_crawl=True,
                headless=False,
                proxy_mode="fuzz",
            ):
                self._append_crawl_output(crawl_data, raw_crawled)
            if raw_crawled:
                base_urls, param_urls = URLDeduplicator.deduplicate_with_params(raw_crawled)
                crawled_param_urls = param_urls
                result["web_urls"] = list(set(scan_urls + base_urls))
                self.log.success(f"Katana: {len(base_urls)} base + {len(param_urls)} parameterized URLs.")
            else:
                result["web_urls"] = scan_urls

        # Nuclei batch scan
        nuclei_plugin = PluginRegistry.get("Nuclei")
        if nuclei_plugin and nuclei_plugin.check_installed() and scan_urls:
            nuclei_targets = list(scan_urls)
            if crawled_param_urls:
                nuclei_targets.extend(crawled_param_urls[:50])
                nuclei_targets = URLDeduplicator.deduplicate(nuclei_targets)

            self.log.info("Nuclei full batch scan with CHUNKING...")
            nuclei_dir = os.path.join(self.raw, "nuclei_full")
            
            async def _scan_nuclei_chunk(chunk_targets):
                return await self._nuclei_batch_with_retry(
                    chunk_targets, nuclei_dir, severity=["critical", "high", "medium"], 
                    mode="full-audit", headers=self._get_auth_headers()
                )

            chunked_results = await self.run_in_chunks(
                f"nuclei_full_audit_{target}", nuclei_targets, self.chunk_size, _scan_nuclei_chunk
            )
            result["nuclei_findings"] = chunked_results
            self.log.success(f"Nuclei found {len(result['nuclei_findings'])} total vulnerabilities.")

        # Step 3c: ffuf directory fuzzing
        if shutil.which("ffuf") and scan_urls:
            ffuf_targets = unique_http_urls_by_host(scan_urls, limit=self._ffuf_runtime_options()["targets"])
            self.log.info(f"ffuf directory fuzzing on {len(ffuf_targets)} unique hosts...")
            ffuf_results = await self._run_ffuf_many(
                ffuf_targets,
                os.path.join(self.raw, "ffuf_full"),
                headers=self._get_auth_headers(),
                purpose="web_content",
            )
            result["web_urls"].extend(ffuf_results)

        # Step 4: gowitness, dnsx, vhost
        if scan_urls:
            screenshots_dir = os.path.join(self.raw, "gowitness_full")
            async with self._heavy_task_semaphore:
                result["screenshots_dir"] = await self._run_gowitness(scan_urls, screenshots_dir)

        dns_dir = os.path.join(self.raw, "dns_full")
        result["dns_records"] = await self._run_dnsx(target, dns_dir)

        vhost_dir = os.path.join(self.raw, "vhost_full")
        result["vhosts"] = await self._run_vhost_discovery(ip, target, vhost_dir)

        return result
