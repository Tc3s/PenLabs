#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Sniper Route Handler
===============================
Precision Service Fingerprinting mode.
"""

import asyncio
import os
from functools import partial

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry


class SniperRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("SNIPER MODE — Precision Service Fingerprinting")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [], "dns_records": {}, "vhosts": []
        }
        loop = asyncio.get_running_loop()

        # Step 1: Port verification — ưu tiên Naabu, fallback Nmap
        verified_ports = []
        naabu_plugin = PluginRegistry.get("Naabu")
        if osint_ports:
            clean_ports = self._sanitize_ports(osint_ports)
            if naabu_plugin and naabu_plugin.check_installed():
                self.log.info(f"Naabu verifying {len(clean_ports)} OSINT ports...")
                try:
                    naabu_dir = os.path.join(self.raw, "naabu_sniper")
                    async with self._heavy_task_semaphore:
                        verified_ports = await loop.run_in_executor(
                            self._plugin_executor, naabu_plugin.get_open_ports, ip, clean_ports, "", False, 1000, naabu_dir
                        )
                except Exception:
                    verified_ports = []
            if not verified_ports:
                self.log.info(f"Nmap verifying {len(clean_ports)} OSINT ports...")
                try:
                    verified_ports = await self._safe_nmap_verify(ip, clean_ports, "1m", mode="sniper")
                except Exception:
                    verified_ports = []
            self.log.success(f"Verified {len(verified_ports)}/{len(clean_ports)} ports alive.")
        else:
            self.log.warning("No OSINT ports. Running Naabu/Nmap top-1000 discovery...")
            if naabu_plugin and naabu_plugin.check_installed():
                try:
                    naabu_dir = os.path.join(self.raw, "naabu_sniper_discovery")
                    async with self._heavy_task_semaphore:
                        verified_ports = await loop.run_in_executor(
                            self._plugin_executor, naabu_plugin.get_open_ports, ip, None, "1000", False, 1000, naabu_dir
                        )
                except Exception:
                    verified_ports = []
            if not verified_ports:
                self.log.info("Nmap fallback: scanning top-200 common ports...")
                try:
                    from config import Config as _Cfg
                    verified_ports = await self._safe_nmap_verify(ip, _Cfg.TOP_200_PORTS, "2m", mode="sniper")
                except Exception:
                    verified_ports = []

        if not verified_ports:
            self.log.warning("No open ports found after verification.")
            return result

        # Step 2: Nmap Version Detection
        nmap_plugin = PluginRegistry.get("Nmap")
        if nmap_plugin:
            self.log.info(f"Nmap version detection on {len(verified_ports)} verified ports...")
            nmap_data = await loop.run_in_executor(
                self._plugin_executor,
                partial(
                    nmap_plugin.run, ip, self.out_dir, index, "sniper", verified_ports,
                    strategy_profile=self._strategy_profile("nmap", "sniper"),
                ),
            )
            result["ports"] = nmap_data.get("ports", [])
            result["nse_cves"] = nmap_data.get("nse_cves", [])

        # Step 3: httpx probe trước Nuclei
        nuclei_plugin = PluginRegistry.get("Nuclei")
        if nuclei_plugin and nuclei_plugin.check_installed():
            tags = self._derive_nuclei_tags(result["ports"])
            if tags:
                nuclei_dir = os.path.join(self.raw, "nuclei_sniper")
                httpx_plugin = PluginRegistry.get("Httpx")
                scan_urls = []
                web_probe_ports = self._web_ports_from_services(result.get("ports", [])) or [
                    p for p in verified_ports if int(p) in [80, 443, 8000, 8080, 8180, 8443, 8888, 9090]
                ]
                if httpx_plugin and httpx_plugin.check_installed():
                    if web_probe_ports:
                        self.log.info(f"httpx probing {len(web_probe_ports)}/{len(verified_ports)} web-like ports before Nuclei...")
                        httpx_dir = os.path.join(self.raw, "httpx_sniper")
                        hx_extra = []
                        if self.rate_limit:
                            hx_extra.extend(["-rl", str(self.rate_limit)])
                        httpx_results = await loop.run_in_executor(
                            self._plugin_executor, httpx_plugin.probe_from_ports, ip, web_probe_ports, httpx_dir, 
                            self._get_auth_headers(), self.proxy_file, hx_extra,
                            "recon"
                        )
                        scan_urls = [r["url"] for r in httpx_results if r.get("url")]
                        
                        for r in httpx_results:
                            for p in result["ports"]:
                                if p["port"] == r.get("port"):
                                    p["tech"] = r.get("tech", [])
                                    p["title"] = r.get("title", "")

                if not scan_urls:
                    for port in web_probe_ports:
                        scheme = "https" if port in [443, 8443] else "http"
                        base_url = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
                        scan_urls.append(base_url)

                # Step 3b: Playwright SPA Discovery
                if self.use_playwright and scan_urls:
                    playwright_plugin = PluginRegistry.get("Playwright")
                    if playwright_plugin:
                        self.log.info(f"Playwright SPA discovery on {min(len(scan_urls), 3)} URLs...")
                        try:
                            pw_results = await playwright_plugin.run(
                                scan_urls[:3], self.raw, timeout=30, 
                                headers=self._get_auth_headers(), proxy=self.proxy_file
                            )
                            if pw_results.get("endpoints"):
                                self.log.success(f"Playwright discovered {len(pw_results['endpoints'])} hidden API endpoints.")
                                scan_urls.extend(pw_results["endpoints"])
                                scan_urls = list(set(scan_urls))
                        except Exception as e:
                            self.log.warning(f"Playwright failed: {e}")

                # Nuclei với CHUNKING
                self.log.info(f"Nuclei targeted scan (tags: {', '.join(tags[:5])}) with CHUNKING...")
                nuclei_dir = os.path.join(self.raw, "nuclei_sniper")
                
                async def _scan_nuclei_chunk_sn(chunk_targets):
                    return await self._nuclei_batch_with_retry(
                        chunk_targets, nuclei_dir, tags=list(tags),
                        severity=["critical", "high", "medium"],
                        mode="sniper", headers=self._get_auth_headers()
                    )

                chunked_results = await self.run_in_chunks(
                    f"nuclei_sniper_{target}", scan_urls, self.chunk_size, _scan_nuclei_chunk_sn
                )
                result["nuclei_findings"] = chunked_results
                self.log.success(f"Nuclei found {len(result['nuclei_findings'])} sniper findings.")

        # Step 4: dnsx
        dns_dir = os.path.join(self.raw, "dns")
        result["dns_records"] = await self._run_dnsx(target, dns_dir)

        return result
