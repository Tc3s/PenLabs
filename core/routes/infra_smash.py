#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Infra Smash Route Handler
====================================
Red Team Full Kill-Chain (InternetDB → Naabu → Nmap).
"""

import asyncio
import os
from functools import partial

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry


class InfraSmashRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("INFRA-SMASH MODE — ☠️ Red Team Full Kill-Chain (InternetDB → Naabu → Nmap)")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [], "internetdb_data": {},
        }
        loop = asyncio.get_running_loop()

        # Step 1: InternetDB Passive Intelligence
        idb_ports = list(osint_ports) if osint_ports else []
        use_internetdb = getattr(self, '_use_internetdb', True)

        if use_internetdb:
            self.log.info(f"Shodan InternetDB passive lookup for {ip or target}...")
            try:
                idb_plugin = PluginRegistry.get("ShodanInternetDB")
                if idb_plugin:
                    idb_data = await loop.run_in_executor(self._plugin_executor, idb_plugin.run, ip or target)
                    if idb_data:
                        result["internetdb_data"] = idb_data
                        idb_ports_raw = idb_data.get("ports", [])
                        if idb_ports_raw:
                            idb_ports = list(set(idb_ports + idb_ports_raw))
                            self.log.success(f"InternetDB passive ports: {idb_ports_raw}")
                        if idb_data.get("vulns"):
                            self.log.success(f"InternetDB known CVEs: {', '.join(idb_data['vulns'][:15])}")
                        if idb_data.get("hostnames"):
                            self.log.info(f"InternetDB hostnames: {', '.join(idb_data['hostnames'][:10])}")
                else:
                    self.log.warning("ShodanInternetDB plugin not registered.")
            except Exception as e:
                self.log.warning(f"InternetDB lookup failed: {e}")

        # Step 2: Naabu — Active port verification
        verified_ports = []
        naabu_plugin = PluginRegistry.get("Naabu")
        if naabu_plugin and naabu_plugin.check_installed():
            if idb_ports:
                self.log.info(f"Naabu verifying {len(idb_ports)} InternetDB ports + scanning top-1000...")
                clean_ports = self._sanitize_ports(idb_ports)
                naabu_dir = os.path.join(self.raw, "naabu_infrasmash")
                try:
                    verified_ports = await loop.run_in_executor(
                        self._plugin_executor, naabu_plugin.get_open_ports, ip or target, clean_ports, "1000", False, 3000, naabu_dir
                    )
                except Exception:
                    verified_ports = []
            else:
                self.log.info("Naabu scanning all 65535 ports (no InternetDB data available)...")
                naabu_dir = os.path.join(self.raw, "naabu_infrasmash_full")
                try:
                    verified_ports = await loop.run_in_executor(
                        self._plugin_executor, naabu_plugin.get_open_ports, ip or target, None, "", True, 5000, naabu_dir
                    )
                except Exception:
                    verified_ports = []
            self.log.success(f"Naabu verified {len(verified_ports)} open ports.")
        else:
            if idb_ports:
                clean_ports = self._sanitize_ports(idb_ports)
                self.log.info(f"Nmap verifying {len(clean_ports)} ports (Naabu unavailable)...")
                verified_ports = await self._safe_nmap_verify(ip or target, clean_ports, "2m", mode="full-audit")
            else:
                self.log.warning("No port data and no Naabu available. Using Nmap top-500 fallback.")
                from config import Config as _CfgIS
                verified_ports = await self._safe_nmap_verify(
                    ip or target, getattr(_CfgIS, 'TOP_200_PORTS', list(range(1, 201))), "3m", mode="full-audit"
                )

        if not verified_ports:
            self.log.warning("No open ports found after verification.")
            return result

        # Step 3: Nmap Full NSE
        nmap_plugin = PluginRegistry.get("Nmap")
        if nmap_plugin:
            self.log.info(f"Nmap full NSE scan on {len(verified_ports)} verified ports...")
            nmap_data = await loop.run_in_executor(
                self._plugin_executor,
                partial(
                    nmap_plugin.run, ip or target, self.out_dir, index, "infra-smash", verified_ports,
                    strategy_profile=self._strategy_profile("nmap", "infra-smash"),
                ),
            )
            result["ports"] = nmap_data.get("ports", [])
            result["nse_cves"] = nmap_data.get("nse_cves", [])
            result["os_detection"] = nmap_data.get("os_detection", [])
            self.log.success(
                f"Nmap found {len(result['ports'])} services, "
                f"{len(result['nse_cves'])} NSE CVEs, "
                f"{len(result['os_detection'])} OS fingerprints."
            )

        # Step 4: httpx probe web ports → Nuclei batch
        web_ports = [p["port"] for p in result.get("ports", [])
                     if p.get("service") in ["http", "ssl/http", "https", "http-proxy"] or
                     p.get("port") in [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090]]
        web_ports = list(set(web_ports))
        scan_urls = []
        if web_ports:
            httpx_plugin = PluginRegistry.get("Httpx")
            if httpx_plugin and httpx_plugin.check_installed():
                self.log.info(f"Httpx probing {len(web_ports)} web ports...")
                httpx_dir = os.path.join(self.raw, "httpx_infrasmash")
                httpx_results = await loop.run_in_executor(
                    self._plugin_executor, httpx_plugin.probe_from_ports, ip or target, web_ports, httpx_dir,
                    self._get_auth_headers(), None, None,
                    "recon"
                )
                scan_urls = [r["url"] for r in httpx_results if r.get("url")]
                for r in httpx_results:
                    for p in result["ports"]:
                        if p["port"] == r.get("port"):
                            p["tech"] = r.get("tech", [])
                            p["title"] = r.get("title", "")
            if not scan_urls:
                for port in web_ports:
                    scheme = "https" if port in [443, 8443] else "http"
                    base_url = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
                    scan_urls.append(base_url)

        result["web_urls"] = scan_urls

        # Step 4b: Playwright SPA Discovery
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

        # Step 5: Nuclei
        if scan_urls:
            self.log.info("Nuclei full CVE + exploit scan with CHUNKING...")
            nuclei_dir = os.path.join(self.raw, "nuclei_infrasmash")
            
            async def _scan_nuclei_chunk_is(chunk_targets):
                return await self._nuclei_batch_with_retry(
                    chunk_targets, nuclei_dir,
                    severity=["critical", "high", "medium"],
                    mode="infra-smash", headers=self._get_auth_headers()
                )

            chunked_results = await self.run_in_chunks(
                f"nuclei_infra_smash_{target}", scan_urls, self.chunk_size, _scan_nuclei_chunk_is
            )
            result["nuclei_findings"] = chunked_results
            self.log.success(f"Nuclei found {len(result['nuclei_findings'])} total findings.")

        # Step 6: UDP scan
        self.log.info("Nmap UDP scan (top 20 critical services)...")
        udp_ports = await self._scan_udp_top20(ip or target)
        if udp_ports:
            result["ports"].extend(udp_ports)
            self.log.success(f"UDP scan found {len(udp_ports)} open UDP services.")

        self.log.success(
            f"INFRA-SMASH complete: {len(result['ports'])} services | "
            f"{len(result['nse_cves'])} CVEs | {len(result['nuclei_findings'])} Nuclei findings"
        )
        return result
