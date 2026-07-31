#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Web Vuln Route Handler
=================================
OWASP 2026 (Playwright → Katana → Nuclei + DAST).
"""

import asyncio
import os
import shutil

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry
from core.performance import unique_http_urls_by_host
from utils.url_dedup import URLDeduplicator


class WebVulnRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("WEB-VULN MODE — OWASP 2026 (Playwright → Katana → Nuclei)")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [], "vhosts": [], "screenshots_dir": "",
            "blind_xss": {}, "mass_assignment_findings": [], "dast_findings": []
        }
        loop = asyncio.get_running_loop()

        web_ports = osint_ports if osint_ports else [80, 443, 8080, 8443, 8888, 3000, 5000, 9090]

        # Step 1: httpx — Probe live HTTP services & detect tech
        httpx_plugin = PluginRegistry.get("Httpx")
        live_urls = []
        if httpx_plugin and httpx_plugin.check_installed():
            self.log.info(f"httpx probing {len(web_ports)} ports for live HTTP services...")
            httpx_dir = os.path.join(self.raw, "httpx")
            hx_extra = []
            if self.rate_limit:
                hx_extra.extend(["-rl", str(self.rate_limit)])
            httpx_results = await loop.run_in_executor(
                self._plugin_executor, httpx_plugin.probe_from_ports, ip, web_ports, httpx_dir, self._get_auth_headers(), None, hx_extra,
                "recon"
            )
            live_urls = [r["url"] for r in httpx_results if r.get("url")]
            for r in httpx_results:
                result["ports"].append({
                    "port": r.get("port", 80), "service": "http",
                    "version": r.get("web_server", ""), "tech": r.get("tech", []), "title": r.get("title", ""),
                })
            self.log.success(f"httpx found {len(live_urls)} live HTTP services.")
        else:
            for port in web_ports:
                scheme = "https" if port in [443, 8443] else "http"
                base_url = f"{scheme}://{target}" if port in [80, 443] else f"{scheme}://{target}:{port}"
                live_urls.append(base_url)

        if not live_urls:
            self.log.warning("No live HTTP services found.")
            return result

        # Step 1b: Playwright SPA Discovery
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

        # Step 2: Katana — JS-Aware Web Crawling
        katana_plugin = PluginRegistry.get("Katana")
        api_like_urls = []
        if katana_plugin and katana_plugin.check_installed():
            from config import Config as _Cfg2
            katana_limit = _Cfg2.KATANA_MAX_URLS.get("web-vuln", 30)
            self.log.info(f"Katana crawling {min(len(live_urls), katana_limit)} URLs (JS-aware, depth=3)...")
            raw_crawled = []
            for crawl_data in await self._run_katana_many(
                katana_plugin,
                live_urls,
                "web_vuln",
                limit=katana_limit,
                depth=3,
                js_crawl=True,
                headless=False,
                proxy_mode="fuzz",
            ):
                self._append_crawl_output(crawl_data, raw_crawled, api_like_urls=api_like_urls)
            
            base_urls, param_urls = URLDeduplicator.deduplicate_with_params(raw_crawled)
            result["web_urls"] = base_urls
            result["web_urls_with_params"] = param_urls
            self.log.success(f"Katana: {len(base_urls)} base + {len(param_urls)} parameterized endpoints.")

        # Step 3: Nuclei — Batch Web Scan
        nuclei_plugin = PluginRegistry.get("Nuclei")
        if nuclei_plugin and nuclei_plugin.check_installed():
            self.log.info("Nuclei web vulnerability scan (Chunked mode for perfect resume)...")
            nuclei_dir = os.path.join(self.raw, "nuclei_web")
            web_tags = ["cve", "sqli", "xss", "ssrf", "lfi", "rfi", "rce", "ssti",
                        "redirect", "exposure", "misconfig", "default-login", "injection",
                        "cors", "header", "token", "oast"]

            nuclei_targets = list(live_urls)
            param_urls = result.get("web_urls_with_params", [])
            if param_urls:
                nuclei_targets.extend(param_urls[:100])
                nuclei_targets = URLDeduplicator.deduplicate(nuclei_targets)

            async def _scan_nuclei_chunk(chunk_targets):
                return await self._nuclei_batch_with_retry(
                    chunk_targets, nuclei_dir, tags=web_tags,
                    severity=["critical", "high", "medium"],
                    mode="web-vuln", headers=self._get_auth_headers()
                )

            chunked_results = await self.run_in_chunks(
                f"nuclei_web_vuln_{target}", nuclei_targets, 20, _scan_nuclei_chunk
            )
            result["nuclei_findings"] = chunked_results
            self.log.success(f"Nuclei found {len(result['nuclei_findings'])} total web vulnerabilities.")

        # Step 4: ffuf — Directory fuzzing
        if shutil.which("ffuf"):
            ffuf_targets = unique_http_urls_by_host(live_urls, limit=self._ffuf_runtime_options()["targets"])
            self.log.info(f"ffuf directory fuzzing on {len(ffuf_targets)} unique hosts...")
            all_ffuf_results = await self._run_ffuf_many(
                ffuf_targets,
                os.path.join(self.raw, "ffuf_webvuln"),
                headers=self._get_auth_headers(),
                purpose="web_content",
            )
            result["web_urls"].extend(all_ffuf_results)
            self.log.success(f"ffuf found {len(all_ffuf_results)} interesting paths across {len(ffuf_targets)} hosts.")

        # Step 4b-4e: Concurrent DAST Plugin Execution Pipeline
        self.log.info("Running DAST Security Plugins (Dalfox, Corsy, BlindXSS, MassAssignment) CONCURRENTLY...")
        dast_coroutines = []
        dast_names = []

        dalfox_plugin = PluginRegistry.get("Dalfox")
        param_urls_for_dast = result.get("web_urls_with_params", [])
        if dalfox_plugin and dalfox_plugin.check_installed() and param_urls_for_dast:
            from config import Config as _CfgDalfox
            dalfox_dir = os.path.join(self.raw, "dalfox_webvuln")
            dalfox_strategy = self._strategy_profile(
                "dalfox", "web-vuln",
                parameterized_count=len(param_urls_for_dast or []),
            )
            dast_coroutines.append(loop.run_in_executor(
                self._plugin_executor, dalfox_plugin.run, param_urls_for_dast, dalfox_dir,
                self._get_auth_headers(), _CfgDalfox.DALFOX_TIMEOUT_PER_URL,
                _CfgDalfox.DALFOX_MAX_URLS, "", False,
                dalfox_strategy.get("proxy_mode", "fuzz"),
                bool(dalfox_strategy.get("deep_domxss")),
            ))
            dast_names.append("dalfox")

        corsy_plugin = PluginRegistry.get("Corsy")
        if corsy_plugin and live_urls:
            corsy_dir = os.path.join(self.raw, "corsy_webvuln")
            dast_coroutines.append(loop.run_in_executor(
                self._plugin_executor, corsy_plugin.run, live_urls, corsy_dir,
                self._get_auth_headers(), 10, 30, False, "exploit"
            ))
            dast_names.append("corsy")

        bxss_plugin = PluginRegistry.get("BlindXSS")
        if bxss_plugin and bxss_plugin.check_installed():
            from config import Config as _CfgBlindXss
            bxss_dir = os.path.join(self.raw, "blind_xss_webvuln")
            interactsh_url = getattr(self, "_interactsh_url", "") or ""
            dast_coroutines.append(loop.run_in_executor(
                self._plugin_executor, bxss_plugin.run, live_urls, bxss_dir,
                self._get_auth_headers(), interactsh_url,
                10, _CfgBlindXss.BLIND_XSS_MAX_URLS, "fuzz"
            ))
            dast_names.append("blind_xss")

        mass_assignment_plugin = PluginRegistry.get("MassAssignment")
        if mass_assignment_plugin:
            mass_assignment_targets = []
            candidate_urls = list(api_like_urls) + list(result.get("web_urls_with_params", []) or [])
            for candidate in candidate_urls:
                candidate_url = str(candidate).strip()
                if any(keyword in candidate_url.lower() for keyword in ["/user", "/users", "/account", "/profile", "/admin", "/member", "/settings"]):
                    mass_assignment_targets.append(candidate_url)
            mass_assignment_targets = URLDeduplicator.deduplicate(mass_assignment_targets)[:10]
            if mass_assignment_targets:
                dast_coroutines.append(loop.run_in_executor(
                    self._plugin_executor,
                    lambda: mass_assignment_plugin.run(
                        urls=mass_assignment_targets,
                        auth_token=self.auth_userA or "",
                        method="POST",
                        headers=self._get_auth_headers(),
                        timeout=15,
                    ),
                ))
                dast_names.append("mass_assignment")

        if dast_coroutines:
            dast_outputs = await asyncio.gather(*dast_coroutines, return_exceptions=True)
            for idx, plugin_name in enumerate(dast_names):
                out = dast_outputs[idx]
                if isinstance(out, Exception):
                    self.log.warning(f"  [{plugin_name}] Error: {out}")
                    continue

                if plugin_name == "dalfox" and isinstance(out, list):
                    result["xss_findings"] = out
                    self._extend_dast_findings(result, "xss", out)
                    self.log.success(f"  [Dalfox]: {len(out)} XSS vulnerabilities found.")
                elif plugin_name == "corsy" and isinstance(out, list):
                    result["cors_findings"] = out
                    result["cors_issues"] = out
                    self._extend_dast_findings(result, "cors", out)
                    if out:
                        self.log.success(f"  [Corsy]: {len(out)} CORS misconfigurations found.")
                elif plugin_name == "blind_xss" and isinstance(out, dict):
                    result["blind_xss"] = out
                    self._extend_dast_findings(result, "blind_xss", out)
                    if out.get("injected_count", 0):
                        self.log.success(f"  [Blind XSS]: Injected {out.get('injected_count', 0)} payloads.")
                elif plugin_name == "mass_assignment" and isinstance(out, list):
                    result["mass_assignment_findings"] = out
                    self._extend_dast_findings(result, "mass_assignment", out)
                    if out:
                        self.log.success(f"  [Mass Assignment]: {len(out)} findings.")

        # Step 5: gowitness
        if live_urls:
            screenshot_dir = await self._run_gowitness(live_urls, os.path.join(self.raw, "gowitness"))
            result["screenshots_dir"] = screenshot_dir

        # Step 6: VHost discovery
        vhost_dir = os.path.join(self.raw, "vhost")
        result["vhosts"] = await self._run_vhost_discovery(ip, target, vhost_dir)

        result["summary"] = {
            "mode": "web-vuln",
            "live_urls": len(live_urls),
            "nuclei_findings": len(result.get("nuclei_findings", [])),
            "xss": len(self._get_dast_findings(result, "xss")),
            "cors": len(self._get_dast_findings(result, "cors")),
            "blind_xss": len(self._get_dast_findings(result, "blind_xss")),
            "mass_assignment": len(self._get_dast_findings(result, "mass_assignment")),
            "parameterized_urls": len(result.get("web_urls_with_params", []) or []),
            "vhosts": len(result.get("vhosts", []) or []),
        }

        self.log.phase("WEB-VULN SUMMARY")
        self.log.info(f"  🔍 Nuclei: {result['summary']['nuclei_findings']} findings")
        self.log.info(f"  🕷️  XSS: {result['summary']['xss']}")
        self.log.info(f"  🌐 CORS: {result['summary']['cors']}")
        self.log.info(f"  🪝 Blind XSS: {result['summary']['blind_xss']}")
        self.log.info(f"  🔐 Mass Assignment: {result['summary']['mass_assignment']}")
        self.log.info(f"  📎 Parameterized URLs: {result['summary']['parameterized_urls']}")
        self.log.info(f"  🧭 VHosts: {result['summary']['vhosts']}")

        result = self._finalize_scan_contracts(result, target, "web-vuln")
        await self._generate_web_vuln_reports(result, target)

        return result
