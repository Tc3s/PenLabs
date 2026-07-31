#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — API Bounty Route Handler
===================================
Bug Bounty Hunting Pipeline (V1.0 — 20 Steps).
"""

import asyncio
import os
import shutil

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry
from core.performance import unique_http_urls_by_host
from utils.url_dedup import URLDeduplicator


class APIBountyRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list, waf_detected: bool = False) -> dict:
        self.log.phase("API-BOUNTY MODE — 🎯 Bug Bounty Hunting Pipeline (V1.0 — 20 Steps)")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [],
            "api_endpoints": [], "hidden_params": {}, "js_secrets": [],
            "xss_findings": [], "cors_findings": [], "cors_issues": [], "graphql_findings": [], "graphql": {},
            "bypass_403": [], "cache_poisoning": [], "sqli_findings": [],
            "mass_assignment_findings": [],
            "wpscan": {},
            "ssrf_findings": [], "blind_xss": {}, "open_redirect_findings": [],
            "crlf_findings": [], "race_condition_findings": [],
            "bola_findings": {},
            "dast_findings": [],
        }
        loop = asyncio.get_running_loop()

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
        
        scan_targets = []
        if osint_ports:
            web_ports = [p for p in osint_ports if int(p) in [80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9090]]
            if not web_ports:
                web_ports = [80, 443]
            for port in web_ports:
                scheme = "https" if int(port) in [443, 8443] else "http"
                base_url = f"{scheme}://{target}" if int(port) in [80, 443] else f"{scheme}://{target}:{port}"
                scan_targets.append(base_url)
        if not scan_targets:
            scan_targets = [f"https://{target}", f"http://{target}"]
        
        if httpx_plugin and httpx_plugin.check_installed():
            self.log.info("httpx probing live URLs + tech detection...")
            httpx_dir = os.path.join(self.raw, "httpx_bounty")
            httpx_results = await loop.run_in_executor(
                self._plugin_executor, httpx_plugin.run, scan_targets, httpx_dir, 
                50, None, self._get_auth_headers(), None,
                "recon"
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

        # Step 2: Katana
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

        # Step 3: Kiterunner
        kr_plugin = PluginRegistry.get("Kiterunner")
        if kr_plugin and kr_plugin.check_installed():
            self.log.info("Kiterunner brute-forcing API routes (Swagger wordlists)...")
            kr_dir = os.path.join(self.raw, "kiterunner")
            kr_wordlist = self._resolve_wordlist("api_routes", out_dir=kr_dir).get("path") or _Cfg.KITERUNNER_WORDLIST
            kr_targets = unique_http_urls_by_host(
                live_urls,
                limit=getattr(self.performance, "kiterunner_targets", 30),
            )
            async with self._heavy_task_semaphore:
                kr_results = await loop.run_in_executor(
                    self._plugin_executor, kr_plugin.run, kr_targets or live_urls, kr_dir,
                    kr_wordlist, _Cfg.KITERUNNER_MAX_CONN,
                    self._get_auth_headers(), _Cfg.KITERUNNER_TIMEOUT
                )
            result["api_endpoints"] = self._normalize_api_endpoints(kr_results, source="kiterunner")
            for ep in result["api_endpoints"]:
                if ep.get("url"):
                    api_like_urls.append(ep["url"])
            self.log.success(f"Kiterunner: {len(kr_results)} API endpoints discovered.")
        else:
            self.log.warning("[Kiterunner] Not installed — skip API route discovery.")

        # Step 4: LinkFinder
        lf_plugin = PluginRegistry.get("LinkFinder")
        if lf_plugin and js_files:
            self.log.info(f"LinkFinder analyzing {len(js_files)} JavaScript files for endpoints & secrets...")
            lf_dir = os.path.join(self.raw, "linkfinder")
            async with self._heavy_task_semaphore:
                lf_results = await loop.run_in_executor(
                    self._plugin_executor, lf_plugin.run, js_files, lf_dir, 15, 50
                )
            for ep in lf_results.get("endpoints", []):
                if ep.startswith("/"):
                    for base in live_urls[:3]:
                        api_like_urls.append(f"{base.rstrip('/')}{ep}")
            result["js_secrets"] = lf_results.get("secrets", [])
            self.log.success(f"LinkFinder: {len(lf_results.get('endpoints', []))} endpoints, {len(result['js_secrets'])} secrets found.")
        
        # Step 5: WPScan
        wp_plugin = PluginRegistry.get("WPScan")
        if wp_plugin and wp_plugin.check_installed():
            for url in live_urls[:3]:
                if wp_plugin.detect_wordpress(url):
                    self.log.info(f"WordPress detected on {url}! Running WPScan...")
                    wp_dir = os.path.join(self.raw, "wpscan")
                    wp_strategy = self._strategy_profile("wpscan", "api-bounty", tech_stack=["wordpress"])
                    async with self._heavy_task_semaphore:
                        wp_result = await loop.run_in_executor(
                            self._plugin_executor, wp_plugin.run, url, wp_dir,
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

        # Step 6: Arjun
        arjun_plugin = PluginRegistry.get("Arjun")
        if arjun_plugin and arjun_plugin.check_installed():
            priority_urls = [u for u in api_like_urls if any(
                kw in u.lower() for kw in ["/api/", "/user", "/admin", "/account", "/profile", "/order", "/v1/", "/v2/"]
            )]
            scan_urls = (priority_urls or api_like_urls)[:_Cfg.ARJUN_MAX_ENDPOINTS]
            if scan_urls:
                self.log.info(f"Arjun discovering hidden params on {len(scan_urls)} priority endpoints...")
                arjun_dir = os.path.join(self.raw, "arjun")
                async with self._heavy_task_semaphore:
                    arjun_results = await loop.run_in_executor(
                        self._plugin_executor, arjun_plugin.run, scan_urls, arjun_dir,
                        "GET", self._get_auth_headers(),
                        _Cfg.ARJUN_TIMEOUT_PER_URL, _Cfg.ARJUN_MAX_ENDPOINTS
                    )
                result["hidden_params"] = arjun_results
                self.log.success(f"Arjun: Hidden params found on {len(arjun_results)} URLs.")

        # Step 7: Dalfox
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
                async with self._heavy_task_semaphore:
                    dalfox_results = await loop.run_in_executor(
                        self._plugin_executor, dalfox_plugin.run, param_urls, dalfox_dir,
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

        # Step 8: SQLMap Detect-Only
        sqlmap_plugin = PluginRegistry.get("SQLMapDetect")
        if sqlmap_plugin and sqlmap_plugin.check_installed() and param_urls:
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
                async with self._heavy_task_semaphore:
                    sqli_results = await loop.run_in_executor(
                        self._plugin_executor, sqlmap_plugin.run, sqli_candidates, sqlmap_dir,
                        self._get_auth_headers(), _Cfg.SQLMAP_DETECT_TIMEOUT,
                        _Cfg.SQLMAP_DETECT_MAX_URLS, "", "", waf_detected, self.sqlmap_relay,
                        sqlmap_strategy.get("risk", 1),
                        sqlmap_strategy.get("level", 1),
                        sqlmap_strategy.get("tamper", []),
                    )
                result["sqli_findings"] = sqli_results
                self._extend_dast_findings(result, "sqli", sqli_results)
                self.log.success(f"SQLMap: {len(sqli_results)} SQL Injection points detected (no exploit).")

        # Step 9: Corsy
        corsy_plugin = PluginRegistry.get("Corsy")
        if corsy_plugin:
            _corsy_proxy_mode = "exploit" if waf_detected else "fuzz"
            if waf_detected:
                self.log.info(f"[PROXY] Escalating Corsy to EXPLOIT mode due to WAF detection")
            self.log.info(f"Corsy checking CORS on {min(len(live_urls), 30)} URLs...")
            corsy_dir = os.path.join(self.raw, "corsy")
            cors_results = await loop.run_in_executor(
                self._plugin_executor, corsy_plugin.run, live_urls, corsy_dir,
                self._get_auth_headers(), 10, 30, waf_detected,
                _corsy_proxy_mode
            )
            result["cors_findings"] = cors_results
            result["cors_issues"] = cors_results
            self._extend_dast_findings(result, "cors", cors_results)
            if cors_results:
                self.log.success(f"Corsy: {len(cors_results)} CORS misconfiguration issues!")

        # Step 10: GraphQL Probe
        gql_plugin = PluginRegistry.get("GraphQLProbe")
        if gql_plugin:
            self.log.info("GraphQL Probe checking for GraphQL endpoints...")
            gql_dir = os.path.join(self.raw, "graphql")
            gql_results = await loop.run_in_executor(
                self._plugin_executor, gql_plugin.run, live_urls, gql_dir,
                self._get_auth_headers(), 10, 10
            )
            result["graphql_findings"] = gql_results.get("introspection_enabled", []) + gql_results.get("graphql_vulns", gql_results.get("findings", []))
            result["graphql"] = gql_results
            self._extend_dast_findings(result, "graphql", result["graphql_findings"])
            if gql_results.get("endpoints_found"):
                self.log.success(f"GraphQL: {len(gql_results['endpoints_found'])} endpoints, "
                                 f"{len(gql_results.get('introspection_enabled', []))} with introspection!")

        # Step 11: 403 Bypass Fuzzer
        forbidden_urls = []
        for ep in result.get("api_endpoints", []):
            if ep.get("status") == 403:
                forbidden_urls.append(ep.get("url", ""))
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

        # Step 12: Cache Poisoning Probe
        self.log.info("Cache Poisoning Probe testing unkeyed headers...")
        cache_results = await self._cache_poison_probe(live_urls)
        result["cache_poisoning"] = cache_results
        self._extend_dast_findings(result, "cache_poisoning", cache_results)
        if cache_results:
            self.log.success(f"Cache Poisoning: {len(cache_results)} potential vectors found!")

        # Step 13: Blind XSS Injector
        bxss_plugin = PluginRegistry.get("BlindXSS")
        if bxss_plugin and bxss_plugin.check_installed():
            self.log.info(f"Blind XSS Injector scanning {min(len(live_urls), _Cfg.BLIND_XSS_MAX_URLS)} URLs for stored/blind XSS...")
            bxss_dir = os.path.join(self.raw, "blind_xss")
            interactsh_url = getattr(self, '_interactsh_url', '') or ''
            bxss_results = await loop.run_in_executor(
                self._plugin_executor, bxss_plugin.run, live_urls, bxss_dir,
                self._get_auth_headers(), interactsh_url,
                10, _Cfg.BLIND_XSS_MAX_URLS, "exploit" if waf_detected else "fuzz"
            )
            result["blind_xss"] = bxss_results
            self._extend_dast_findings(result, "blind_xss", bxss_results)
            self.log.success(f"Blind XSS: Injected {bxss_results.get('injected_count', 0)} payloads into {bxss_results.get('forms_found', 0)} forms.")

        # Step 14: Mass Assignment Probe
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
                    self._plugin_executor,
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

        # Step 15: SSRF Probe
        ssrf_plugin = PluginRegistry.get("SSRFProbe")
        if ssrf_plugin and ssrf_plugin.check_installed():
            ssrf_targets = param_urls[:_Cfg.SSRF_MAX_URLS] if param_urls else live_urls[:10]
            if ssrf_targets:
                self.log.info(f"SSRF Probe testing {len(ssrf_targets)} URLs for Server-Side Request Forgery...")
                ssrf_dir = os.path.join(self.raw, "ssrf")
                interactsh_url = getattr(self, '_interactsh_url', '') or ''
                ssrf_results = await loop.run_in_executor(
                    self._plugin_executor, ssrf_plugin.run, ssrf_targets, ssrf_dir,
                    self._get_auth_headers(), interactsh_url,
                    _Cfg.SSRF_TIMEOUT_PER_URL, _Cfg.SSRF_MAX_URLS
                )
                result["ssrf_findings"] = ssrf_results
                self._extend_dast_findings(result, "ssrf", ssrf_results)
                if ssrf_results:
                    self.log.success(f"SSRF Probe: {len(ssrf_results)} SSRF vulnerabilities found!")
                else:
                    self.log.info("[SSRF] No SSRF detected.")

        # Step 16: Open Redirect Scanner
        redirect_plugin = PluginRegistry.get("OpenRedirect")
        if redirect_plugin and redirect_plugin.check_installed():
            redirect_targets = param_urls[:_Cfg.OPEN_REDIRECT_MAX_URLS] if param_urls else live_urls[:20]
            self.log.info(f"Open Redirect Scanner testing {len(redirect_targets)} URLs...")
            redirect_dir = os.path.join(self.raw, "open_redirect")
            redirect_results = await loop.run_in_executor(
                self._plugin_executor, redirect_plugin.run, redirect_targets, redirect_dir,
                self._get_auth_headers(), 10, _Cfg.OPEN_REDIRECT_MAX_URLS
            )
            result["open_redirect_findings"] = redirect_results
            self._extend_dast_findings(result, "open_redirect", redirect_results)
            if redirect_results:
                self.log.success(f"Open Redirect: {len(redirect_results)} redirect vulnerabilities found!")

        # Step 17: CRLF Injection Scanner
        crlf_plugin = PluginRegistry.get("CRLFScan")
        if crlf_plugin and crlf_plugin.check_installed():
            self.log.info(f"CRLF Scanner testing {min(len(live_urls), _Cfg.CRLF_MAX_URLS)} URLs for header injection...")
            crlf_dir = os.path.join(self.raw, "crlf")
            crlf_results = await loop.run_in_executor(
                self._plugin_executor, crlf_plugin.run, live_urls, crlf_dir,
                self._get_auth_headers(), 10, _Cfg.CRLF_MAX_URLS
            )
            result["crlf_findings"] = crlf_results
            self._extend_dast_findings(result, "crlf", crlf_results)
            if crlf_results:
                self.log.success(f"CRLF: {len(crlf_results)} CRLF injection points found!")

        # Step 18: Race Condition Tester
        race_plugin = PluginRegistry.get("RaceTest")
        all_discovered_urls = list(set(live_urls + api_like_urls + param_urls))
        if race_plugin and race_plugin.check_installed() and all_discovered_urls:
            self.log.info(f"Race Condition Tester checking {len(all_discovered_urls)} endpoints for TOCTOU...")
            race_dir = os.path.join(self.raw, "race_condition")
            race_results = await loop.run_in_executor(
                self._plugin_executor, race_plugin.run, all_discovered_urls, race_dir,
                self._get_auth_headers(), _Cfg.RACE_CONDITION_CONCURRENT,
                15, _Cfg.RACE_CONDITION_MAX_URLS
            )
            result["race_condition_findings"] = race_results
            self._extend_dast_findings(result, "race_condition", race_results)
            if race_results:
                self.log.success(f"Race Condition: {len(race_results)} potential race conditions found!")

        # Step 19: BOLA/IDOR Engine
        bola_plugin = PluginRegistry.get("BOLAEngine")
        if bola_plugin and bola_plugin.check_installed() and self.bola_engine and self.auth_userA and self.auth_userB:
            bola_targets = api_like_urls[:_Cfg.BOLA_MAX_ENDPOINTS] if api_like_urls else live_urls[:20]
            self.log.info(f"BOLA Engine cross-testing {len(bola_targets)} endpoints with 2 user tokens...")
            bola_dir = os.path.join(self.raw, "bola")
            bola_results = await loop.run_in_executor(
                self._plugin_executor, bola_plugin.run, bola_targets, bola_dir,
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

        # Step 20: Nuclei — Targeted Bounty Templates
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
            if self.delay:
                extra_flags.extend(["-delay", self.delay])
            nuclei_strategy = self._strategy_profile(
                "nuclei", "api-bounty", waf_detected=waf_detected,
                parameterized_count=len(param_urls or []),
            )
            from core.plugin_strategy import merge_nuclei_tags
            bounty_tags = merge_nuclei_tags(bounty_tags, nuclei_strategy)
            
            noise_stop = asyncio.Event()
            noise_task = asyncio.create_task(self._send_behavioral_noise(noise_stop, f"https://{target}"))
            self.log.info("Nuclei full batch scan with CHUNKING...")
            
            async def _scan_nuclei_chunk_bounty(chunk_targets):
                return await loop.run_in_executor(
                    self._plugin_executor,
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

        # Step 21: Generate Reports
        await self._generate_bounty_reports(result, target)

        _executed_steps = sum([
            1 if result.get("web_urls") else 0,
            1 if result.get("api_endpoints") else 0,
            1 if result.get("hidden_params") else 0,
            1 if self._get_dast_findings(result, "xss") else 0,
            1 if self._get_dast_findings(result, "sqli") else 0,
            1 if self._get_dast_findings(result, "ssrf") else 0,
            1 if self._get_dast_findings(result, "cors") else 0,
            1 if result.get("nuclei_findings") else 0,
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
