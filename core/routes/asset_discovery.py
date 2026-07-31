#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Asset Discovery Route Handler
========================================
Full Asset Enumeration (Subfinder → Httpx → Katana → Nuclei).
"""

import asyncio
import hashlib
import json
import os
import shutil
from urllib.parse import urlparse
from functools import partial

import aiohttp

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry
from utils.url_dedup import URLDeduplicator


class AssetDiscoveryRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("ASSET-DISCOVERY MODE — Full Asset Enumeration (Subfinder → Httpx → Katana → Nuclei)")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [], "subdomains": [],
            "api_endpoints": [], "js_secrets": [], "secrets": [], "httpx_results": [], "js_files": [],
        }
        loop = asyncio.get_running_loop()

        # Step 1: Subfinder — Subdomain enumeration
        subdomains = []
        if shutil.which("subfinder"):
            self.log.info(f"Subfinder enumerating subdomains for {target}...")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "subfinder", "-d", target, "-silent", "-all",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=180)
                subdomains = [s.strip() for s in stdout.decode('utf-8', errors='ignore').splitlines() if s.strip()]
                self.log.success(f"Subfinder found {len(subdomains)} subdomains.")
            except Exception as e:
                self.log.warning(f"Subfinder failed: {e}")
        result["subdomains"] = subdomains

        # Step 2: Httpx — Probe all targets (main + subs) for live HTTP services + tech-detect
        httpx_plugin = PluginRegistry.get("Httpx")
        live_urls = []
        all_targets = [f"https://{target}", f"http://{target}"]
        for sub in subdomains[:100]:
            all_targets.append(f"https://{sub}")
            all_targets.append(f"http://{sub}")

        if httpx_plugin and httpx_plugin.check_installed():
            self.log.info(f"Httpx probing {len(all_targets)} targets for live HTTP services + tech-detect...")
            httpx_dir = os.path.join(self.raw, "httpx_asset_discovery")
            hx_extra = []
            if self.rate_limit:
                hx_extra.extend(["-rl", str(self.rate_limit)])
            httpx_threads = max(1, min(int(self.rate_limit or 50), 50))
            httpx_results = await loop.run_in_executor(
                self._plugin_executor, httpx_plugin.run, all_targets, httpx_dir,
                httpx_threads, hx_extra or None, self._get_auth_headers(), None,
                "recon"
            )
            live_urls = URLDeduplicator.deduplicate([r["url"] for r in httpx_results if r.get("url")])
            result["httpx_results"] = httpx_results
            for r in httpx_results:
                result["ports"].append({
                    "port": r.get("port", 80),
                    "service": "http",
                    "version": r.get("web_server", ""),
                    "tech": r.get("tech", []),
                    "title": r.get("title", ""),
                })
            self.log.success(f"Httpx found {len(live_urls)} live HTTP services.")
        else:
            live_urls = [f"https://{target}"]

        if not live_urls:
            self.log.warning("No live HTTP services found.")
            return result

        # Step 3: Katana — JS-Aware Crawling cho các live URLs
        katana_plugin = PluginRegistry.get("Katana")
        raw_crawled = []
        if katana_plugin and katana_plugin.check_installed():
            from config import Config as _CfgAD
            katana_limit = _CfgAD.KATANA_MAX_URLS.get("asset-discovery", _CfgAD.KATANA_MAX_URLS.get("web-vuln", 30))
            katana_endpoint_candidates = []
            katana_secret_candidates = []
            
            unique_live_urls = []
            seen_hosts = set()
            for url in sorted(live_urls, key=lambda u: 0 if u.startswith("https") else 1):
                try:
                    parsed = urlparse(url)
                    host = parsed.netloc.lower()
                    if host not in seen_hosts:
                        seen_hosts.add(host)
                        unique_live_urls.append(url)
                except Exception:
                    continue
            
            self.log.info(f"Katana JS-aware crawling {min(len(unique_live_urls), katana_limit)} unique URLs (depth=3)...")
            for url in unique_live_urls[:katana_limit]:
                katana_dir = self._raw_tool_dir("katana", "asset_discovery", url)
                jsonl_file = os.path.join(katana_dir, "katana_output.jsonl")

                crawl_data = await loop.run_in_executor(
                    self._plugin_executor,
                    partial(self._run_katana, katana_plugin, url, katana_dir, depth=3, js_crawl=True, headless=False, proxy_mode="recon"),
                )

                if not (os.path.exists(jsonl_file) and os.path.getsize(jsonl_file) > 0):
                    self.log.warning(f"  [Katana] 0-byte output for {url}, retrying with depth=5 headless...")
                    crawl_data = await loop.run_in_executor(
                        self._plugin_executor,
                        partial(self._run_katana, katana_plugin, url, katana_dir, depth=5, js_crawl=True, headless=True, proxy_mode="recon"),
                    )

                if isinstance(crawl_data, dict):
                    self._append_crawl_output(
                        crawl_data,
                        raw_crawled,
                        api_like_urls=katana_endpoint_candidates,
                        js_files=result["js_files"],
                        js_secrets=katana_secret_candidates,
                    )
                elif os.path.exists(jsonl_file) and os.path.getsize(jsonl_file) > 0:
                    parsed_file = os.path.join(katana_dir, "katana_parsed.json")
                    if os.path.exists(parsed_file):
                        try:
                            with open(parsed_file, "r") as f:
                                parsed_crawl = json.load(f)
                            self._append_crawl_output(
                                parsed_crawl,
                                raw_crawled,
                                api_like_urls=katana_endpoint_candidates,
                                js_files=result["js_files"],
                                js_secrets=katana_secret_candidates,
                            )
                        except (OSError, json.JSONDecodeError) as exc:
                            self.log.warning(f"  [Katana] Failed to merge parsed output for {url}: {exc}")
                    else:
                        try:
                            with open(jsonl_file, "r") as f:
                                for line in f:
                                    line = line.strip()
                                    if not line:
                                        continue
                                    self._append_crawl_output(
                                        json.loads(line),
                                        raw_crawled,
                                        api_like_urls=katana_endpoint_candidates,
                                        js_files=result["js_files"],
                                        js_secrets=katana_secret_candidates,
                                    )
                        except (OSError, json.JSONDecodeError) as exc:
                            self.log.warning(f"  [Katana] Failed to merge raw output for {url}: {exc}")
                else:
                    self.log.warning(f"  [Katana] No valid output for {url} after retry (skipped)")

            result["js_files"] = list(set(result["js_files"]))

            js_files_to_download = result["js_files"]
            if js_files_to_download:
                js_download_dir = os.path.join(self.raw, "js_downloads")
                os.makedirs(js_download_dir, exist_ok=True)
                self.log.info(f"[Katana] Downloading {len(js_files_to_download)} discovered JS files to raw/js_downloads...")
                
                async def download_js(js_url, session, mapping):
                    try:
                        js_hash = hashlib.md5(js_url.encode()).hexdigest()[:12]
                        js_file_path = os.path.join(js_download_dir, f"{js_hash}.js")
                        
                        if os.path.exists(js_file_path):
                            mapping[js_url] = f"js_downloads/{js_hash}.js"
                            return

                        async with session.get(js_url, ssl=False, timeout=15) as resp:
                            if resp.status == 200:
                                js_content = await resp.read()
                                with open(js_file_path, "wb") as js_out:
                                    js_out.write(js_content)
                                mapping[js_url] = f"js_downloads/{js_hash}.js"
                    except Exception:
                        pass

                js_mapping = {}
                async with aiohttp.ClientSession(headers=self._get_auth_headers()) as session:
                    tasks = [download_js(url, session, js_mapping) for url in js_files_to_download[:50]]
                    await asyncio.gather(*tasks, return_exceptions=True)
                
                with open(os.path.join(js_download_dir, "mapping.json"), "w") as map_f:
                    json.dump(js_mapping, map_f, indent=4)
                downloaded_count = len(js_mapping)
                if downloaded_count:
                    self.log.success(
                        f"[Katana] Downloaded {downloaded_count}/{len(js_files_to_download)} JS files to {js_download_dir}"
                    )
                else:
                    self.log.warning(
                        f"[Katana] JS URLs discovered, but no JS bodies were downloaded to {js_download_dir}"
                    )

            base_urls, param_urls = URLDeduplicator.deduplicate_with_params(raw_crawled)
            result["web_urls"] = base_urls
            result["web_urls_with_params"] = param_urls
            result["api_endpoints"] = self._normalize_api_endpoints(
                katana_endpoint_candidates + param_urls,
                source="katana"
            )
            result["js_secrets"] = list({json.dumps(item, sort_keys=True): item for item in katana_secret_candidates if isinstance(item, dict)}.values())
            result["secrets"] = list(result["js_secrets"])
            self.log.success(f"Katana: {len(base_urls)} base + {len(param_urls)} parameterized URLs.")

            discovered_subs = set()
            for url in raw_crawled:
                try:
                    parsed = urlparse(url)
                    host = parsed.netloc.lower().split(":")[0]
                    if host.endswith(target) and host != target:
                        discovered_subs.add(host)
                except Exception:
                    continue

            new_discovered = discovered_subs - set(result.get("subdomains", []))
            if new_discovered:
                self.log.success(f"[Feedback-Loop] Detected {len(new_discovered)} new subdomains from JS/HTML crawling: {', '.join(new_discovered)}")
                result["subdomains"] = list(set(result.get("subdomains", [])).union(new_discovered))

            lf_plugin = PluginRegistry.get("LinkFinder")
            if lf_plugin and result.get("js_files"):
                self.log.info(f"[LinkFinder] Analyzing {len(result['js_files'])} JavaScript files for endpoints & secrets in ASSET-DISCOVERY...")
                lf_dir = os.path.join(self.raw, "linkfinder_asset_discovery")
                lf_results = await loop.run_in_executor(
                    self._plugin_executor, lf_plugin.run, result["js_files"], lf_dir, 15, 50
                )
                
                merged_secrets = result.get("js_secrets", []) + lf_results.get("secrets", [])
                result["js_secrets"] = list({
                    json.dumps(item, sort_keys=True): item
                    for item in merged_secrets
                    if isinstance(item, dict)
                }.values())
                result["secrets"] = list(result["js_secrets"])
                
                result["api_endpoints"] = self._normalize_api_endpoints(
                    result.get("api_endpoints", []) + lf_results.get("endpoints", []),
                    source="linkfinder"
                )
                
                self.log.success(
                    f"[LinkFinder] Found {len(lf_results.get('endpoints', []))} endpoints "
                    f"and {len(result['js_secrets'])} secrets inside JS assets!"
                )

        # Step 4: Nuclei — Targeted scan
        nuclei_targets = URLDeduplicator.deduplicate([r["url"] for r in httpx_results if r.get("status_code") == 200])
        param_urls_extra = result.get("web_urls_with_params", [])
        if param_urls_extra:
            nuclei_targets.extend(param_urls_extra[:50])
            nuclei_targets = URLDeduplicator.deduplicate(nuclei_targets)

        tags_to_scan = ["exposed-tokens", "javascript", "api", "token", "exposure", "misconfig"]
        any_restricted = any(r.get("status_code") in [401, 403] for r in httpx_results)
        if any_restricted:
            tags_to_scan.append("default-login")
            self.log.info("[Nuclei] Target restricted (401/403) — Adding 'default-login' to scan scope.")

        self.log.info(f"Nuclei scanning {len(nuclei_targets)} targets (tags: {', '.join(tags_to_scan)})...")
        import uuid
        batch_id = str(uuid.uuid4())[:8]
        nuclei_dir = os.path.join(self.raw, f"nuclei_asset_discovery_{batch_id}")
        nuclei_results = await self._nuclei_batch_with_retry(
            nuclei_targets, nuclei_dir,
            tags=tags_to_scan,
            severity=["critical", "high", "medium"],
            mode="asset-discovery", headers=self._get_auth_headers()
        )
        result["nuclei_findings"] = nuclei_results
        self.log.success(f"Nuclei found {len(nuclei_results)} findings.")

        # Step 5: Deep OSINT
        email_plugin = PluginRegistry.get("EmailFinder")
        if self.use_emailfinder and email_plugin:
            self.log.info(f"EmailFinder harvesting emails for {target}...")
            email_dir = os.path.join(self.raw, "emailfinder")
            try:
                email_results = await loop.run_in_executor(self._plugin_executor, email_plugin.run, target, email_dir)
                if email_results and email_results.get("emails"):
                    result["emails"] = email_results["emails"]
                    self.log.success(f"EmailFinder: {len(result['emails'])} emails found.")
            except Exception as e:
                self.log.debug(f"EmailFinder failed: {e}")

        metagoofil_plugin = PluginRegistry.get("Metagoofil")
        doc_exts = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"]
        doc_urls = [u for u in raw_crawled if any(u.lower().endswith(ext) for ext in doc_exts)]
        if self.use_metagoofil and metagoofil_plugin and doc_urls:
            self.log.info(f"Metagoofil analyzing {len(doc_urls)} documents for metadata...")
            mg_dir = os.path.join(self.raw, "metagoofil")
            try:
                mg_results = await loop.run_in_executor(self._plugin_executor, metagoofil_plugin.run, target, mg_dir)
                result["metadata"] = mg_results
                self.log.success(f"Metagoofil: {mg_results.get('total_findings', 0)} metadata entries found.")
            except Exception as e:
                self.log.debug(f"Metagoofil failed: {e}")

        result = self._finalize_scan_contracts(result, target, "asset-discovery")

        result["summary"] = {
            "mode": "asset-discovery",
            "subdomains": len(result.get("subdomains", [])),
            "live_urls": len(live_urls),
            "api_endpoints": len(result.get("api_endpoints", [])),
            "js_files": len(result.get("js_files", [])),
            "secrets": len(result.get("secrets", result.get("js_secrets", []))),
            "nuclei_findings": len(result.get("nuclei_findings", [])),
        }

        self.log.phase("ASSET-DISCOVERY SUMMARY")
        self.log.info(f"  🌐 Subdomains: {result['summary']['subdomains']}")
        self.log.info(f"  ✅ Live URLs: {result['summary']['live_urls']}")
        self.log.info(f"  📡 API Endpoints: {result['summary']['api_endpoints']}")
        self.log.info(f"  📜 JS Files: {result['summary']['js_files']}")
        self.log.info(f"  🔑 Secrets: {result['summary']['secrets']}")
        self.log.info(f"  🔍 Nuclei: {result['summary']['nuclei_findings']} findings")

        return result
