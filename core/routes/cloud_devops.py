#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Cloud DevOps Route Handler
====================================
Cloud Infrastructure & CI/CD Audit.
"""

import asyncio
import os
import shutil

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry


class CloudDevopsRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("CLOUD-DEVOPS MODE — Cloud Infrastructure Audit")
        result = {"ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [], "cloud_findings": {}, "os_detection": [], "dns_records": {}}
        loop = asyncio.get_running_loop()

        subdomains = []
        if shutil.which("subfinder"):
            self.log.info(f"Subfinder enumerating subdomains for {target}...")
            try:
                proc = await asyncio.create_subprocess_exec(
                    "subfinder", "-d", target, "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
                subdomains = [s.strip() for s in stdout.decode('utf-8', errors='ignore').splitlines() if s.strip()]
                self.log.success(f"Subfinder found {len(subdomains)} subdomains.")
            except Exception as e:
                self.log.warning(f"Subfinder failed: {e}")

        cloud_plugin = PluginRegistry.get("CloudDevOps")
        if cloud_plugin:
            self.log.info("Running Cloud/DevOps recon (S3 buckets, takeover, DevOps exposure)...")
            cloud_dir = os.path.join(self.raw, "cloud")
            cloud_data = await loop.run_in_executor(
                self._plugin_executor, cloud_plugin.run, target, ip, cloud_dir
            )

            if subdomains and hasattr(cloud_plugin, '_check_subdomain_takeover'):
                self.log.info(f"Checking {len(subdomains)} subdomains for takeover...")
                existing_takeovers = cloud_data.get("takeover_candidates", [])
                for sub in subdomains:
                    try:
                        sub_takeovers = cloud_plugin._check_subdomain_takeover(sub)
                        existing_takeovers.extend(sub_takeovers)
                    except Exception:
                        continue
                cloud_data["takeover_candidates"] = existing_takeovers

            result["cloud_findings"] = cloud_data

            buckets = cloud_data.get("bucket_findings", [])
            takeovers = cloud_data.get("takeover_candidates", [])
            devops = cloud_data.get("devops_exposed", [])
            nuclei_cloud = cloud_data.get("nuclei_cloud", [])

            if buckets:
                self.log.success(f"Found {len(buckets)} cloud buckets!")
                for b in buckets:
                    self.log.info(f"  → [{b['provider']}] {b['bucket']} — {b['status']} ({b['severity']})")
            if takeovers:
                self.log.success(f"Found {len(takeovers)} subdomain takeover candidates!")
                for t in takeovers:
                    self.log.info(f"  → {t['subdomain']} CNAME→ {t['cname']} ({t['service']}) — {t['status']}")
            if devops:
                self.log.success(f"Found {len(devops)} exposed DevOps ports!")
                for d in devops:
                    self.log.info(f"  → Port {d['port']}: {d['service']} ({d['severity']})")
            if nuclei_cloud:
                self.log.success(f"Nuclei cloud templates found {len(nuclei_cloud)} issues!")

            for d in devops:
                result["ports"].append({
                    "port": d["port"],
                    "service": d["service"],
                    "version": "",
                    "confidence": 1.0,
                })

        nuclei_plugin = PluginRegistry.get("Nuclei")
        if nuclei_plugin and nuclei_plugin.check_installed():
            cloud_tags = ["cloud", "aws", "azure", "gcp", "kubernetes", "docker",
                          "ci", "devops", "misconfig", "exposure", "takeover"]
            self.log.info("Nuclei cloud/DevOps template scan...")
            nuclei_dir = os.path.join(self.raw, "nuclei_cloud")
            cloud_targets = [f"https://{target}", f"http://{target}"]
            for sub in subdomains[:20]:
                cloud_targets.append(f"https://{sub}")
            nuclei_results = await self._nuclei_batch_with_retry(
                cloud_targets, nuclei_dir, tags=cloud_tags,
                severity=["critical", "high", "medium"],
                mode="cloud-devops", headers=self._get_auth_headers()
            )
            result["nuclei_findings"] = nuclei_results
            if nuclei_results:
                self.log.success(f"Nuclei cloud: {len(nuclei_results)} issues found!")

        httpx_plugin = PluginRegistry.get("Httpx")
        devops_ports = [p["port"] for p in result.get("ports", []) if p.get("service") in
                        ["jenkins", "gitlab", "grafana", "prometheus", "kibana", "docker", "kubernetes"]]
        if httpx_plugin and httpx_plugin.check_installed() and devops_ports:
            self.log.info(f"httpx probing {len(devops_ports)} DevOps ports for exposed dashboards...")
            httpx_dir = os.path.join(self.raw, "httpx_devops")
            httpx_results = await loop.run_in_executor(
                self._plugin_executor, httpx_plugin.probe_from_ports, ip, devops_ports, httpx_dir, self._get_auth_headers(), self.proxy_file
            )
            for r in httpx_results:
                if r.get("url"):
                    result["web_urls"].append(r["url"])
            self.log.success(f"httpx: {len(result['web_urls'])} live DevOps dashboards found.")

        if shutil.which("ffuf") and result.get("web_urls"):
            cicd_paths = [
                ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml",
                ".travis.yml", "docker-compose.yml", "Dockerfile", ".dockerignore",
                "kubernetes", "k8s", "helm", ".env", ".env.production", ".env.staging",
                "terraform", "terraform.tfstate", ".terraform", "ansible",
                "vault/config", "consul", ".kube/config",
            ]
            ffuf_dir = os.path.join(self.raw, "ffuf_cicd")
            os.makedirs(ffuf_dir, exist_ok=True)
            cicd_wordlist = os.path.join(ffuf_dir, "cicd_paths.txt")
            with open(cicd_wordlist, 'w') as f:
                f.write("\n".join(cicd_paths))
            ffuf_results = await self._run_ffuf_many(
                result["web_urls"],
                ffuf_dir,
                headers=self._get_auth_headers(),
                purpose="cicd_paths",
                wordlist=cicd_wordlist,
                limit=3,
            )
            if ffuf_results:
                self.log.success(f"ffuf CI/CD: {len(ffuf_results)} exposed CI/CD paths.")
                result["web_urls"].extend(ffuf_results)

        return result
