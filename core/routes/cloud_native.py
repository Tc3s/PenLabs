#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Cloud Native Route Handler
=====================================
Cloud Infrastructure Audit (S3/GCP/Azure + Takeover).
"""

import asyncio
import os
import shutil

from core.routes.base_route import BaseRoute
from core.registry import PluginRegistry


class CloudNativeRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("CLOUD-NATIVE MODE — Cloud Infrastructure Audit (S3/GCP/Azure + Takeover)")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [], "subdomains": [],
        }
        loop = asyncio.get_running_loop()

        # Step 1: Subfinder — enumerate subdomains for takeover checks
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
        result["subdomains"] = subdomains

        # Step 2: Specialized cloud-native plugins — S3, multi-cloud storage, K8s
        result["cloud_findings"].setdefault("s3_scanner", [])
        s3_plugin = PluginRegistry.get("S3Scanner")
        if s3_plugin:
            self.log.info("Running S3Scanner bucket enumeration...")
            try:
                s3_findings = await loop.run_in_executor(self._plugin_executor, s3_plugin.run, target)
                result["cloud_findings"]["s3_scanner"] = s3_findings
                if s3_findings:
                    self.log.success(f"S3Scanner found {len(s3_findings)} buckets.")
            except Exception as e:
                self.log.warning(f"S3Scanner failed: {e}")

        cloud_enum_plugin = PluginRegistry.get("CloudEnum")
        if cloud_enum_plugin and cloud_enum_plugin.check_installed():
            self.log.info(f"CloudEnum scanning {target} for cloud resources...")
            try:
                ce_findings = await loop.run_in_executor(
                    self._plugin_executor, cloud_enum_plugin.run, target, ["aws", "azure", "gcp"], 300
                )
                result["cloud_findings"]["cloud_enum"] = ce_findings
                total_ce = sum(len(v) for v in ce_findings.values() if isinstance(v, list))
                if total_ce:
                    self.log.success(f"CloudEnum found {total_ce} cloud resources.")
            except Exception as e:
                self.log.warning(f"CloudEnum failed: {e}")

        kube_hunter_plugin = PluginRegistry.get("KubeHunter")
        k8s_target = f"https://{ip or target}:6443" if (ip or target) else ""
        if kube_hunter_plugin and kube_hunter_plugin.check_installed() and k8s_target:
            self.log.info(f"KubeHunter remote check against {k8s_target}...")
            try:
                k8s_findings = await loop.run_in_executor(self._plugin_executor, kube_hunter_plugin.run, k8s_target, "remote", 600)
                result["cloud_findings"]["kube_hunter"] = k8s_findings
                k8s_count = len(k8s_findings.get("findings", [])) if isinstance(k8s_findings, dict) else 0
                if k8s_count:
                    self.log.success(f"KubeHunter found {k8s_count} Kubernetes findings.")
            except Exception as e:
                self.log.warning(f"KubeHunter failed: {e}")

        # Step 3: CloudDevOps legacy plugin — takeover, DevOps exposure, Nuclei cloud fallback
        cloud_plugin = PluginRegistry.get("CloudDevOps")
        if cloud_plugin:
            self.log.info("Running Cloud/DevOps recon (S3/GCP/Azure buckets, takeover, DevOps leaks)...")
            cloud_dir = os.path.join(self.raw, "cloud_native")
            cloud_data = await loop.run_in_executor(self._plugin_executor, cloud_plugin.run, target, ip, cloud_dir)

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

            result["cloud_findings"]["cloud_devops"] = cloud_data

            buckets = cloud_data.get("bucket_findings", [])
            takeovers = cloud_data.get("takeover_candidates", [])
            if buckets:
                self.log.success(f"Found {len(buckets)} cloud buckets!")
                for b in buckets:
                    self.log.info(f"  → [{b['provider']}] {b['bucket']} — {b['status']} ({b['severity']})")
            if takeovers:
                self.log.success(f"Found {len(takeovers)} subdomain takeover candidates!")
                for t in takeovers:
                    self.log.info(f"  → {t['subdomain']} CNAME→ {t['cname']} ({t['service']}) — {t['status']}")
        
        # Step 4: Nuclei — Cloud-specific templates
        scan_urls = [f"https://{target}", f"http://{target}"]
        for sub in subdomains[:50]:
            scan_urls.append(f"https://{sub}")
        scan_urls = list(set(scan_urls))

        self.log.info(f"Nuclei scanning {len(scan_urls)} targets (tags: cloud,takeovers,k8s,s3,azure,gcp,misconfiguration)...")
        nuclei_dir = os.path.join(self.raw, "nuclei_cloud_native")
        nuclei_results = await self._nuclei_batch_with_retry(
            scan_urls, nuclei_dir,
            tags=["cloud", "takeovers", "k8s", "s3", "azure", "gcp", "misconfig",
                  "exposure", "default-login", "devops"],
            severity=["critical", "high", "medium"],
            mode="cloud-native", headers=self._get_auth_headers()
        )
        result["nuclei_findings"] = nuclei_results
        self.log.success(f"Nuclei found {len(nuclei_results)} cloud-related findings.")

        return result
