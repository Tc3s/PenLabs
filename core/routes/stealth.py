#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Stealth Route Handler
================================
Zero-Touch OSINT & Data Mining mode.
"""

import asyncio
from core.routes.base_route import BaseRoute
from utils.passive_data_miner import PassiveDataMiner


class StealthRoute(BaseRoute):
    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        self.log.phase("STEALTH MODE — Zero-Touch OSINT & Data Mining")
        result = {
            "ports": [], "nse_cves": [], "nuclei_findings": [], "web_urls": [],
            "cloud_findings": {}, "os_detection": [], "subdomains": [],
            "dns_records": {}, "tech_stack": []
        }

        miner = PassiveDataMiner(self.log)

        # Parallel passive data mining via asyncio.gather
        mining_results = await asyncio.gather(
            miner.get_hackertarget(target),
            miner.get_crtsh(target),
            miner.get_wayback_tech(target),
            return_exceptions=True
        )

        ht_data = mining_results[0] if isinstance(mining_results[0], list) else []
        crtsh_subs = mining_results[1] if isinstance(mining_results[1], list) else []
        tech_stack = mining_results[2] if isinstance(mining_results[2], list) else []

        for item in ht_data:
            if isinstance(item, dict):
                sub = item.get("subdomain")
                ip_val = item.get("ip")
                if sub:
                    result["subdomains"].append(sub)
                    if ip_val and ip_val != "127.0.0.1":
                        if sub not in result["dns_records"]:
                            result["dns_records"][sub] = {"a": [ip_val]}

        result["subdomains"].extend(crtsh_subs)
        result["subdomains"] = list(set(result["subdomains"]))
        result["tech_stack"] = tech_stack

        self.log.success(f"Zero-Touch: Found {len(result['subdomains'])} subdomains concurrently.")
        if tech_stack:
            self.log.success(f"Zero-Touch: Detected technologies: {', '.join(tech_stack)}")

        self.log.info("Stealth mode completed. No active packets were sent to the target.")
        return result
