#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Passive Data Miner (Single Source of Truth)
=====================================================
Centralized passive OSINT data collection via public APIs.
Previously duplicated in scanner_router.py and Module1_Recon.py.
"""

import logging

import aiohttp

logger = logging.getLogger(__name__)


class PassiveDataMiner:
    def __init__(self, log=None):
        self.log = log or logger

    async def get_hackertarget(self, domain: str) -> list:
        self.log.info(f"PassiveMining [HackerTarget] cho {domain}...")
        results = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        for line in text.splitlines():
                            if "," in line:
                                parts = line.split(",")
                                if len(parts) == 2:
                                    results.append({"subdomain": parts[0].strip(), "ip": parts[1].strip()})
        except Exception as e:
            self.log.warning(f"HackerTarget lỗi: {e}")
        return results

    async def get_crtsh(self, domain: str) -> list:
        self.log.info(f"PassiveMining [crt.sh] cho {domain}...")
        subdomains = set()
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%25.{domain}&output=json"
                async with session.get(url, timeout=30) as resp:
                    if resp.status == 200:
                        try:
                            data = await resp.json()
                            for entry in data:
                                name = entry.get("name_value", "")
                                for n in name.split("\n"):
                                    n = n.strip().replace("*.", "")
                                    if n:
                                        subdomains.add(n)
                        except (ValueError, KeyError) as e:
                            logger.debug(f"crt.sh JSON parse error: {e}")
        except Exception as e:
            self.log.warning(f"crt.sh lỗi: {e}")
        return list(subdomains)

    async def get_wayback_tech(self, domain: str) -> list:
        self.log.info(f"PassiveMining [WaybackMachine] cho {domain}...")
        tech_hints = set()
        try:
            async with aiohttp.ClientSession() as session:
                url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=500"
                async with session.get(url, timeout=30) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if "_layouts/15" in text:
                            tech_hints.add("SharePoint")
                        if "wp-content" in text or "wp-includes" in text:
                            tech_hints.add("WordPress")
                        if "owa/auth" in text:
                            tech_hints.add("Exchange OWA")
        except Exception as e:
            self.log.warning(f"WaybackMachine lỗi: {e}")
        return list(tech_hints)
