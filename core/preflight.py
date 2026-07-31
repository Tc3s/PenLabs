#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Centralized Preflight Tool Validator
================================================
Runs before scan execution to audit CLI tool dependencies per scan mode.
Prevents runtime crashes due to missing critical tools.
"""

from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from typing import Dict, List

from core.registry import PluginRegistry

logger = logging.getLogger(__name__)


@dataclass
class PreflightReport:
    mode: str
    available_tools: List[str] = field(default_factory=list)
    missing_critical: List[str] = field(default_factory=list)
    missing_important: List[str] = field(default_factory=list)
    missing_optional: List[str] = field(default_factory=list)

    @property
    def is_executable(self) -> bool:
        return len(self.missing_critical) == 0


# Tool requirements per scan mode
MODE_REQUIREMENTS: Dict[str, Dict[str, List[str]]] = {
    "stealth": {
        "critical": [],
        "important": ["subfinder", "httpx"],
        "optional": ["katana", "nuclei"],
    },
    "sniper": {
        "critical": ["nmap"],
        "important": ["httpx", "nuclei"],
        "optional": ["naabu", "gowitness"],
    },
    "fast": {
        "critical": ["nmap"],
        "important": ["httpx"],
        "optional": ["naabu"],
    },
    "web-vuln": {
        "critical": [],
        "important": ["httpx", "katana", "nuclei", "ffuf"],
        "optional": ["dalfox", "sqlmap", "arjun"],
    },
    "cloud-devops": {
        "critical": [],
        "important": ["subfinder", "httpx", "nuclei"],
        "optional": ["cloud-enum", "kube-hunter"],
    },
    "full-audit": {
        "critical": ["nmap"],
        "important": ["httpx", "katana", "nuclei", "ffuf"],
        "optional": ["rustscan", "naabu", "gowitness", "sqlmap", "dalfox"],
    },
    "api-bounty": {
        "critical": [],
        "important": ["httpx", "katana", "nuclei", "ffuf", "kiterunner"],
        "optional": ["arjun", "dalfox", "sqlmap"],
    },
    "api-breach": {
        "critical": [],
        "important": ["subfinder", "httpx", "katana", "nuclei"],
        "optional": ["arjun"],
    },
    "cloud-native": {
        "critical": [],
        "important": ["subfinder", "httpx", "nuclei"],
        "optional": ["cloud-enum", "kube-hunter"],
    },
    "infra-smash": {
        "critical": ["nmap"],
        "important": ["naabu", "httpx", "nuclei"],
        "optional": ["rustscan"],
    },
    "asset-discovery": {
        "critical": [],
        "important": ["subfinder", "httpx", "katana"],
        "optional": ["nuclei"],
    },
}


class PreflightChecker:
    """Audit system dependencies and plugin availability prior to scan launch."""

    def __init__(self, log=None):
        self.log = log or logger

    def check(self, mode: str) -> PreflightReport:
        mode_key = str(mode or "").strip().lower()
        reqs = MODE_REQUIREMENTS.get(mode_key, MODE_REQUIREMENTS.get("sniper", {}))

        report = PreflightReport(mode=mode_key)

        all_tools = (
            set(reqs.get("critical", []))
            | set(reqs.get("important", []))
            | set(reqs.get("optional", []))
        )

        for tool in all_tools:
            is_installed = self._check_tool(tool)
            if is_installed:
                report.available_tools.append(tool)
            else:
                if tool in reqs.get("critical", []):
                    report.missing_critical.append(tool)
                elif tool in reqs.get("important", []):
                    report.missing_important.append(tool)
                else:
                    report.missing_optional.append(tool)

        # Log findings
        if report.missing_critical:
            self.log.error(
                f"[Preflight] CRITICAL MISSING TOOLS for mode '{mode_key}': "
                f"{', '.join(report.missing_critical)}"
            )
        if report.missing_important:
            self.log.warning(
                f"[Preflight] Important missing tools for mode '{mode_key}': "
                f"{', '.join(report.missing_important)}"
            )
        if report.missing_optional:
            self.log.info(
                f"[Preflight] Optional missing tools for mode '{mode_key}': "
                f"{', '.join(report.missing_optional)}"
            )

        if report.is_executable:
            self.log.info(
                f"[Preflight] Passed! ({len(report.available_tools)} tools ready for '{mode_key}')"
            )

        return report

    def _check_tool(self, tool_name: str) -> bool:
        # Check system PATH first
        if shutil.which(tool_name):
            return True

        # Fallback to PluginRegistry check
        # Tool name mapping to plugin registry key
        registry_map = {
            "nmap": "Nmap",
            "nuclei": "Nuclei",
            "httpx": "Httpx",
            "katana": "Katana",
            "ffuf": "Ffuf",
            "naabu": "Naabu",
            "subfinder": "Subfinder",
            "rustscan": "RustScan",
            "gowitness": "Gowitness",
            "dalfox": "Dalfox",
            "sqlmap": "Sqlmap",
            "arjun": "Arjun",
            "kiterunner": "Kiterunner",
            "cloud-enum": "CloudEnum",
            "kube-hunter": "KubeHunter",
        }
        plugin_key = registry_map.get(tool_name.lower())
        if plugin_key:
            plugin = PluginRegistry.get(plugin_key)
            if plugin and hasattr(plugin, "check_installed"):
                return plugin.check_installed()

        return False
