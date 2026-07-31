#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mode and context aware strategy hints for scanner plugins."""

from __future__ import annotations

from typing import Any


TECHNIQUE_TO_NUCLEI_TAGS = {
    "API": {"api"},
    "AUTHZ": {"auth-bypass", "exposure"},
    "CACHE": {"cache", "cache-poisoning"},
    "CLOUD": {"cloud", "metadata"},
    "CORS": {"cors"},
    "GRAPHQL": {"graphql"},
    "HEADER": {"header", "crlf"},
    "JWT": {"jwt"},
    "OAUTH": {"oauth"},
    "REDIRECT": {"redirect"},
    "SSRF": {"ssrf"},
    "SQLI": {"sqli"},
    "WP": {"wordpress", "wp-plugin"},
    "XSS": {"xss"},
}


def build_strategy_profile(
    *,
    mode: str,
    tool: str,
    waf_detected: bool = False,
    tech_stack: list[str] | None = None,
    parameterized_count: int = 0,
    knowledge_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tool_name = str(tool).lower()
    tech = {str(item).lower() for item in tech_stack or []}
    knowledge_summary: dict[str, Any] = {}
    if knowledge_profile:
        try:
            from core.knowledge_base import summarize_knowledge_for_strategy
            knowledge_summary = summarize_knowledge_for_strategy(knowledge_profile)
        except Exception:
            knowledge_summary = {}
    technique_codes = {str(code).upper() for code in knowledge_summary.get("technique_codes", []) or []}
    profile: dict[str, Any] = {
        "mode": mode,
        "tool": tool_name,
        "proxy_mode": "exploit" if waf_detected and tool_name in {"dalfox", "sqlmap", "corsy", "nuclei"} else "fuzz",
        "rate_profile": "low" if waf_detected or mode == "stealth" else "normal",
        "tags": [],
        "templates": [],
        "reasons": [],
        "knowledge_first_tests": knowledge_summary.get("first_tests", []) or [],
        "knowledge_frameworks": knowledge_summary.get("frameworks", []) or [],
    }

    if tool_name == "nuclei":
        tags = {"cve", "misconfig", "exposure"}
        tags.update(knowledge_summary.get("nuclei_tags", []) or [])
        for technique in technique_codes:
            tags.update(TECHNIQUE_TO_NUCLEI_TAGS.get(technique, set()))
        if "wordpress" in tech:
            tags.update({"wordpress", "wp-plugin"})
            profile["reasons"].append("wordpress tech detected")
        if {"next.js", "nextjs", "_next"} & tech:
            tags.update({"ssrf", "exposure", "misconfig"})
            profile["reasons"].append("nextjs operator card")
        if {"spring boot", "spring", "actuator"} & tech:
            tags.update({"springboot", "exposure", "misconfig"})
            profile["reasons"].append("spring boot operator card")
        if {"laravel"} & tech:
            tags.update({"laravel", "exposure", "misconfig"})
            profile["reasons"].append("laravel operator card")
        if {"django", "drf"} & tech:
            tags.update({"django", "exposure", "misconfig"})
            profile["reasons"].append("django operator card")
        if {"kubernetes", "k8s", "docker"} & tech or mode in {"cloud-native", "cloud-devops"}:
            tags.update({"cloud", "k8s", "devops"})
            profile["reasons"].append("cloud/devops context")
        if parameterized_count:
            tags.update({"sqli", "xss", "ssrf", "redirect"})
            profile["reasons"].append("parameterized endpoints available")
        if technique_codes:
            profile["reasons"].append("knowledge-base technique mapping")
        profile["tags"] = sorted(tags)

    elif tool_name == "sqlmap":
        profile["risk"] = 1 if waf_detected else 2
        profile["level"] = 1 if waf_detected else 2
        profile["tamper"] = ["between", "randomcase", "space2comment"] if waf_detected else ["space2comment"]
        profile["reasons"].append("detect-only profile")
        if "SQLI" in technique_codes or parameterized_count:
            profile["candidate_params"] = "prioritize_parameterized_endpoints"
            profile["reasons"].append("knowledge-base SQLi/API mapping")

    elif tool_name == "dalfox":
        profile["deep_domxss"] = mode in {"web-vuln", "api-bounty"} and parameterized_count > 10
        profile["reasons"].append("parameterized URL count drives XSS scope")
        if "XSS" in technique_codes:
            profile["blind_xss_followup"] = "manual_oob_callback_mapping"
            profile["reasons"].append("knowledge-base XSS mapping")

    elif tool_name == "wpscan":
        profile["enumerate"] = "vp,vt,u" if "wordpress" in tech else "vp,vt"
        profile["reasons"].append("wordpress-only scanner")
        if "WP" in technique_codes:
            profile["reasons"].append("knowledge-base WordPress mapping")

    elif tool_name == "nmap":
        profile["timing"] = "T2" if waf_detected or mode == "stealth" else ("T4" if mode in {"full-audit", "infra-smash"} else "T3")
        profile["scripts"] = "vuln" if mode in {"full-audit", "infra-smash"} else "version"
        if {"CLOUD", "FRAMEWORK"} & technique_codes:
            profile["reasons"].append("knowledge-base service triage mapping")

    return profile


def build_strategy_matrix(mode: str, context: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        tool: build_strategy_profile(
            mode=mode,
            tool=tool,
            waf_detected=bool(context.get("waf_detected")),
            tech_stack=context.get("tech_stack", []),
            parameterized_count=int(context.get("parameterized_count", 0) or 0),
            knowledge_profile=context.get("knowledge_profile", {}),
        )
        for tool in ("nuclei", "sqlmap", "dalfox", "wpscan", "nmap")
    }


def merge_nuclei_tags(base_tags: list[str] | None, strategy: dict[str, Any] | None) -> list[str]:
    tags = set(base_tags or [])
    tags.update((strategy or {}).get("tags", []) or [])
    return sorted(tags)
