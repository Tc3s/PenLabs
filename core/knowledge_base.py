#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Knowledge-base adapters for strategy, WSTG coverage and manual handoff.

The external knowledge-base is mostly Markdown operator guidance. This module
keeps it as guidance metadata instead of importing raw payload packs into
runtime execution.
"""

from __future__ import annotations

import os
from collections import Counter
from typing import Any


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_KB_ROOTS = [
    os.path.join(REPO_ROOT, "knowledge-base"),
    os.path.join(REPO_ROOT, "data", "knowledge-base"),
    "/home/tcus/Desktop/WEb/wstg-pentest/knowledge-base",
]
DEFAULT_KB_ROOT = DEFAULT_KB_ROOTS[-1]


CATEGORY_KNOWLEDGE: dict[str, dict[str, Any]] = {
    "xss": {
        "techniques": ["XSS", "CLNT"],
        "wstg_refs": ["WSTG-INPV-01", "WSTG-CLNT-01"],
        "guide": "portswigger-academy/cross-site-scripting.md",
        "manual_next": "Confirm sink, context, CSP/cookie impact and whether the payload reaches an authenticated workflow.",
    },
    "blind_xss": {
        "techniques": ["XSS", "OOB"],
        "wstg_refs": ["WSTG-INPV-01", "WSTG-CLNT-01"],
        "guide": "payloads/xss-elite.md",
        "manual_next": "Wait for OOB callbacks, map callback source to role/workflow, then prove privileged data exposure.",
    },
    "sqli": {
        "techniques": ["SQLI"],
        "wstg_refs": ["WSTG-INPV-05"],
        "guide": "portswigger-academy/sql-injection.md",
        "manual_next": "Keep automation in detection mode unless RoE allows deeper extraction; prove impact with minimal queries.",
    },
    "ssrf": {
        "techniques": ["SSRF", "CLOUD", "WEBHOOK"],
        "wstg_refs": ["WSTG-INPV-19"],
        "guide": "portswigger-academy/ssrf.md",
        "manual_next": "Verify outbound reachability and cloud metadata impact only within RoE-approved boundaries.",
    },
    "cors": {
        "techniques": ["CORS"],
        "wstg_refs": ["WSTG-CONF-13"],
        "guide": "portswigger-academy/cors.md",
        "manual_next": "Only escalate when credentialed cross-origin reads expose sensitive authenticated data.",
    },
    "open_redirect": {
        "techniques": ["REDIRECT", "OAUTH"],
        "wstg_refs": ["WSTG-CLNT-04", "WSTG-ATHN-10"],
        "guide": "portswigger-academy/oauth.md",
        "manual_next": "Check OAuth redirect_uri, SSO callback, password reset and invite flows for code/token theft chains.",
    },
    "crlf": {
        "techniques": ["HEADER", "CACHE"],
        "wstg_refs": ["WSTG-INPV-15"],
        "guide": "portswigger-academy/header-injection.md",
        "manual_next": "Confirm response splitting/header injection with a harmless marker and assess cache interaction.",
    },
    "cache_poisoning": {
        "techniques": ["CACHE", "HEADER"],
        "wstg_refs": ["WSTG-CONF-12"],
        "guide": "portswigger-academy/web-cache-poisoning.md",
        "manual_next": "Confirm cache key behavior with a non-destructive cache buster before calling impact.",
    },
    "bypass_403": {
        "techniques": ["AUTHZ", "HEADER"],
        "wstg_refs": ["WSTG-ATHZ-02", "WSTG-ATHZ-04"],
        "guide": "portswigger-academy/access-control.md",
        "manual_next": "Replay baseline vs bypass with the same auth state and prove protected object access.",
    },
    "mass_assignment": {
        "techniques": ["API", "AUTHZ"],
        "wstg_refs": ["WSTG-INPV-20", "WSTG-ATHZ-04"],
        "guide": "payloads/authz-idor-elite.md",
        "manual_next": "Use dual-user context and safe privilege fields to prove unauthorized state change.",
    },
    "bola": {
        "techniques": ["AUTHZ", "TENANT", "API"],
        "wstg_refs": ["WSTG-ATHZ-04", "WSTG-APIT-01"],
        "guide": "payloads/authz-idor-elite.md",
        "manual_next": "Use User A/B and object IDs from real workflows; evidence must show cross-user or cross-tenant data/action.",
    },
    "graphql": {
        "techniques": ["GRAPHQL", "AUTHZ"],
        "wstg_refs": ["WSTG-APIT-01", "WSTG-ATHZ-04"],
        "guide": "portswigger-academy/graphql.md",
        "manual_next": "Check introspection, batching, node IDOR and mutation authorization with dual-user context.",
    },
    "race_condition": {
        "techniques": ["RACE", "BUSLOGIC"],
        "wstg_refs": ["WSTG-BUSL-04"],
        "guide": "portswigger-academy/race-conditions.md",
        "manual_next": "Replay only low-impact workflow steps first; prove duplicate state change before raising severity.",
    },
    "wordpress": {
        "techniques": ["FRAMEWORK", "WP"],
        "wstg_refs": ["WSTG-CONF-05", "WSTG-CONF-10"],
        "guide": "frameworks/wordpress.md",
        "manual_next": "Prioritize plugin/theme exposure and authenticated role impact over raw version banners.",
    },
}


FRAMEWORK_RULES: list[dict[str, Any]] = [
    {
        "name": "Next.js / React SSR",
        "aliases": ["next.js", "nextjs", "_next", "react ssr"],
        "guide": "frameworks/nextjs.md",
        "techniques": ["SPA", "SSRF", "AUTHZ", "API"],
        "nuclei_tags": ["exposure", "misconfig", "ssrf"],
        "first_tests": ["/_next/image", "/_next/static", "middleware routes", "server actions", "source maps"],
    },
    {
        "name": "Spring Boot",
        "aliases": ["spring boot", "spring", "actuator"],
        "guide": "frameworks/spring-boot.md",
        "techniques": ["FRAMEWORK", "INFO", "API"],
        "nuclei_tags": ["springboot", "exposure", "misconfig"],
        "first_tests": ["/actuator", "/actuator/env", "/swagger-ui", "/v3/api-docs"],
    },
    {
        "name": "Laravel",
        "aliases": ["laravel", "php laravel"],
        "guide": "frameworks/laravel.md",
        "techniques": ["FRAMEWORK", "INFO"],
        "nuclei_tags": ["laravel", "exposure", "misconfig"],
        "first_tests": ["/.env", "/telescope", "ignition debug", "debug headers"],
    },
    {
        "name": "Django / DRF",
        "aliases": ["django", "django rest framework", "drf"],
        "guide": "frameworks/django.md",
        "techniques": ["API", "AUTHZ", "FRAMEWORK"],
        "nuclei_tags": ["django", "exposure", "misconfig"],
        "first_tests": ["/admin", "browsable API", "mass assignment", "CSRF/authz checks"],
    },
    {
        "name": "Express / Node",
        "aliases": ["express", "node.js", "nodejs", "nestjs", "nest.js"],
        "guide": "frameworks/express-node.md",
        "techniques": ["PROTO", "JWT", "API"],
        "nuclei_tags": ["nodejs", "exposure", "misconfig"],
        "first_tests": ["prototype pollution", "JWT handling", "mass assignment", "debug endpoints"],
    },
    {
        "name": "WordPress",
        "aliases": ["wordpress", "wp-content", "wp-includes"],
        "guide": "frameworks/wordpress.md",
        "techniques": ["FRAMEWORK", "WP"],
        "nuclei_tags": ["wordpress", "wp-plugin"],
        "first_tests": ["/wp-json/wp/v2/users", "/xmlrpc.php", "plugin/theme nuclei", "wpscan enumerate"],
    },
    {
        "name": "GraphQL",
        "aliases": ["graphql", "apollo", "graphene"],
        "guide": "portswigger-academy/graphql.md",
        "techniques": ["GRAPHQL", "AUTHZ", "API"],
        "nuclei_tags": ["graphql", "exposure"],
        "first_tests": ["introspection", "batching", "node IDOR", "mutation authz"],
    },
]


def knowledge_root() -> str:
    env_root = os.getenv("PENLABS_KNOWLEDGE_BASE", "").strip()
    if env_root:
        return env_root
    for candidate in DEFAULT_KB_ROOTS:
        if os.path.isdir(candidate):
            return candidate
    return DEFAULT_KB_ROOT


def _guide_path(relative_path: str, kb_root: str | None = None) -> str:
    root = kb_root or knowledge_root()
    path = os.path.join(root, relative_path)
    return path if os.path.exists(path) else relative_path


def _list_value(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value or "").strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    return [part.strip().strip("'\"") for part in text.split(",") if part.strip().strip("'\"")]


def _parse_frontmatter(path: str) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            if handle.readline().strip() != "---":
                return meta
            for line in handle:
                stripped = line.strip()
                if stripped == "---":
                    break
                if ":" not in stripped:
                    continue
                key, value = stripped.split(":", 1)
                key = key.strip()
                value = value.strip()
                meta[key] = _list_value(value) if value.startswith("[") else value
    except OSError:
        return {}
    return meta


def load_wstg_cards(kb_root: str | None = None) -> list[dict[str, Any]]:
    root = kb_root or knowledge_root()
    wstg_root = os.path.join(root, "web-security-testing-guide")
    cards: list[dict[str, Any]] = []
    if not os.path.isdir(wstg_root):
        return cards
    for dirpath, _, filenames in os.walk(wstg_root):
        for filename in filenames:
            if not filename.endswith(".md"):
                continue
            path = os.path.join(dirpath, filename)
            meta = _parse_frontmatter(path)
            if not meta.get("id"):
                continue
            meta["path"] = path
            meta["tools"] = _list_value(meta.get("tools"))
            meta["wstg_refs"] = _list_value(meta.get("wstg_refs"))
            cards.append(meta)
    return sorted(cards, key=lambda item: str(item.get("id", "")))


def load_crosswalk_entries(kb_root: str | None = None) -> list[dict[str, Any]]:
    root = kb_root or knowledge_root()
    path = os.path.join(root, "CROSSWALK.md")
    entries: list[dict[str, Any]] = []
    if not os.path.exists(path):
        return entries
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped.startswith("| WSTG-"):
                    continue
                cells = [cell.strip() for cell in stripped.strip("|").split("|")]
                if len(cells) < 4:
                    continue
                wstg_id, focus, techniques, tools = cells[:4]
                entries.append({
                    "wstg_id": wstg_id,
                    "focus": focus,
                    "technique_codes": [code.strip() for code in techniques.replace("—", "").split(",") if code.strip()],
                    "tools": [tool.strip() for tool in tools.split(",") if tool.strip()],
                })
    except OSError:
        return []
    return entries


def framework_hints_for_tech(tech_stack: list[str] | None, kb_root: str | None = None) -> list[dict[str, Any]]:
    tech_text = " ".join(str(item).lower() for item in tech_stack or [])
    hints: list[dict[str, Any]] = []
    for rule in FRAMEWORK_RULES:
        if any(alias in tech_text for alias in rule["aliases"]):
            hints.append({
                "framework": rule["name"],
                "guide": _guide_path(rule["guide"], kb_root),
                "technique_codes": list(rule["techniques"]),
                "nuclei_tags": list(rule["nuclei_tags"]),
                "first_tests": list(rule["first_tests"]),
            })
    return hints


def _finding_categories(result: dict[str, Any]) -> list[str]:
    categories: list[str] = []
    for finding in result.get("dast_findings", []) or []:
        if isinstance(finding, dict) and finding.get("category"):
            categories.append(str(finding["category"]).lower())
    if result.get("nuclei_findings"):
        categories.append("nuclei")
    return categories


def _endpoint_urls(result: dict[str, Any]) -> list[str]:
    urls: list[str] = []
    for key in ("web_urls", "web_urls_with_params", "api_endpoints", "endpoint_store"):
        for entry in result.get(key, []) or []:
            if isinstance(entry, str):
                urls.append(entry)
            elif isinstance(entry, dict) and entry.get("url"):
                urls.append(str(entry["url"]))
    return urls


def enrich_dast_findings_with_knowledge(findings: list[dict[str, Any]], kb_root: str | None = None) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        item = dict(finding)
        category = str(item.get("category", "")).lower()
        knowledge = CATEGORY_KNOWLEDGE.get(category)
        if knowledge:
            item["technique_codes"] = sorted(set(item.get("technique_codes", []) or []) | set(knowledge["techniques"]))
            item["wstg_refs"] = sorted(set(item.get("wstg_refs", []) or []) | set(knowledge["wstg_refs"]))
            item["guide_path"] = item.get("guide_path") or _guide_path(knowledge["guide"], kb_root)
            item["manual_next"] = item.get("manual_next") or knowledge["manual_next"]
            tags = set(item.get("tags", []) or [])
            tags.update(code.lower().replace("_", "-") for code in knowledge["techniques"])
            item["tags"] = sorted(tags)
        enriched.append(item)
    return enriched


def build_wstg_coverage(result: dict[str, Any], kb_root: str | None = None) -> dict[str, Any]:
    categories = set(_finding_categories(result))
    covered_refs: set[str] = set()
    techniques: set[str] = set()
    category_counts = Counter(_finding_categories(result))

    for category in categories:
        knowledge = CATEGORY_KNOWLEDGE.get(category)
        if not knowledge:
            continue
        covered_refs.update(knowledge["wstg_refs"])
        techniques.update(knowledge["techniques"])

    framework_hints = framework_hints_for_tech(result.get("tech_stack", []), kb_root)
    crosswalk_entries = load_crosswalk_entries(kb_root)
    crosswalk_by_id = {entry["wstg_id"]: entry for entry in crosswalk_entries}
    for hint in framework_hints:
        techniques.update(hint.get("technique_codes", []))

    endpoints = _endpoint_urls(result)
    has_api = bool(result.get("api_endpoints")) or any("/api/" in url.lower() for url in endpoints)
    parameterized = [url for url in endpoints if "?" in url]
    url_params = " ".join(parameterized).lower()

    manual_gaps: list[dict[str, Any]] = []
    def add_gap(wstg_id: str, title: str, reason: str, techniques_: list[str], guide: str) -> None:
        if wstg_id in covered_refs:
            return
        crosswalk = crosswalk_by_id.get(wstg_id, {})
        manual_gaps.append({
            "wstg_id": wstg_id,
            "title": title,
            "reason": reason,
            "technique_codes": sorted(set(techniques_) | set(crosswalk.get("technique_codes", []) or [])),
            "tools": crosswalk.get("tools", []),
            "guide": _guide_path(guide, kb_root),
        })

    if has_api:
        add_gap("WSTG-ATHZ-04", "BOLA/IDOR dual-user authorization", "API surface exists but no BOLA finding was confirmed.", ["AUTHZ", "TENANT", "API"], "payloads/authz-idor-elite.md")
        add_gap("WSTG-INPV-20", "Mass assignment checks", "API surface exists and privilege fields need dual-user validation.", ["API", "AUTHZ"], "payloads/authz-idor-elite.md")
    if any(token in url_params for token in ("url=", "uri=", "next=", "redirect=", "callback=", "webhook=")):
        add_gap("WSTG-INPV-19", "SSRF/redirect sink validation", "Parameterized URL-like inputs were discovered.", ["SSRF", "REDIRECT"], "portswigger-academy/ssrf.md")
    if framework_hints:
        add_gap("WSTG-INFO-08", "Framework-specific fingerprint follow-up", "Detected stack has framework operator cards.", ["FRAMEWORK"], "real-world/tech-stack-matrix.md")

    return {
        "kb_root": kb_root or knowledge_root(),
        "kb_available": os.path.isdir(kb_root or knowledge_root()),
        "crosswalk_entries": len(crosswalk_entries),
        "wstg_cards": len(load_wstg_cards(kb_root)),
        "covered_wstg_refs": sorted(covered_refs),
        "technique_codes": sorted(techniques),
        "category_counts": dict(sorted(category_counts.items())),
        "manual_gaps": manual_gaps[:20],
        "framework_hints": framework_hints,
    }


def build_manual_handoff(result: dict[str, Any], kb_root: str | None = None) -> list[dict[str, Any]]:
    handoff: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for finding in result.get("dast_findings", []) or []:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("verification_status", "")).lower()
        category = str(finding.get("category", "")).lower()
        if status not in {"suspected", "manual_review"} and category not in {"bola", "mass_assignment", "blind_xss", "ssrf"}:
            continue
        knowledge = CATEGORY_KNOWLEDGE.get(category)
        if not knowledge:
            continue
        key = (category, str(finding.get("url", "")), status)
        if key in seen:
            continue
        seen.add(key)
        handoff.append({
            "category": category,
            "status": status or "manual_review",
            "url": finding.get("url", finding.get("matched_at", "")),
            "guide": _guide_path(knowledge["guide"], kb_root),
            "next_step": finding.get("manual_next") or knowledge["manual_next"],
            "technique_codes": list(knowledge["techniques"]),
            "wstg_refs": list(knowledge["wstg_refs"]),
        })

    coverage = build_wstg_coverage(result, kb_root)
    for gap in coverage.get("manual_gaps", [])[:8]:
        key = ("gap", gap["wstg_id"], "")
        if key in seen:
            continue
        handoff.append({
            "category": "coverage_gap",
            "status": "manual_review",
            "url": "",
            "guide": gap["guide"],
            "next_step": f"{gap['wstg_id']} - {gap['title']}: {gap['reason']}",
            "technique_codes": gap["technique_codes"],
            "wstg_refs": [gap["wstg_id"]],
        })
    return handoff[:30]


def build_knowledge_profile(result: dict[str, Any], mode: str, target: str = "", kb_root: str | None = None) -> dict[str, Any]:
    coverage = build_wstg_coverage(result, kb_root)
    handoff = build_manual_handoff(result, kb_root)
    guide_counts = Counter(item.get("category", "") for item in handoff)
    return {
        "target": target,
        "mode": mode,
        "kb_root": coverage["kb_root"],
        "kb_available": coverage["kb_available"],
        "technique_codes": coverage["technique_codes"],
        "wstg_coverage": coverage,
        "manual_handoff": handoff,
        "manual_handoff_summary": dict(sorted(guide_counts.items())),
    }


def summarize_knowledge_for_strategy(knowledge_profile: dict[str, Any] | None) -> dict[str, Any]:
    profile = knowledge_profile or {}
    coverage = profile.get("wstg_coverage", {}) if isinstance(profile.get("wstg_coverage"), dict) else {}
    framework_hints = coverage.get("framework_hints", []) if isinstance(coverage.get("framework_hints"), list) else []
    nuclei_tags: set[str] = set()
    first_tests: list[str] = []
    for hint in framework_hints:
        if not isinstance(hint, dict):
            continue
        nuclei_tags.update(hint.get("nuclei_tags", []) or [])
        first_tests.extend(hint.get("first_tests", []) or [])
    return {
        "technique_codes": profile.get("technique_codes", coverage.get("technique_codes", [])) or [],
        "nuclei_tags": sorted(nuclei_tags),
        "first_tests": first_tests[:20],
        "frameworks": [hint.get("framework", "") for hint in framework_hints if isinstance(hint, dict)],
    }
