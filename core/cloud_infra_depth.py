#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cloud/infra depth summary built from normalized scan results."""

from __future__ import annotations

from typing import Any


HIGH_VALUE_PORTS = {
    22: "remote_admin",
    3389: "remote_admin",
    5432: "database",
    3306: "database",
    6379: "database",
    27017: "database",
    6443: "kubernetes",
    8080: "web_admin",
    8443: "web_admin",
    9090: "monitoring",
    3000: "devops",
    9200: "search",
    5601: "devops",
    2375: "container_api",
    2376: "container_api",
    10250: "kubernetes",
}


def summarize_cloud_infra_depth(result: dict[str, Any]) -> dict[str, Any]:
    ports = [p for p in result.get("ports", []) or [] if isinstance(p, dict)]
    cloud_findings = result.get("cloud_findings", {}) if isinstance(result.get("cloud_findings"), dict) else {}
    nse_cves = [c for c in result.get("nse_cves", []) or [] if isinstance(c, dict)]
    nuclei = [n for n in result.get("nuclei_findings", []) or [] if isinstance(n, dict)]

    exposed_services = []
    for port in ports:
        port_num = port.get("port")
        if port_num in HIGH_VALUE_PORTS:
            exposed_services.append({
                "port": port_num,
                "service": port.get("service", HIGH_VALUE_PORTS[port_num]),
                "class": HIGH_VALUE_PORTS[port_num],
                "severity": "high" if HIGH_VALUE_PORTS[port_num] in {"database", "kubernetes", "remote_admin"} else "medium",
            })

    cloud_counts: dict[str, int] = {}
    for tool, value in cloud_findings.items():
        if isinstance(value, list):
            cloud_counts[str(tool)] = len(value)
        elif isinstance(value, dict):
            cloud_counts[str(tool)] = sum(len(v) for v in value.values() if isinstance(v, list))
        elif value:
            cloud_counts[str(tool)] = 1

    high_nuclei = [
        item for item in nuclei
        if str(item.get("severity") or item.get("info", {}).get("severity", "")).lower() in {"critical", "high"}
    ]
    triage = []
    for service in exposed_services:
        if service["class"] in {"kubernetes", "container_api"}:
            triage.append({
                "area": "kubernetes/container",
                "severity": "high",
                "target": f"{service.get('service')}:{service.get('port')}",
                "manual_next": "Check auth requirements, anonymous API access, and kubelet/container API exposure.",
            })
        elif service["class"] == "database":
            triage.append({
                "area": "database",
                "severity": "high",
                "target": f"{service.get('service')}:{service.get('port')}",
                "manual_next": "Validate network exposure, auth requirement, and version-specific CVEs.",
            })

    for tool, count in cloud_counts.items():
        if count:
            triage.append({
                "area": tool,
                "severity": "medium",
                "target": str(count),
                "manual_next": "Review normalized cloud finding evidence and permissions manually.",
            })

    return {
        "open_ports": len(ports),
        "high_value_services": exposed_services,
        "nse_cves": len(nse_cves),
        "cloud_tools": cloud_counts,
        "high_nuclei_findings": len(high_nuclei),
        "triage_items": triage,
        "needs_manual_cloud_review": bool(cloud_counts or any(s["class"] in {"kubernetes", "database"} for s in exposed_services)),
    }
