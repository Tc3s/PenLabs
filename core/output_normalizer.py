"""Output Normalizer — map mỗi tool output → unified Pydantic schema."""
from __future__ import annotations

import os
import re
import json
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class NormalizedFinding(BaseModel):
    """Unified finding schema — output của mọi tool scan."""
    # Identity
    finding_id: str = Field(description="Unique ID: {tool}:{target}:{cve|template}")
    tool: str = Field(description="Tool name: nuclei, nmap, dalfox, ...")
    target: str = Field(description="Target URL/IP/domain")
    
    # Classification
    finding_type: str = Field(description="vuln, misconfig, info, exposure")
    severity: str = Field(default="info", description="critical/high/medium/low/info")
    cve_id: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Evidence
    matched_at: str = Field(description="URL hoặc endpoint cụ thể")
    url: Optional[str] = Field(default=None, description="URL to preserve backward compatibility")
    request: Optional[str] = None
    response: Optional[str] = None
    payload: Optional[str] = None
    screenshot_path: Optional[str] = None
    
    # Metadata
    template_id: Optional[str] = None  # Nuclei
    port: Optional[int] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    name: str = Field(default="", description="Name of vulnerability or finding")
    description: str = Field(default="", description="Description of finding")
    interaction: bool = Field(default=False, description="OOB interaction detected")
    curl_command: Optional[str] = Field(default="", description="Equivalent curl command from nuclei")
    
    # Timestamps
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Source tool-specific data (preserve original)
    raw: Dict[str, Any] = Field(default_factory=dict)


class ToolNormalizer:
    """Base class cho mỗi tool normalizer."""
    TOOL_NAME: str = ""
    
    @classmethod
    def can_handle(cls, raw_output: Any) -> bool:
        """Detect nếu raw output là của tool này."""
        raise NotImplementedError
    
    @classmethod
    def normalize(cls, raw_output: Any, target: str) -> List[NormalizedFinding]:
        """Convert raw output → list of NormalizedFinding."""
        raise NotImplementedError


class NucleiNormalizer(ToolNormalizer):
    """Normalize Nuclei JSON output (v3 và v4 compatible)."""
    TOOL_NAME = "nuclei"
    
    SEVERITY_MAP = {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "info": "info", "unknown": "info"
    }
    
    @classmethod
    def can_handle(cls, raw_output: Any) -> bool:
        if isinstance(raw_output, dict):
            return (
                "template-id" in raw_output 
                or "templateID" in raw_output 
                or "template_id" in raw_output
            )
        return False
    
    @classmethod
    def normalize(cls, raw_output: Any, target: str) -> List[NormalizedFinding]:
        template_id = (
            raw_output.get("template-id") 
            or raw_output.get("templateID") 
            or raw_output.get("template_id", "")
        )
        info = raw_output.get("info", {}) or {}
        # If it's already mapped, raw_output itself has the severity, etc.
        severity_str = info.get("severity") or raw_output.get("severity") or "unknown"
        severity = cls.SEVERITY_MAP.get(severity_str.lower(), "info")
        
        # Extract CVE từ template-id hoặc classification
        cve_id = raw_output.get("cve_id")
        if not cve_id:
            if template_id.upper().startswith("CVE-"):
                cve_id = template_id
            else:
                classification = info.get("classification", {}) if isinstance(info, dict) else {}
                if classification:
                    cve_list = classification.get("cve-id")
                    if isinstance(cve_list, list) and cve_list:
                        cve_id = cve_list[0]
                    elif isinstance(cve_list, str):
                        cve_id = cve_list
        
        # Extract CWE
        cwe_id = raw_output.get("cwe_id")
        if not cwe_id:
            classification = info.get("classification", {}) if isinstance(info, dict) else {}
            if classification:
                cwe_list = classification.get("cwe-id")
                if isinstance(cwe_list, list) and cwe_list:
                    cwe_id = cwe_list[0]
                elif isinstance(cwe_list, str):
                    cwe_id = cwe_list

        tags = info.get("tags") or raw_output.get("tags") or []
        name = info.get("name") or raw_output.get("template_name") or raw_output.get("name") or ""
        description = info.get("description") or raw_output.get("description") or ""
        interaction = raw_output.get("interaction", False)
        curl_command = raw_output.get("curl-command") or raw_output.get("curl_command") or ""

        matched_at = raw_output.get("matched-at") or raw_output.get("matched") or raw_output.get("matched_at") or target
        return [NormalizedFinding(
            finding_id=f"nuclei:{target}:{template_id}",
            tool="nuclei",
            target=target,
            finding_type="vuln" if cve_id else "misconfig",
            severity=severity,
            cve_id=cve_id,
            cwe_id=cwe_id,
            cvss_score=info.get("classification", {}).get("cvss-score") if (isinstance(info, dict) and info.get("classification")) else None,
            matched_at=matched_at,
            url=matched_at,
            template_id=template_id,
            tags=tags,
            name=name,
            description=description,
            interaction=interaction,
            curl_command=curl_command,
            raw=raw_output
        )]


class NmapNormalizer(ToolNormalizer):
    """Normalize Nmap XML output."""
    TOOL_NAME = "nmap"
    
    @classmethod
    def can_handle(cls, raw_output: Any) -> bool:
        return isinstance(raw_output, str) and raw_output.strip().startswith("<?xml")
    
    @classmethod
    def normalize(cls, raw_output: str, target: str) -> List[NormalizedFinding]:
        findings = []
        try:
            import defusedxml.ElementTree as DET
            root = DET.fromstring(raw_output.encode("utf-8", errors="ignore"))
            for host in root.findall("host"):
                ip = host.find("address").get("addr") if host.find("address") is not None else target
                for port in host.findall(".//port"):
                    state = port.find("state").get("state") if port.find("state") is not None else "unknown"
                    if state != "open":
                        continue
                    port_num = int(port.get("portid", 0))
                    service_elem = port.find("service")
                    service_name = service_elem.get("name", "") if service_elem is not None else ""
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    
                    findings.append(NormalizedFinding(
                        finding_id=f"nmap:{ip}:{port_num}",
                        tool="nmap",
                        target=ip,
                        finding_type="info",
                        severity="info",
                        matched_at=f"{ip}:{port_num}/{service_name}",
                        port=port_num,
                        service=service_name,
                        product=product,
                        version=version,
                        raw={"ip": ip, "port": port_num, "state": state}
                    ))
        except ET.ParseError as e:
            logging.error(f"[NmapNormalizer] XML parse error: {e}")
        return findings


class DalfoxNormalizer(ToolNormalizer):
    """Normalize Dalfox output (XSS findings)."""
    TOOL_NAME = "dalfox"
    
    @classmethod
    def can_handle(cls, raw_output: Any) -> bool:
        return isinstance(raw_output, dict) and ("param" in raw_output and ("url" in raw_output or "data" in raw_output))
    
    @classmethod
    def normalize(cls, raw_output: Dict, target: str) -> List[NormalizedFinding]:
        severity = raw_output.get("severity", "high")
        if severity == "medium":
            severity = "high" # XSS is always high severity
        matched_at = raw_output.get("url") or raw_output.get("data") or target
        return [NormalizedFinding(
            finding_id=f"dalfox:{target}:{raw_output.get('param', '')}",
            tool="dalfox",
            target=target,
            finding_type="vuln",
            severity=severity,
            cwe_id="CWE-79",
            matched_at=matched_at,
            url=matched_at,
            payload=raw_output.get("payload", ""),
            raw=raw_output
        )]


class NaabuNormalizer(ToolNormalizer):
    """Normalize Naabu JSON output."""
    TOOL_NAME = "naabu"
    
    @classmethod
    def can_handle(cls, raw_output: Any) -> bool:
        return isinstance(raw_output, dict) and "host" in raw_output and "port" in raw_output
    
    @classmethod
    def normalize(cls, raw_output: Dict, target: str) -> List[NormalizedFinding]:
        return [NormalizedFinding(
            finding_id=f"naabu:{raw_output['host']}:{raw_output['port']}",
            tool="naabu",
            target=raw_output["host"],
            finding_type="info",
            severity="info",
            matched_at=f"{raw_output['host']}:{raw_output['port']}",
            port=raw_output["port"],
            raw=raw_output
        )]


# === Registry of normalizers ===
NORMALIZERS = [
    NucleiNormalizer,
    NmapNormalizer,
    DalfoxNormalizer,
    NaabuNormalizer,
]


def normalize_output(raw_output: Any, target: str, force_tool: str = None) -> List[NormalizedFinding]:
    """
    Auto-detect tool từ raw output và normalize.
    Args:
        raw_output: raw từ tool (str, dict, list)
        target: target URL/IP
        force_tool: nếu biết tool name, skip auto-detect
    Returns:
        List of NormalizedFinding
    """
    # Try force_tool first
    if force_tool:
        for norm_class in NORMALIZERS:
            if norm_class.TOOL_NAME == force_tool:
                return norm_class.normalize(raw_output, target)
    
    # Auto-detect
    for norm_class in NORMALIZERS:
        if norm_class.can_handle(raw_output):
            return norm_class.normalize(raw_output, target)
    
    logging.warning(f"[OutputNormalizer] Unknown output format for {target}")
    return []
