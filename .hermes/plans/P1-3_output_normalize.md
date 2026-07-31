# P1-3: Output Normalization — DETAILED PLAN

## Hiện trạng đã verify

### Vấn đề
- Mỗi tool (Nuclei, Nmap, Naabu, Dalfox, Corsy, Sqlmap, Arjun) có output format riêng
- scanner_router.py parse 10+ format khác nhau (xem `_route_*` methods)
- Khi tool update version → format JSON thay đổi → PenLabs crash
- Ví dụ: Nuclei v3 → v4 thay đổi JSON schema 2024

### Evidence từ code
- `core/schemas.py` chỉ define M1Asset/AttackPlanEntry (high-level), không có NormalizedFinding
- scanner_router.py có ~10 `_route_*` methods, mỗi method parse JSON khác nhau
- Module2_VulnAnalysis.py parse thêm 1 lần nữa → 2 layer parsing

## Approach: OutputNormalizer class

### 1. core/output_normalizer.py (MỚI)

```python
"""Output Normalizer — map mỗi tool output → unified Pydantic schema."""
import os
import re
import json
import logging
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional
from datetime import datetime
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
    
    # Timestamps
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    
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
            return "template-id" in raw_output or "templateID" in raw_output
        return False
    
    @classmethod
    def normalize(cls, raw_output: Any, target: str) -> List[NormalizedFinding]:
        # Handle both v3 (template-id) và v4 (templateID)
        template_id = raw_output.get("template-id") or raw_output.get("templateID", "")
        info = raw_output.get("info", {})
        severity = cls.SEVERITY_MAP.get(info.get("severity", "unknown"), "info")
        
        # Extract CVE từ template-id hoặc classification
        cve_id = None
        if template_id.startswith("CVE-"):
            cve_id = template_id
        else:
            classification = info.get("classification", {})
            if classification:
                cve_id = classification.get("cve-id", [None])[0] if isinstance(classification.get("cve-id"), list) else classification.get("cve-id")
        
        return [NormalizedFinding(
            finding_id=f"nuclei:{target}:{template_id}",
            tool="nuclei",
            target=target,
            finding_type="vuln" if cve_id else "misconfig",
            severity=severity,
            cve_id=cve_id,
            cwe_id=info.get("classification", {}).get("cwe-id", [None])[0] if isinstance(info.get("classification", {}).get("cwe-id"), list) else None,
            cvss_score=info.get("classification", {}).get("cvss-score"),
            matched_at=raw_output.get("matched-at", raw_output.get("matched", target)),
            template_id=template_id,
            tags=info.get("tags", []),
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
            root = ET.fromstring(raw_output)
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
        return isinstance(raw_output, dict) and ("type" in raw_output and "param" in raw_output)
    
    @classmethod
    def normalize(cls, raw_output: Dict, target: str) -> List[NormalizedFinding]:
        return [NormalizedFinding(
            finding_id=f"dalfox:{target}:{raw_output.get('param', '')}",
            tool="dalfox",
            target=target,
            finding_type="vuln",
            severity="high",  # XSS = high default
            cwe_id="CWE-79",
            matched_at=raw_output.get("data", target),
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
```

### 2. core/schemas.py — thêm NormalizedFinding
Đã include ở trên trong output_normalizer.py

### 3. scanner_router.py — dùng OutputNormalizer
Trong mỗi _route_* method, sau khi parse raw JSON, gọi:
```python
from core.output_normalizer import normalize_output

# Thay vì:
result["nuclei_findings"].append(raw_finding)

# Dùng:
normalized = normalize_output(raw_finding, target, force_tool="nuclei")
result["nuclei_findings"].extend(normalized)
```

### 4. tests/test_output_normalizer.py (MỚI)
```python
"""Test OutputNormalizer với sample outputs từ Nuclei v3, v4, Nmap, Dalfox, Naabu."""
import json
from core.output_normalizer import normalize_output, NucleiNormalizer, NmapNormalizer

def test_nuclei_v3_normalize():
    raw = {
        "template-id": "CVE-2021-44228",
        "info": {"severity": "critical", "name": "Log4Shell", "tags": ["cve"]},
        "matched-at": "https://target.com/"}
    findings = normalize_output(raw, "target.com", force_tool="nuclei")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-44228"
    assert findings[0].severity == "critical"

def test_nuclei_v4_normalize():
    """Nuclei v4 dùng templateID thay vì template-id."""
    raw = {
        "templateID": "CVE-2021-44228",
        "info": {"severity": "critical"},
        "matched": "https://target.com/"
    }
    findings = normalize_output(raw, "target.com", force_tool="nuclei")
    assert len(findings) == 1

def test_nmap_xml_normalize():
    raw = """<?xml version="1.0"?>
    <nmaprun>
      <host><address addr="1.2.3.4"/>
        <ports><port portid="80"><state state="open"/>
          <service name="http" product="Apache" version="2.4.49"/></port>
        </ports>
      </host>
    </nmaprun>"""
    findings = normalize_output(raw, "1.2.3.4", force_tool="nmap")
    assert len(findings) == 1
    assert findings[0].port == 80
    assert findings[0].product == "Apache"
```

## Acceptance Criteria

1. **Mỗi tool output** → Pydantic NormalizedFinding
2. **Schema stable** khi tool update minor version (vd Nuclei v3 → v4)
3. **Backward compat**: format cũ vẫn parse được
4. **Test coverage** ≥ 80% cho OutputNormalizer
5. **No regression**: existing scanner_router vẫn chạy được

## Verification

1. Run pytest tests/test_output_normalizer.py — phải pass
2. Dispatch subagent review
3. Test với real sample từ /tmp của user
