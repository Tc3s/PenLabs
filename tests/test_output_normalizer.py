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

def test_dalfox_normalize():
    raw = {
        "url": "http://example.com/search?q=1",
        "param": "q",
        "type": "reflected",
        "payload": "alert(1)",
        "poc": "http://example.com/search?q=alert(1)",
        "severity": "medium"
    }
    findings = normalize_output(raw, "example.com", force_tool="dalfox")
    assert len(findings) == 1
    assert findings[0].tool == "dalfox"
    assert findings[0].severity == "high"
    assert findings[0].cwe_id == "CWE-79"

def test_naabu_normalize():
    raw = {
        "host": "1.2.3.4",
        "port": 443
    }
    findings = normalize_output(raw, "1.2.3.4", force_tool="naabu")
    assert len(findings) == 1
    assert findings[0].tool == "naabu"
    assert findings[0].port == 443

