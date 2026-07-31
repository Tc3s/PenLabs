import os
import json
import pytest
from unittest.mock import MagicMock
from core.schemas import M1Asset, AttackPlanEntry
from core.db import get_session, init_db, persist_to_database, Vulnerability, Asset
from core.reporter import generate_attack_surface_report
from scripts.Module1_Recon import _summarize_subdomain_vulns
from scripts.Module3_Exploit import TheExecutioner
from core.diff_engine import DiffEngine


def test_m1_m2_m3_contract(tmp_path):
    """
    Validate the data contract boundary between M1 (Recon), M2 (VulnAnalysis),
    and M3 (Exploit) pipeline stages.
    
    Uses pytest's tmp_path fixture for sandboxed file I/O instead of hardcoded
    /tmp paths that break isolation and may fail on restricted systems.
    """
    # Simulate M1 Output conforming to M1Asset
    m1_data = [{
        "target": "test.com", 
        "ip": "1.1.1.1", 
        "open_ports": [{"port": 80, "protocol": "tcp"}], 
        "tech_stack": ["Nginx"]
    }]
    
    # Test M1 validation
    asset = M1Asset(**m1_data[0])
    assert asset.target == "test.com"
    
    # Test DiffEngine initialization
    engine = DiffEngine(project_id=1, scan_session_id=1)
    mock_session = MagicMock()
    # Test that it has the ingest_recon_results method
    assert hasattr(engine, "ingest_recon_results")
    
    # Simulate M2 Output conforming to AttackPlanEntry
    m2_data = {
        "filter_summary": {"total_vulns": 1},
        "attack_plan": [
            {
                "target": "test.com", 
                "ip": "1.1.1.1", 
                "cve": "CVE-2023-1234", 
                "rport": 80,
                "severity": "high"
            }
        ]
    }
    
    # Test M2 validation
    plan_entry = AttackPlanEntry(**m2_data["attack_plan"][0])
    assert plan_entry.cve == "CVE-2023-1234"
    
    # Test M3 load_plan — use tmp_path for sandboxed file I/O
    session_dir = tmp_path / "penlabs_test"
    session_dir.mkdir()
    plan_file = session_dir / "m2_vuln.json"
    plan_file.write_text(json.dumps(m2_data), encoding="utf-8")
        
    m3 = TheExecutioner(plan_file=str(plan_file), session_dir=str(session_dir))
    assert m3.load_plan() == True
    assert len(m3.tasks) == 1
    assert m3.tasks[0]["target"] == "test.com"


def test_web_dast_contract_flows_from_m1_to_db_and_report(tmp_path):
    session_dir = tmp_path / "session"
    session_dir.mkdir()
    db_url = f"sqlite:///{tmp_path / 'integration.db'}"
    init_db(db_url)

    m1_data = {
        "target": "example.com",
        "ip": "1.2.3.4",
        "scan_mode": "web-vuln",
        "web_urls": ["https://example.com"],
        "api_endpoints": [{"url": "https://example.com/api/users"}],
        "dast_findings": [
            {
                "category": "blind_xss",
                "tool": "blind_xss",
                "title": "Blind XSS Injection",
                "severity": "high",
                "url": "https://example.com/profile",
                "matched_at": "https://example.com/profile",
                "evidence": "Injected blind XSS payload into fields: bio",
            },
            {
                "category": "mass_assignment",
                "tool": "mass_assignment",
                "title": "Mass Assignment",
                "severity": "high",
                "url": "https://example.com/api/users",
                "matched_at": "https://example.com/api/users",
                "evidence": "Response contains injected privilege fields",
            },
            {
                "category": "cors",
                "tool": "corsy",
                "title": "CORS Misconfiguration",
                "severity": "medium",
                "url": "https://example.com",
                "matched_at": "https://example.com",
                "evidence": "Wildcard origin allowed",
            },
        ],
        "summary": {
            "mode": "web-vuln",
            "nuclei_findings": 0,
            "xss": 0,
            "cors": 1,
            "blind_xss": 1,
            "mass_assignment": 1,
            "parameterized_urls": 1,
            "vhosts": 0,
        },
    }

    asset = M1Asset(**m1_data)
    assert asset.summary["blind_xss"] == 1
    assert len(asset.dast_findings) == 3

    stats = persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="web-vuln",
        recon_data=asset.model_dump(),
        vuln_data=[],
        scan_session_id=None,
    )
    assert stats["vulns_new"] >= 3

    with get_session(db_url) as session:
        vuln_types = {v.vuln_type for v in session.query(Vulnerability).all()}
        assert {"Blind-XSS", "Mass-Assignment", "CORS-Misconfig"} <= vuln_types

    m1_path = session_dir / "m1_recon.json"
    m1_path.write_text(json.dumps(m1_data), encoding="utf-8")
    report_path = generate_attack_surface_report(
        session_dir=str(session_dir),
        target="example.com",
        mode="web-vuln",
        m1_json_path=str(m1_path),
    )
    report = (session_dir / "attack_surface_report.md").read_text(encoding="utf-8")

    assert report_path.endswith("attack_surface_report.md")
    assert "| Blind XSS | 1 |" in report
    assert "| Mass Assignment | 1 |" in report
    assert "Blind_XSS" in report
    assert "Mass_Assignment" in report


def test_asset_discovery_contract_flows_through_schema_and_db(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'asset-discovery.db'}"
    init_db(db_url)

    m1_data = {
        "target": "example.com",
        "ip": "1.2.3.4",
        "scan_mode": "asset-discovery",
        "subdomains": ["api.example.com", "static.example.com"],
        "web_urls": ["https://example.com", "https://api.example.com"],
        "api_endpoints": [
            {"url": "https://api.example.com/v1/users", "method": "GET", "source": "katana"},
            {"url": "https://api.example.com/v1/admin", "method": "GET", "source": "linkfinder"},
        ],
        "js_files": ["https://static.example.com/app.js"],
        "secrets": [
            {"type": "Token", "source": "https://static.example.com/app.js", "value": "secret-1"},
            {"type": "API Key", "source": "https://static.example.com/app.js", "value": "secret-2"},
        ],
        "summary": {
            "mode": "asset-discovery",
            "subdomains": 2,
            "live_urls": 2,
            "api_endpoints": 2,
            "js_files": 1,
            "secrets": 2,
            "nuclei_findings": 0,
        },
    }

    asset = M1Asset(**m1_data)
    assert asset.summary["api_endpoints"] == 2
    assert len(asset.api_endpoints) == 2
    assert len(asset.secrets) == 2

    stats = persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="asset-discovery",
        recon_data=asset.model_dump(),
        vuln_data=[],
        scan_session_id=None,
    )

    assert stats["assets_new"] >= 4
    assert stats["vulns_new"] >= 2

    with get_session(db_url) as session:
        vuln_types = {v.vuln_type for v in session.query(Vulnerability).all()}
        asset_values = {a.value for a in session.query(Asset).all()}

        assert {"Secret: Token", "Secret: API Key"} <= vuln_types
        assert "https://api.example.com/v1/users" in asset_values
        assert "https://api.example.com/v1/admin" in asset_values


def test_subdomain_vuln_summary_prefers_dast_contract_and_falls_back_legacy(tmp_path):
    sub_path = tmp_path / "sub.json"
    sub_path.write_text(json.dumps({
        "dast_findings": [
            {"category": "xss"},
            {"category": "blind_xss"},
            {"category": "sqli"},
            {"category": "mass_assignment"},
            {"category": "ssrf"},
        ],
        "nuclei_findings": [{}, {}],
    }), encoding="utf-8")

    legacy_entry = {
        "xss_findings": [{}, {}],
        "sqli_findings": [{}],
        "ssrf_findings": [{}],
        "nuclei_findings": [{}],
    }

    summary = _summarize_subdomain_vulns([str(sub_path), legacy_entry])

    assert summary["total_subdomains_scanned"] == 2
    assert summary["total_xss"] == 3
    assert summary["total_blind_xss"] == 1
    assert summary["total_sqli"] == 2
    assert summary["total_ssrf"] == 2
    assert summary["total_mass_assignment"] == 1
    assert summary["total_nuclei"] == 3
