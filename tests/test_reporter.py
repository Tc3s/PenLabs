import json

from core.reporter import generate_attack_surface_report


def test_reporter_surfaces_dast_summary_and_contract_findings(tmp_path):
    session_dir = tmp_path / "session"
    session_dir.mkdir()

    m1_path = session_dir / "m1_recon.json"
    m1_payload = {
        "target": "example.com",
        "scan_mode": "web-vuln",
        "web_urls": ["https://example.com"],
        "api_endpoints": [{"url": "https://example.com/api/users"}],
        "nuclei_findings": [],
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
        "dast_findings": [
            {
                "category": "blind_xss",
                "tool": "blind_xss",
                "title": "Blind XSS Injection",
                "severity": "high",
                "url": "https://example.com/profile",
                "evidence": "Injected blind XSS payload into fields: bio",
            },
            {
                "category": "mass_assignment",
                "tool": "mass_assignment",
                "title": "Mass Assignment",
                "severity": "high",
                "url": "https://example.com/api/users",
                "evidence": "Response contains injected privilege fields",
            },
            {
                "category": "cors",
                "tool": "corsy",
                "title": "CORS Misconfiguration",
                "severity": "medium",
                "url": "https://example.com",
                "evidence": "Wildcard origin allowed",
            },
        ],
        "knowledge_profile": {
            "technique_codes": ["API", "AUTHZ", "XSS"],
            "wstg_coverage": {
                "covered_wstg_refs": ["WSTG-INPV-01"],
                "technique_codes": ["API", "AUTHZ", "XSS"],
                "manual_gaps": [
                    {
                        "wstg_id": "WSTG-ATHZ-04",
                        "title": "BOLA/IDOR dual-user authorization",
                        "reason": "API surface exists but no BOLA finding was confirmed.",
                        "guide": "/kb/payloads/authz-idor-elite.md",
                    }
                ],
                "framework_hints": [
                    {
                        "framework": "Next.js / React SSR",
                        "first_tests": ["/_next/image", "server actions"],
                        "guide": "/kb/frameworks/nextjs.md",
                    }
                ],
            },
            "manual_handoff": [
                {
                    "category": "coverage_gap",
                    "status": "manual_review",
                    "wstg_refs": ["WSTG-ATHZ-04"],
                    "next_step": "Validate BOLA with User A/B",
                }
            ],
        },
        "wordlist_profile": {
            "web_content": {"source": "repo", "path": "/repo/wordlists/common.txt"},
            "api_routes": {"source": "repo", "path": "/repo/wordlists/routes-small.kite"},
            "passwords": {"source": "repo", "path": "/repo/wordlists/top-10000-passwords.txt"},
        },
    }
    m1_path.write_text(json.dumps(m1_payload), encoding="utf-8")

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
    assert "| Blind XSS | 1 |" in report
    assert "| Mass Assignment | 1 |" in report
    assert "Blind_XSS" in report
    assert "Mass_Assignment" in report
    assert "Knowledge-Guided Coverage" in report
    assert "WSTG-ATHZ-04" in report
    assert "Manual Handoff Queue" in report
    assert "Wordlist Profile" in report
    assert "routes-small.kite" in report
