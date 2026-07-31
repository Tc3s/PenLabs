import core.db as db_module
from core.db import (
    DiffEventType,
    ScanSession,
    ScanStatus,
    Vulnerability,
    get_or_create_project,
    get_session,
    init_db,
    persist_to_database,
)
from core.diff_engine import DiffEngine
from core.schemas import M1Asset


def _reset_db_singletons():
    for engine in db_module._ENGINE_CACHE.values():
        engine.dispose()
    db_module._engine = None
    db_module._SessionFactory = None
    db_module._ENGINE_CACHE = {}
    db_module._SESSION_FACTORY_CACHE = {}


def test_m1_asset_syncs_canonical_aliases():
    asset = M1Asset(
        target="example.com",
        cors_issues=[{"url": "https://example.com", "details": "wildcard"}],
        graphql={
            "introspection_enabled": [{"url": "https://example.com/graphql", "details": "enabled"}],
            "graphql_vulns": [{"endpoint": "https://example.com/graphql", "details": "batching"}],
        },
        js_secrets=[{"type": "API Key", "source": "https://example.com/app.js"}],
    )

    assert asset.cors_findings == asset.cors_issues
    assert len(asset.graphql_findings) == 2
    assert asset.secrets == asset.js_secrets


def test_persist_to_database_handles_canonical_keys(tmp_path):
    _reset_db_singletons()
    db_url = f"sqlite:///{tmp_path / 'penlabs.db'}"
    recon_data = {
        "ip": "1.2.3.4",
        "web_urls": ["https://example.com"],
        "api_endpoints": ["https://example.com/api/users"],
        "cors_findings": [{"url": "https://example.com", "details": "wildcard origin"}],
        "graphql_findings": [{"endpoint": "https://example.com/graphql", "details": "introspection enabled"}],
        "secrets": [{"type": "Token", "source": "https://example.com/app.js", "value": "redacted"}],
        "emails": ["sec@example.com"],
        "metadata": {"users": ["alice"], "emails": [], "software": [], "paths": []},
    }

    stats = persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="api-bounty",
        recon_data=recon_data,
        vuln_data=[],
        scan_session_id=None,
    )

    assert stats["assets_new"] >= 3

    with get_session(db_url) as session:
        vulns = session.query(Vulnerability).all()
        vuln_types = {v.vuln_type for v in vulns}
        evidence_urls = {v.evidence_url for v in vulns}

        assert "CORS-Misconfig" in vuln_types
        assert "GraphQL-Exposure" in vuln_types
        assert "Secret: Token" in vuln_types
        assert "Email-Leak" in vuln_types
        assert "Identity-Metadata" in vuln_types
        assert "https://example.com/graphql" in evidence_urls


def test_persist_to_database_handles_bola_open_redirect_and_crlf(tmp_path):
    _reset_db_singletons()
    db_url = f"sqlite:///{tmp_path / 'penlabs-extra.db'}"
    recon_data = {
        "ip": "1.2.3.4",
        "web_urls": ["https://example.com"],
        "open_redirect_findings": [{
            "url": "https://example.com/redirect?next=https://evil.test",
            "payload": "https://evil.test",
            "severity": "medium",
        }],
        "crlf_findings": [{
            "url": "https://example.com/search?q=test",
            "payload": "%0d%0aSet-Cookie:%20owned=1",
            "severity": "medium",
        }],
        "bola_findings": {
            "high_confidence_bola": [{
                "endpoint": "https://example.com/api/users/42",
                "method": "GET",
                "evidence": "User B accessed User A record",
                "severity": "critical",
            }],
            "privilege_escalation": [{
                "endpoint": "https://example.com/api/admin/users",
                "method": "POST",
                "evidence": "Regular user reached admin function",
                "severity": "critical",
            }],
        },
    }

    stats = persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="api-bounty",
        recon_data=recon_data,
        vuln_data=[],
        scan_session_id=None,
    )

    assert stats["vulns_new"] >= 4

    with get_session(db_url) as session:
        vulns = session.query(Vulnerability).all()
        by_type = {}
        for vuln in vulns:
            by_type.setdefault(vuln.vuln_type, []).append(vuln)

        assert "Open-Redirect" in by_type
        assert by_type["Open-Redirect"][0].evidence_url == "https://example.com/redirect?next=https://evil.test"

        assert "CRLF-Injection" in by_type
        assert by_type["CRLF-Injection"][0].evidence_payload == "%0d%0aSet-Cookie:%20owned=1"

        assert "BOLA-IDOR" in by_type
        bola_urls = {v.evidence_url for v in by_type["BOLA-IDOR"]}
        assert "https://example.com/api/users/42" in bola_urls
        assert "https://example.com/api/admin/users" in bola_urls


def test_persist_to_database_dedupes_same_evidence_url_on_repeat_runs(tmp_path):
    _reset_db_singletons()
    db_url = f"sqlite:///{tmp_path / 'penlabs-dedupe.db'}"
    recon_data = {
        "ip": "1.2.3.4",
        "web_urls": ["https://example.com"],
        "cors_findings": [{"url": "https://example.com", "details": "wildcard origin"}],
        "graphql_findings": [{"endpoint": "https://example.com/graphql", "details": "introspection enabled"}],
        "open_redirect_findings": [{
            "url": "https://example.com/redirect?next=https://evil.test",
            "payload": "https://evil.test",
        }],
        "crlf_findings": [{
            "url": "https://example.com/search?q=test",
            "payload": "%0d%0aSet-Cookie:%20owned=1",
        }],
        "bola_findings": {
            "high_confidence_bola": [{
                "endpoint": "https://example.com/api/users/42",
                "method": "GET",
                "evidence": "User B accessed User A record",
            }],
        },
    }

    persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="api-bounty",
        recon_data=recon_data,
        vuln_data=[],
        scan_session_id=None,
    )
    persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="api-bounty",
        recon_data=recon_data,
        vuln_data=[],
        scan_session_id=None,
    )

    with get_session(db_url) as session:
        vulns = session.query(Vulnerability).all()

        assert len(vulns) == 5
        assert session.query(Vulnerability).filter_by(
            vuln_type="CORS-Misconfig",
            evidence_url="https://example.com",
        ).count() == 1
        assert session.query(Vulnerability).filter_by(
            vuln_type="GraphQL-Exposure",
            evidence_url="https://example.com/graphql",
        ).count() == 1
        assert session.query(Vulnerability).filter_by(
            vuln_type="Open-Redirect",
            evidence_url="https://example.com/redirect?next=https://evil.test",
        ).count() == 1
        assert session.query(Vulnerability).filter_by(
            vuln_type="CRLF-Injection",
            evidence_url="https://example.com/search?q=test",
        ).count() == 1
        assert session.query(Vulnerability).filter_by(
            vuln_type="BOLA-IDOR",
            evidence_url="https://example.com/api/users/42",
        ).count() == 1


def test_persist_to_database_handles_extended_dast_contract_categories(tmp_path):
    _reset_db_singletons()
    db_url = f"sqlite:///{tmp_path / 'penlabs-dast-extended.db'}"
    recon_data = {
        "ip": "1.2.3.4",
        "web_urls": ["https://example.com"],
        "dast_findings": [
            {
                "category": "blind_xss",
                "tool": "blind_xss",
                "title": "Blind XSS Injection",
                "severity": "high",
                "url": "https://example.com/contact",
                "matched_at": "https://example.com/contact",
                "evidence": "Injected blind XSS payload into feedback form",
            },
            {
                "category": "mass_assignment",
                "tool": "mass_assignment",
                "title": "Mass Assignment",
                "severity": "high",
                "url": "https://example.com/api/users/7",
                "matched_at": "https://example.com/api/users/7",
                "evidence": "Response contains injected privilege fields",
            },
            {
                "category": "bypass_403",
                "tool": "bypass_403",
                "title": "403 Bypass",
                "severity": "high",
                "url": "https://example.com/admin",
                "matched_at": "https://example.com/admin",
                "evidence": "Header: X-Original-URL returned status 200",
            },
            {
                "category": "cache_poisoning",
                "tool": "cache_poison_probe",
                "title": "Web Cache Poisoning",
                "severity": "medium",
                "url": "https://example.com/",
                "matched_at": "https://example.com/",
                "evidence": "Unkeyed header reflected in cached response",
            },
        ],
    }

    stats = persist_to_database(
        db_url=db_url,
        target="example.com",
        scan_mode="api-bounty",
        recon_data=recon_data,
        vuln_data=[],
        scan_session_id=None,
    )

    assert stats["vulns_new"] >= 4

    with get_session(db_url) as session:
        assert session.query(Vulnerability).filter_by(vuln_type="Blind-XSS").count() == 1
        assert session.query(Vulnerability).filter_by(vuln_type="Mass-Assignment").count() == 1
        assert session.query(Vulnerability).filter_by(vuln_type="Bypass-403").count() == 1
        assert session.query(Vulnerability).filter_by(vuln_type="Cache-Poisoning").count() == 1


def test_diff_engine_flattens_canonical_and_nested_findings(tmp_path):
    _reset_db_singletons()
    db_url = f"sqlite:///{tmp_path / 'diff.db'}"
    init_db(db_url)

    with get_session(db_url) as session:
        project = get_or_create_project(session, name="Example", slug="example")
        project_id = project.id
        scan_session = ScanSession(
            project_id=project_id,
            session_uid="test-session-1",
            target="example.com",
            profile="api-bounty",
            status=ScanStatus.COMPLETED.value,
        )
        session.add(scan_session)
        session.flush()
        scan_session_id = scan_session.id

    m1_data = {
        "target": "example.com",
        "subdomains": ["api.example.com"],
        "web_urls": ["https://example.com"],
        "cors_findings": [{"url": "https://example.com", "details": "wildcard origin", "severity": "medium"}],
        "graphql_findings": [{"endpoint": "https://example.com/graphql", "details": "introspection", "severity": "medium"}],
        "bola_findings": {
            "high_confidence_bola": [{
                "endpoint": "https://example.com/api/users/7",
                "method": "GET",
                "evidence": "User B saw User A data",
                "severity": "critical",
            }],
            "graphql_findings": [{
                "endpoint": "https://example.com/graphql",
                "evidence": "Cross-tenant object fetch",
                "severity": "high",
            }],
        },
        "secrets": [{"source": "https://example.com/app.js", "type": "API Key", "value": "redacted"}],
    }

    with get_session(db_url) as session:
        report = DiffEngine(project_id=project_id, scan_session_id=scan_session_id).ingest_recon_results(session, m1_data)
        diffs = session.query(Vulnerability).all()

        assert report.has_changes is True
        assert len(report.new_vulns) >= 4
        assert {v.vuln_type for v in diffs} >= {
            "CORS_Misconfiguration",
            "GraphQL_Exposure",
            "BOLA_IDOR",
            "Hardcoded_Secret",
        }


def test_diff_engine_prefers_dast_contract_extended_categories(tmp_path):
    _reset_db_singletons()
    db_url = f"sqlite:///{tmp_path / 'diff-dast.db'}"
    init_db(db_url)

    with get_session(db_url) as session:
        project = get_or_create_project(session, name="Example", slug="example-dast")
        project_id = project.id
        scan_session = ScanSession(
            project_id=project_id,
            session_uid="test-session-dast",
            target="example.com",
            profile="web-vuln",
            status=ScanStatus.COMPLETED.value,
        )
        session.add(scan_session)
        session.flush()
        scan_session_id = scan_session.id

    m1_data = {
        "target": "example.com",
        "web_urls": ["https://example.com"],
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
        ],
    }

    with get_session(db_url) as session:
        report = DiffEngine(project_id=project_id, scan_session_id=scan_session_id).ingest_recon_results(session, m1_data)
        diffs = session.query(Vulnerability).all()

        assert report.has_changes is True
        assert {v.vuln_type for v in diffs} >= {"Blind_XSS", "Mass_Assignment"}


def test_db_engine_and_session_factory_are_isolated_per_db_url(tmp_path):
    _reset_db_singletons()
    db_url_a = f"sqlite:///{tmp_path / 'a.db'}"
    db_url_b = f"sqlite:///{tmp_path / 'b.db'}"

    init_db(db_url_a)
    init_db(db_url_b)

    engine_a = db_module.get_engine(db_url_a)
    engine_b = db_module.get_engine(db_url_b)
    factory_a = db_module.get_session_factory(db_url_a)
    factory_b = db_module.get_session_factory(db_url_b)

    assert engine_a is not engine_b
    assert factory_a is not factory_b

    with get_session(db_url_a) as session:
        get_or_create_project(session, name="Project A", slug="project-a")

    with get_session(db_url_b) as session:
        assert session.query(db_module.Project).filter_by(slug="project-a").count() == 0
