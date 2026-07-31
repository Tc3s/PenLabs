import json
from unittest.mock import MagicMock

from core.dast_contract import normalize_dast_findings
from plugins.kiterunner_plugin import KiterunnerPlugin
from plugins.graphql_probe_plugin import GraphQLProbePlugin
from plugins.wpscan_plugin import WPScanPlugin
from scripts.subdomain_scanner import SubdomainScanner


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_graphql_probe_introspection_returns_dict_entries(tmp_path):
    plugin = GraphQLProbePlugin()
    session = MagicMock()

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "data": {
            "__schema": {
                "types": [
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [{"name": "deleteUser", "args": [{"name": "id"}]}],
                    }
                ]
            }
        }
    }
    session.post.return_value = response

    result = {
        "endpoints_found": [],
        "introspection_enabled": [],
        "schemas": {},
        "mutations": [],
        "findings": [],
        "graphql_vulns": [],
    }

    plugin._try_introspection(session, "https://example.com/graphql", {"Content-Type": "application/json"}, 5, result, str(tmp_path))

    assert result["introspection_enabled"][0]["url"] == "https://example.com/graphql"
    assert result["graphql_vulns"][0]["type"] == "graphql_introspection_enabled"
    assert result["mutations"][0]["field"] == "deleteUser"


def test_subdomain_scanner_extracts_new_subdomains_from_canonical_aliases():
    scanner = SubdomainScanner(scanner_router=MagicMock(), logger=DummyLogger(), orchestrator=MagicMock())
    scanner.scanned_subs = {"api.example.com"}

    scan_result = {
        "web_urls": ["https://portal.example.com"],
        "api_endpoints": [{"url": "https://app.example.com/api/users"}],
        "cors_findings": [{"url": "https://cors.example.com", "origin": "https://static.example.com"}],
        "secrets": [{"value": "https://cdn.example.com/app.js"}],
    }

    new_subs = scanner._extract_new_subdomains(scan_result, "example.com")

    assert {"portal.example.com", "app.example.com", "cors.example.com", "static.example.com", "cdn.example.com"} <= new_subs
    assert "api.example.com" not in new_subs


def test_kiterunner_parse_line_exposes_canonical_aliases():
    parsed = KiterunnerPlugin._parse_kr_line("GET 200 https://example.com/api/v1/users [1234,json]")

    assert parsed["status"] == 200
    assert parsed["status_code"] == 200
    assert parsed["length"] == 1234
    assert parsed["content_length"] == 1234
    assert parsed["source"] == "kiterunner"


def test_wpscan_parse_json_exposes_summary_and_aliases(tmp_path):
    sample = {
        "version": {"number": "6.5.1", "vulnerabilities": [{"title": "Example XSS", "fixed_in": "6.5.2"}]},
        "main_theme": {"slug": "twentytwentyfour", "version": {"number": "1.0"}, "vulnerabilities": []},
        "plugins": {
            "contact-form-7": {
                "version": {"number": "5.8"},
                "vulnerabilities": [{"title": "Plugin RCE", "fixed_in": "5.9"}],
            }
        },
        "users": {"admin": {"id": 1}},
        "interesting_findings": [{"url": "https://example.com/xmlrpc.php", "type": "xmlrpc", "to_s": "XML-RPC enabled"}],
    }
    json_path = tmp_path / "wpscan.json"
    json_path.write_text(json.dumps(sample), encoding="utf-8")

    result = WPScanPlugin()._parse_wpscan_json(str(json_path))

    assert result["detected"] is True
    assert result["main_theme"]["name"] == "twentytwentyfour"
    assert result["summary"] == {"vulnerabilities": 2, "plugins": 1, "users": 1, "themes": 1}
    assert result["findings"] == result["vulnerabilities"]


def test_dast_contract_normalizes_remaining_bounty_shapes():
    blind_xss = normalize_dast_findings("blind_xss", {
        "injected_count": 1,
        "forms_found": 1,
        "injections": [{
            "url": "https://app.example.com/feedback",
            "action": "https://app.example.com/api/feedback",
            "method": "POST",
            "fields_injected": ["message"],
            "payload_type": "blind_xss",
        }],
    })
    mass_assignment = normalize_dast_findings("mass_assignment", [{
        "url": "https://api.example.com/users/7",
        "method": "PATCH",
        "severity": "high",
        "evidence": "Response contains injected privilege fields: {'role': 'admin'}",
    }])
    bypass = normalize_dast_findings("bypass_403", [{
        "url": "https://app.example.com/admin",
        "bypass_method": "Header: X-Original-URL",
        "status": 200,
        "severity": "high",
    }])
    cache_poisoning = normalize_dast_findings("cache_poisoning", [{
        "url": "https://app.example.com/",
        "unkeyed_header": "X-Forwarded-Host",
        "cache_status": "HIT",
        "details": "Header reflected in body",
        "severity": "high",
    }])

    assert blind_xss[0]["category"] == "blind_xss"
    assert blind_xss[0]["url"] == "https://app.example.com/api/feedback"
    assert blind_xss[0]["severity"] == "medium"
    assert mass_assignment[0]["category"] == "mass_assignment"
    assert mass_assignment[0]["method"] == "PATCH"
    assert bypass[0]["finding_type"] == "403_bypass"
    assert bypass[0]["evidence"].startswith("Header: X-Original-URL")
    assert cache_poisoning[0]["category"] == "cache_poisoning"
    assert cache_poisoning[0]["severity"] == "high"


def test_cache_poison_without_hit_stays_low_confidence():
    result = normalize_dast_findings("cache_poisoning", [{
        "url": "https://app.example.com/",
        "unkeyed_header": "X-Forwarded-Host",
        "cache_status": "MISS",
        "details": "Header reflected in body without cache hit",
        "severity": "low",
        "confidence": "LOW",
    }])

    assert result[0]["severity"] == "low"
    assert result[0]["confidence"] == "low"
