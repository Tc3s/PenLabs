import asyncio
import json
import os

import pytest


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_api_breach_route_maps_arjun_results_by_url(monkeypatch, tmp_path):
    from core.registry import PluginRegistry
    from core.scanner_router import ScannerRouter

    class FakeHttpx:
        def check_installed(self):
            return True

        def probe_from_ports(self, host, ports, out_dir, headers, *_args):
            return [{
                "url": "https://api.example.com",
                "port": 443,
                "web_server": "nginx",
                "tech": ["nginx"],
                "title": "API",
            }]

    class FakeKatana:
        def check_installed(self):
            return True

        def run(self, url, out_dir, depth, js_crawl, headless, extra_flags, cookies, headers, proxy, proxy_mode):
            assert proxy_mode == "recon"
            return {
                "urls": ["https://api.example.com/users?id=1"],
                "endpoints": [],
                "js_secrets": [],
            }

    class FakeArjun:
        def check_installed(self):
            return True

        def run(self, urls, out_dir, *args):
            assert urls == ["https://api.example.com"]
            return {"https://api.example.com": ["debug", "tenant"]}

    plugins = {
        "Httpx": FakeHttpx(),
        "Katana": FakeKatana(),
        "Arjun": FakeArjun(),
    }
    monkeypatch.setattr(PluginRegistry, "get", classmethod(lambda cls, name: plugins.get(name)))
    monkeypatch.setattr("core.scanner_router.shutil.which", lambda name: None)

    router = ScannerRouter(str(tmp_path), DummyLogger())

    async def fake_nuclei_batch(*args, **kwargs):
        return []

    router._nuclei_batch_with_retry = fake_nuclei_batch

    result = asyncio.run(router._route_api_breach("1.2.3.4", "example.com", 0, [443]))

    assert result["web_urls"] == ["https://api.example.com"]
    assert result["web_urls_with_params"] == ["https://api.example.com/users?id=1"]
    assert result["hidden_params"]["https://api.example.com"] == ["debug", "tenant"]


def test_api_bounty_route_keeps_canonical_aliases_and_proxy_mode(monkeypatch, tmp_path):
    from core.registry import PluginRegistry
    from core.scanner_router import ScannerRouter

    captured = {}

    class FakeHttpx:
        def check_installed(self):
            return True

        def run(self, scan_targets, out_dir, rate_limit, cookies, headers, proxy_file, proxy_mode):
            assert proxy_mode == "recon"
            return [{"url": "https://app.example.com", "status_code": 403}]

    class FakeKatana:
        def check_installed(self):
            return True

        def run(self, url, out_dir, depth, js_crawl, headless, extra_flags, cookies, headers, proxy):
            return {
                "urls": ["https://app.example.com/profile?id=7"],
                "endpoints": ["https://app.example.com/api/users"],
                "js_files": [],
            }

    class FakeCorsy:
        def run(self, live_urls, out_dir, headers, timeout, max_urls, waf_detected, proxy_mode):
            captured["cors_proxy_mode"] = proxy_mode
            return [{"url": live_urls[0], "details": "wildcard origin"}]

    class FakeGraphQL:
        def run(self, live_urls, out_dir, headers, timeout, max_urls):
            return {
                "endpoints_found": ["https://app.example.com/graphql"],
                "introspection_enabled": [{"url": "https://app.example.com/graphql", "details": "enabled"}],
                "graphql_vulns": [{"endpoint": "https://app.example.com/graphql", "details": "batching enabled"}],
            }

    class FakeBlindXSS:
        def check_installed(self):
            return True

        def run(self, live_urls, out_dir, headers, interactsh_url, timeout, max_urls, proxy_mode):
            captured["blind_xss_proxy_mode"] = proxy_mode
            return {
                "injected_count": 1,
                "forms_found": 1,
                "injections": [{
                    "url": "https://app.example.com/profile",
                    "action": "https://app.example.com/profile",
                    "method": "POST",
                    "fields_injected": ["bio"],
                }],
            }

    class FakeMassAssignment:
        def run(self, urls, auth_token=None, method="POST", payloads=None, headers=None, timeout=15):
            captured["mass_assignment_urls"] = urls
            return [{
                "url": urls[0],
                "method": "POST",
                "severity": "high",
                "evidence": "Response contains injected privilege fields: {'role': 'admin'}",
            }]

    plugins = {
        "Httpx": FakeHttpx(),
        "Katana": FakeKatana(),
        "Corsy": FakeCorsy(),
        "GraphQLProbe": FakeGraphQL(),
        "BlindXSS": FakeBlindXSS(),
        "MassAssignment": FakeMassAssignment(),
    }
    monkeypatch.setattr(PluginRegistry, "get", classmethod(lambda cls, name: plugins.get(name)))
    monkeypatch.setattr("core.scanner_router.shutil.which", lambda name: None)

    router = ScannerRouter(str(tmp_path), DummyLogger())

    async def fake_cache_probe(_live_urls):
        return [{
            "url": "https://app.example.com/",
            "unkeyed_header": "X-Forwarded-Host",
            "cache_status": "HIT",
            "details": "reflected",
            "severity": "high",
        }]

    async def fake_bypass(_urls):
        return [{
            "url": "https://app.example.com/admin",
            "bypass_method": "Header: X-Original-URL",
            "status": 200,
            "severity": "high",
        }]

    router._cache_poison_probe = fake_cache_probe
    router._bypass_403 = fake_bypass

    result = asyncio.run(router._route_api_bounty("1.2.3.4", "example.com", 0, [443], waf_detected=False))

    assert captured["cors_proxy_mode"] == "fuzz"
    assert captured["blind_xss_proxy_mode"] == "fuzz"
    assert captured["mass_assignment_urls"] == ["https://app.example.com/api/users"]
    assert result["cors_findings"] == result["cors_issues"]
    assert len(result["graphql_findings"]) == 2
    assert result["graphql"]["endpoints_found"] == ["https://app.example.com/graphql"]
    categories = {finding["category"] for finding in result["dast_findings"]}
    assert {"cors", "graphql", "blind_xss", "mass_assignment", "bypass_403", "cache_poisoning"} <= categories


def test_web_vuln_route_runs_blind_xss_and_mass_assignment(monkeypatch, tmp_path):
    from core.registry import PluginRegistry
    from core.scanner_router import ScannerRouter

    captured = {}

    class FakeHttpx:
        def check_installed(self):
            return True

        def probe_from_ports(self, host, ports, out_dir, headers, proxy_file, extra_args, proxy_mode):
            assert proxy_mode == "recon"
            return [{"url": "https://web.example.com", "port": 443, "web_server": "nginx", "tech": ["nginx"], "title": "Web"}]

    class FakeKatana:
        def check_installed(self):
            return True

        def run(self, url, out_dir, depth, js_crawl, headless, extra_flags, cookies, headers, proxy):
            return {
                "urls": ["https://web.example.com/profile?id=9"],
                "endpoints": ["https://web.example.com/api/users"],
            }

    class FakeBlindXSS:
        def check_installed(self):
            return True

        def run(self, live_urls, out_dir, headers, interactsh_url, timeout, max_urls, proxy_mode):
            captured["blind_xss_proxy_mode"] = proxy_mode
            return {
                "injected_count": 1,
                "forms_found": 1,
                "injections": [{
                    "url": "https://web.example.com/profile",
                    "action": "https://web.example.com/profile",
                    "method": "POST",
                    "fields_injected": ["bio"],
                }],
            }

    class FakeMassAssignment:
        def run(self, urls, auth_token=None, method="POST", payloads=None, headers=None, timeout=15):
            captured["mass_assignment_urls"] = urls
            return [{
                "url": urls[0],
                "method": "POST",
                "severity": "high",
                "evidence": "Response contains injected privilege fields: {'role': 'admin'}",
            }]

    plugins = {
        "Httpx": FakeHttpx(),
        "Katana": FakeKatana(),
        "BlindXSS": FakeBlindXSS(),
        "MassAssignment": FakeMassAssignment(),
    }
    monkeypatch.setattr(PluginRegistry, "get", classmethod(lambda cls, name: plugins.get(name)))
    monkeypatch.setattr("core.scanner_router.shutil.which", lambda name: None)

    router = ScannerRouter(str(tmp_path), DummyLogger())

    async def fake_nuclei_batch(*args, **kwargs):
        return []

    async def fake_gowitness(_live_urls, _out_dir):
        return ""

    async def fake_vhost(_ip, _target, _out_dir):
        return []

    router._nuclei_batch_with_retry = fake_nuclei_batch
    router._run_gowitness = fake_gowitness
    router._run_vhost_discovery = fake_vhost

    result = asyncio.run(router._route_web_vuln("1.2.3.4", "example.com", 0, [443]))

    assert captured["blind_xss_proxy_mode"] == "fuzz"
    assert captured["mass_assignment_urls"] == ["https://web.example.com/api/users", "https://web.example.com/profile?id=9"]
    categories = {finding["category"] for finding in result["dast_findings"]}
    assert {"blind_xss", "mass_assignment"} <= categories
    assert result["blind_xss"]["injected_count"] == 1
    assert len(result["mass_assignment_findings"]) == 1
    assert result["summary"]["mode"] == "web-vuln"
    assert result["summary"]["blind_xss"] == 1
    assert result["summary"]["mass_assignment"] == 1
    assert result["summary"]["xss"] == 0
    handoff = (tmp_path / "web_vuln_handoff.md").read_text(encoding="utf-8")
    assert "| Blind XSS | 1 |" in handoff
    assert "| Mass Assignment | 1 |" in handoff
    assert "Response contains injected privilege fields" in handoff


def test_asset_discovery_normalizes_katana_and_linkfinder_outputs(monkeypatch, tmp_path):
    from core.registry import PluginRegistry
    from core.scanner_router import ScannerRouter

    class FakeHttpx:
        def check_installed(self):
            return True

        def run(self, all_targets, out_dir, rate_limit, cookies, headers, proxy_file, proxy_mode):
            assert proxy_mode == "recon"
            return [{"url": "https://app.example.com", "status_code": 200, "port": 443, "web_server": "nginx", "tech": ["nginx"], "title": "App"}]

    class FakeKatana:
        def check_installed(self):
            return True

        def run(self, url, katana_dir, depth, js_crawl, headless, extra_flags, cookies, headers, proxy, rate_limit, proxy_mode):
            assert proxy_mode == "recon"
            output_path = os.path.join(katana_dir, "katana_output.jsonl")
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(json.dumps({
                    "urls": ["https://app.example.com/profile?id=7"],
                    "endpoints": ["https://app.example.com/api/users", "https://app.example.com/api/users"],
                    "js_files": ["https://app.example.com/static/app.js"],
                    "js_secrets": [{"type": "Token", "source": "https://app.example.com/static/app.js", "value": "katana-token"}],
                }) + "\n")

    class FakeLinkFinder:
        def run(self, js_files, out_dir, timeout, max_files):
            return {
                "endpoints": ["https://app.example.com/api/admin", "https://app.example.com/api/users"],
                "secrets": [{"type": "Token", "source": "https://app.example.com/static/app.js", "value": "lf-token"}],
            }

    plugins = {
        "Httpx": FakeHttpx(),
        "Katana": FakeKatana(),
        "LinkFinder": FakeLinkFinder(),
    }
    monkeypatch.setattr(PluginRegistry, "get", classmethod(lambda cls, name: plugins.get(name)))
    monkeypatch.setattr("core.scanner_router.shutil.which", lambda name: None)

    router = ScannerRouter(str(tmp_path), DummyLogger())

    async def fake_nuclei_batch(*args, **kwargs):
        return []

    router._nuclei_batch_with_retry = fake_nuclei_batch

    result = asyncio.run(router._route_asset_discovery("1.2.3.4", "example.com", 0, [443]))

    api_by_url = {item["url"]: item for item in result["api_endpoints"]}
    assert "https://app.example.com/api/users" in api_by_url
    assert "https://app.example.com/api/admin" in api_by_url
    assert "https://app.example.com/profile?id=7" in api_by_url
    assert api_by_url["https://app.example.com/api/users"]["source"] in {"katana", "linkfinder"}
    assert result["secrets"] == result["js_secrets"]
    assert len(result["js_secrets"]) == 2
    assert result["summary"]["mode"] == "asset-discovery"
    assert result["summary"]["api_endpoints"] == 3
    assert result["summary"]["js_files"] == 1
    assert result["summary"]["secrets"] == 2
