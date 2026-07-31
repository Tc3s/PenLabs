from core.auth_context import AuthContext
from core.cloud_infra_depth import summarize_cloud_infra_depth
from core.correlation import correlate_attack_paths
from core.endpoint_store import EndpointStore
from core.dry_run_snapshot import build_dry_run_snapshot
from core.knowledge_base import build_knowledge_profile, enrich_dast_findings_with_knowledge, framework_hints_for_tech
from core.plugin_strategy import build_strategy_matrix, build_strategy_profile, merge_nuclei_tags
from core.verification import annotate_verification, bucket_findings, bucket_summary
from core.verification_replay import replay_verify_finding, replay_verify_findings


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_endpoint_store_merges_crawler_api_and_arjun_feedback():
    store = EndpointStore(target="example.com")
    store.add_many(["https://app.example.com/api/users?id=7"], source="katana")
    store.add({"url": "https://app.example.com/api/users?id=7", "status": 200, "length": 1234}, source="kiterunner")
    store.add_hidden_params({"https://app.example.com/api/users?id=7": ["debug", "role"]})

    endpoints = store.all()

    assert len(endpoints) == 1
    assert endpoints[0]["status_code"] == 200
    assert endpoints[0]["is_api_like"] is True
    assert endpoints[0]["is_parameterized"] is True
    assert {"katana", "kiterunner", "arjun"} <= set(endpoints[0]["sources"])
    assert endpoints[0]["hidden_params"] == ["debug", "role"]


def test_auth_context_builds_dual_user_headers_and_extracts_csrf():
    ctx = AuthContext(cookie="sid=abc")
    ctx.user_a.token = "token-a"
    ctx.user_b.token = "Bearer token-b"

    token = ctx.extract_csrf('<input name="csrf" value="csrf-token-12345">')

    assert token == "csrf-token-12345"
    assert ctx.has_dual_user() is True
    assert ctx.user_headers("A")["Authorization"] == "Bearer token-a"
    assert ctx.user_headers("B")["Authorization"] == "Bearer token-b"
    assert ctx.user_headers("A")["Cookie"] == "sid=abc"
    assert ctx.default_headers()["X-CSRF-Token"] == "csrf-token-12345"


def test_auth_context_refresh_updates_token_cookie_and_csrf():
    class FakeCookies(dict):
        def items(self):
            return {"sid": "fresh"}.items()

    class FakeResponse:
        status_code = 200
        text = ""
        cookies = FakeCookies()

        def json(self):
            return {"auth": {"token": "new-token"}, "csrf": "csrf-fresh"}

    class FakeSession:
        def request(self, *args, **kwargs):
            return FakeResponse()

    ctx = AuthContext(profile={
        "refresh": {
            "url": "https://auth.example.com/login",
            "token_path": "auth.token",
            "csrf_path": "csrf",
        }
    })

    assert ctx.refresh_if_needed(force=True, session=FakeSession()) is True
    assert ctx.default_headers()["Authorization"] == "Bearer new-token"
    assert ctx.default_headers()["Cookie"] == "sid=fresh"
    assert ctx.default_headers()["X-CSRF-Token"] == "csrf-fresh"


def test_verification_buckets_classify_pass2_and_confirmed_findings():
    findings = annotate_verification([
        {"category": "xss", "url": "https://app.example.com/?q=1", "evidence": "payload reflected"},
        {"category": "ssrf", "url": "https://app.example.com/fetch?url=x", "confidence": "low"},
        {"category": "cache_poisoning", "url": "https://app.example.com", "raw": {"cache_status": "HIT"}},
        {"category": "open_redirect", "url": "https://app.example.com/r", "raw": {"status": 404}},
    ])
    summary = bucket_summary(bucket_findings(findings))

    assert summary["confirmed"] == 2
    assert summary["suspected"] == 1
    assert summary["noise"] == 1
    assert [f for f in findings if f["category"] == "ssrf"][0]["needs_pass2"] is True


def test_verification_replay_confirms_bypass_and_cache_poisoning():
    class FakeResponse:
        def __init__(self, status_code=200, text="", headers=None):
            self.status_code = status_code
            self.text = text
            self.headers = headers or {}

    class FakeSession:
        def __init__(self):
            self.calls = 0

        def get(self, url, **kwargs):
            self.calls += 1
            if "plcb=" in url:
                marker = url.split("plcb=", 1)[1]
                return FakeResponse(200, marker, {"X-Cache": "HIT"})
            if self.calls == 1:
                return FakeResponse(403)
            return FakeResponse(200)

    findings = replay_verify_findings([
        {
            "category": "bypass_403",
            "url": "https://app.example.com/admin",
            "raw": {"bypass_method": "Header: X-Forwarded-For"},
            "verification_status": "suspected",
            "needs_pass2": True,
        },
        {
            "category": "cache_poisoning",
            "url": "https://app.example.com/",
            "raw": {"unkeyed_header": "X-Forwarded-Host"},
            "verification_status": "suspected",
            "needs_pass2": True,
        },
    ], session=FakeSession())

    assert [f["verification_status"] for f in findings] == ["confirmed", "confirmed"]


def test_verification_replay_confirms_external_redirect():
    class FakeResponse:
        status_code = 302
        text = ""
        headers = {"Location": "https://evil.example/cb"}

    class FakeSession:
        def get(self, *args, **kwargs):
            return FakeResponse()

    finding = replay_verify_finding(
        {"category": "open_redirect", "url": "https://app.example.com/r?next=https://evil.example/cb"},
        session=FakeSession(),
    )

    assert finding["verification_status"] == "confirmed"


def test_strategy_profiles_use_waf_tech_and_parameter_context():
    knowledge = build_knowledge_profile({
        "tech_stack": ["Next.js"],
        "dast_findings": [{"category": "ssrf", "url": "https://app.example.com/_next/image?url=x"}],
        "api_endpoints": [{"url": "https://app.example.com/api/users"}],
    }, "api-bounty", "example.com")
    nuclei = build_strategy_profile(
        mode="api-bounty",
        tool="nuclei",
        waf_detected=True,
        tech_stack=["WordPress"],
        parameterized_count=3,
        knowledge_profile=knowledge,
    )
    matrix = build_strategy_matrix("infra-smash", {"tech_stack": ["kubernetes"], "parameterized_count": 0, "knowledge_profile": knowledge})

    assert nuclei["proxy_mode"] == "exploit"
    assert {"wordpress", "sqli", "xss", "redirect", "ssrf"} <= set(nuclei["tags"])
    assert "wordpress" in merge_nuclei_tags(["cve"], nuclei)
    assert matrix["nmap"]["timing"] == "T4"
    assert "k8s" in matrix["nuclei"]["tags"]
    assert "Next.js / React SSR" in matrix["nuclei"]["knowledge_frameworks"]


def test_knowledge_base_enriches_findings_and_builds_manual_handoff():
    findings = enrich_dast_findings_with_knowledge([
        {"category": "bola", "url": "https://app.example.com/api/orders/2", "verification_status": "manual_review"},
        {"category": "open_redirect", "url": "https://app.example.com/oauth/callback?next=x", "verification_status": "confirmed"},
    ])
    profile = build_knowledge_profile({
        "tech_stack": ["Next.js"],
        "api_endpoints": [{"url": "https://app.example.com/api/orders/1"}],
        "web_urls_with_params": ["https://app.example.com/fetch?url=https://x"],
        "dast_findings": findings,
    }, "api-bounty", "example.com")
    hints = framework_hints_for_tech(["Next.js"])

    assert {"AUTHZ", "TENANT", "API"} <= set(findings[0]["technique_codes"])
    assert "WSTG-ATHZ-04" in findings[0]["wstg_refs"]
    assert hints[0]["framework"] == "Next.js / React SSR"
    assert "SSRF" in profile["technique_codes"]
    assert profile["manual_handoff"]
    assert any(item["category"] == "bola" for item in profile["manual_handoff"])


def test_correlation_and_cloud_infra_depth_summarize_manual_followup():
    result = {
        "web_urls": ["https://app.example.com/oauth/callback"],
        "api_endpoints": [{"url": "https://app.example.com/api/users"}],
        "dast_findings": [
            {"category": "open_redirect", "url": "https://app.example.com/oauth/callback?next=x"},
            {"category": "ssrf", "url": "https://app.example.com/fetch?url=x"},
        ],
        "ports": [{"port": 6443, "service": "kubernetes"}, {"port": 443, "service": "https"}],
        "cloud_findings": {"s3_scanner": [{"bucket": "example-assets"}]},
        "nse_cves": [{"cve": "CVE-2024-0001"}],
        "nuclei_findings": [{"severity": "high"}],
    }

    chains = correlate_attack_paths(result)
    depth = summarize_cloud_infra_depth(result)

    assert {chain["title"] for chain in chains} >= {"Open Redirect + OAuth/SSO", "SSRF + Cloud Metadata"}
    assert chains[0]["score"] >= chains[-1]["score"]
    assert depth["open_ports"] == 2
    assert depth["high_value_services"][0]["class"] == "kubernetes"
    assert depth["cloud_tools"]["s3_scanner"] == 1
    assert depth["triage_items"]
    assert depth["needs_manual_cloud_review"] is True


def test_router_finalizer_attaches_contracts(tmp_path):
    from core.scanner_router import ScannerRouter

    router = ScannerRouter(str(tmp_path), DummyLogger())
    result = router._finalize_scan_contracts(
        {
            "web_urls": ["https://app.example.com"],
            "web_urls_with_params": ["https://app.example.com/search?q=1"],
            "api_endpoints": ["https://app.example.com/api/users"],
            "dast_findings": [{"category": "xss", "url": "https://app.example.com/search?q=1", "evidence": "reflected"}],
            "ports": [{"port": 443, "service": "https"}],
            "cloud_findings": {},
            "nuclei_findings": [],
        },
        "example.com",
        "web-vuln",
    )

    assert result["endpoint_summary"]["endpoints"] == 3
    assert result["verification_summary"]["confirmed"] == 1
    assert result["strategy_profiles"]["nuclei"]["tool"] == "nuclei"
    assert result["knowledge_profile"]["wstg_coverage"]["covered_wstg_refs"]
    assert result["dast_findings"][0]["technique_codes"]
    assert result["wordlist_profile"]["web_content"]["exists"] is True
    assert result["asset_findings"]
    assert result["dry_run_snapshot"]["counts"]["dast_findings"] == 1


def test_dry_run_snapshot_is_stable_and_count_based():
    snapshot = build_dry_run_snapshot(
        {
            "web_urls": ["https://app.example.com"],
            "api_endpoints": [{"url": "https://app.example.com/api/users"}],
            "endpoint_store": [{"url": "https://app.example.com/api/users"}],
            "dast_findings": [{"category": "xss"}, {"category": "ssrf"}],
            "verification_summary": {"confirmed": 1, "suspected": 1},
            "strategy_profiles": {"nuclei": {}, "sqlmap": {}},
        },
        "api-bounty",
    )

    assert snapshot == {
        "mode": "api-bounty",
        "counts": {
            "web_urls": 1,
            "api_endpoints": 1,
            "endpoint_store": 1,
            "dast_findings": 2,
            "nuclei_findings": 0,
            "attack_chains": 0,
        },
        "dast_categories": {"ssrf": 1, "xss": 1},
        "verification_summary": {"confirmed": 1, "suspected": 1},
        "strategy_tools": ["nuclei", "sqlmap"],
    }
