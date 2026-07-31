import asyncio


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_performance_budget_is_mode_aware(monkeypatch):
    from core.performance import performance_budget

    monkeypatch.delenv("PENLABS_FFUF_TARGETS", raising=False)
    stealth = performance_budget("stealth")
    full = performance_budget("full-audit")

    assert stealth.ffuf_concurrency == 1
    assert stealth.ffuf_threads < full.ffuf_threads
    assert stealth.ffuf_targets < full.ffuf_targets
    assert full.ffuf_concurrency >= 3


def test_performance_budget_allows_env_override(monkeypatch):
    from core.performance import performance_budget

    monkeypatch.setenv("PENLABS_FFUF_TARGETS", "7")
    monkeypatch.setenv("PENLABS_FFUF_CONCURRENCY", "4")

    budget = performance_budget("web-vuln")

    assert budget.ffuf_targets == 7
    assert budget.ffuf_concurrency == 4


def test_unique_http_urls_by_host_preserves_first_and_limit():
    from core.performance import unique_http_urls_by_host

    urls = [
        "https://app.example.com",
        "https://app.example.com/admin",
        "http://api.example.com",
        "mailto:security@example.com",
        "https://cdn.example.com/a.js",
    ]

    assert unique_http_urls_by_host(urls, limit=2) == [
        "https://app.example.com",
        "http://api.example.com",
    ]


def test_run_ffuf_many_dedupes_hosts_and_respects_concurrency(tmp_path):
    from core.performance import PerformanceBudget
    from core.scanner_router import ScannerRouter

    router = ScannerRouter(str(tmp_path), DummyLogger(), mode="web-vuln")
    router.performance = PerformanceBudget(ffuf_targets=4, ffuf_concurrency=2, ffuf_threads=10, ffuf_rate=150)
    router._heavy_task_semaphore = asyncio.Semaphore(10)

    active = 0
    max_active = 0
    calls = []

    async def fake_run_ffuf(url, out_dir, headers=None, purpose="web_content", wordlist=""):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        calls.append((url, out_dir, headers, purpose, wordlist))
        await asyncio.sleep(0.02)
        active -= 1
        return [f"{url.rstrip('/')}/admin"]

    router._run_ffuf = fake_run_ffuf

    results = asyncio.run(router._run_ffuf_many(
        [
            "https://app.example.com",
            "https://app.example.com/login",
            "https://api.example.com",
            "https://cdn.example.com",
        ],
        str(tmp_path / "ffuf"),
        headers={"X-Test": "1"},
        purpose="web_content",
    ))

    assert [call[0] for call in calls] == [
        "https://app.example.com",
        "https://api.example.com",
        "https://cdn.example.com",
    ]
    assert max_active <= 2
    assert results == [
        "https://app.example.com/admin",
        "https://api.example.com/admin",
        "https://cdn.example.com/admin",
    ]


def test_run_katana_many_respects_crawler_concurrency(tmp_path):
    from core.performance import PerformanceBudget
    from core.scanner_router import ScannerRouter

    router = ScannerRouter(str(tmp_path), DummyLogger(), mode="web-vuln")
    router.performance = PerformanceBudget(crawler_concurrency=2)
    router._heavy_task_semaphore = asyncio.Semaphore(10)

    active = 0
    max_active = 0
    calls = []

    class FakeKatana:
        def run(self, target, out_dir, depth, js_crawl, headless, proxy_mode):
            nonlocal active, max_active
            active += 1
            max_active = max(max_active, active)
            calls.append(target)
            import time
            time.sleep(0.02)
            active -= 1
            return {"urls": [f"{target.rstrip('/')}/profile?id=1"], "endpoints": []}

    results = asyncio.run(router._run_katana_many(
        FakeKatana(),
        [
            "https://app.example.com",
            "https://app.example.com",
            "https://api.example.com",
            "https://cdn.example.com",
        ],
        "web_vuln",
        limit=4,
        depth=3,
        js_crawl=True,
        headless=False,
        proxy_mode="fuzz",
    ))

    assert calls == [
        "https://app.example.com",
        "https://api.example.com",
        "https://cdn.example.com",
    ]
    assert max_active <= 2
    assert len(results) == 3


def test_router_auth_headers_drop_none_host(tmp_path):
    from core.scanner_router import ScannerRouter

    router = ScannerRouter(str(tmp_path), DummyLogger(), mode="sniper")

    headers = router._get_auth_headers()

    assert "Host" not in headers
    assert all(value is not None for value in headers.values())


def test_web_ports_from_services_filters_non_http_ports():
    from core.scanner_router import ScannerRouter

    ports = [
        {"port": 21, "service": "ftp", "version": "vsftpd 2.3.4"},
        {"port": 22, "service": "ssh", "version": "OpenSSH"},
        {"port": 80, "service": "http", "version": "Apache httpd"},
        {"port": 3306, "service": "mysql", "version": "MySQL"},
        {"port": 8180, "service": "http", "version": "Apache Tomcat/Coyote JSP engine"},
        {"port": 8009, "service": "ajp13", "version": "Apache Jserv"},
    ]

    assert ScannerRouter._web_ports_from_services(ports) == [80, 8180]
