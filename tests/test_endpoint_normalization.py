from core.db import _extract_endpoint_value
from core.schemas import M1Asset
from core.scanner_router import ScannerRouter


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_m1_asset_coerces_string_api_endpoints_to_dicts():
    asset = M1Asset(
        target="example.com",
        api_endpoints=["https://example.com/api/users", "/internal/status"],
    )

    assert asset.api_endpoints[0]["url"] == "https://example.com/api/users"
    assert asset.api_endpoints[0]["method"] == "GET"
    assert asset.api_endpoints[1]["path"] == "/internal/status"


def test_scanner_router_normalizes_mixed_api_endpoint_shapes(tmp_path):
    router = ScannerRouter(str(tmp_path), DummyLogger())

    normalized = router._normalize_api_endpoints([
        "https://example.com/api/users",
        {"url": "https://example.com/api/users", "method": "GET", "status": 200},
        {"path": "/relative/health", "method": "POST"},
        {"url": "https://example.com/api/admin", "status_code": 403, "source": "kiterunner"},
    ], source="linkfinder")

    by_url = {item["url"]: item for item in normalized}

    assert len(normalized) == 3
    assert by_url["https://example.com/api/users"]["status_code"] == 200
    assert by_url["/relative/health"]["status_code"] is None
    assert by_url["https://example.com/api/admin"]["source"] == "kiterunner"


def test_extract_endpoint_value_handles_dict_and_string_shapes():
    assert _extract_endpoint_value("https://example.com/api/users") == "https://example.com/api/users"
    assert _extract_endpoint_value({"url": "https://example.com/api/admin"}) == "https://example.com/api/admin"
    assert _extract_endpoint_value({"path": "/internal/health"}) == "/internal/health"
