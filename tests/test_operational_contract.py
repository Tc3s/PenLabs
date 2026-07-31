from core.operational_contract import (
    normalize_asset_findings,
    normalize_cloud_findings,
    normalize_exposure_findings,
    normalize_infra_findings,
)
from core.schemas import M1Asset


def test_operational_contract_normalizes_asset_exposure_infra_cloud():
    asset = {
        "target": "example.com",
        "ip": "1.2.3.4",
        "subdomains": ["api.example.com"],
        "web_urls": ["https://api.example.com"],
        "api_endpoints": [{"url": "https://api.example.com/v1/users", "source": "katana"}],
        "js_secrets": [{"type": "API key", "source": "https://api.example.com/app.js", "value": "redacted"}],
        "ports": [{"port": 443, "service": "https"}],
        "nse_cves": [{"cve": "CVE-2024-0001", "port": 443, "source": "Nmap-NSE"}],
        "cloud_findings": {
            "s3_scanner": [{"bucket": "example-assets", "severity": "medium"}],
            "cloud_enum": {"aws": [{"resource": "assets.s3.amazonaws.com", "type": "s3"}]},
        },
    }

    assert len(normalize_asset_findings(asset)) == 3
    assert normalize_exposure_findings(asset)[0]["category"] == "exposure"
    assert len(normalize_infra_findings(asset)) == 2
    assert len(normalize_cloud_findings(asset)) == 2


def test_m1_asset_populates_operational_contract_aliases():
    m1 = M1Asset(
        target="example.com",
        ip="1.2.3.4",
        subdomains=["www.example.com"],
        web_urls=["https://www.example.com"],
        api_endpoints=["https://www.example.com/api"],
        cloud_findings={"s3_scanner": [{"bucket": "example-assets"}]},
        ports=[{"port": 80, "service": "http"}],
    )

    assert m1.asset_findings
    assert m1.cloud_inventory_findings
    assert m1.infra_findings
    assert m1.api_endpoints[0]["url"] == "https://www.example.com/api"
