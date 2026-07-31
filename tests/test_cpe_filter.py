import pytest

from core import cpe_filter
from scripts.Module2_VulnAnalysis import VulnAnalyzer


def test_cross_validate_drops_conflicting_web_server_cpe():
    nmap_cpes = [
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*",
    ]

    filtered = cpe_filter.SmartCPEFilter.cross_validate(nmap_cpes, ["Nginx", "PHP"])

    assert filtered == ["cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"]


def test_version_range_matcher_supports_regex_interval_and_compound():
    assert cpe_filter.VersionRangeMatcher.match_range("2.4.49", r"2\.4\.49") is True
    assert cpe_filter.VersionRangeMatcher.match_range("2.4.51", "2.4.0-2.4.49") is False
    assert cpe_filter.VersionRangeMatcher.match_range("2.4.49", ">=2.4.0,<2.4.50") is True
    assert cpe_filter.VersionRangeMatcher.match_range("2.4.50", ">=2.4.0,<2.4.50") is False


def test_os_gate_drops_windows_only_cve_on_linux_target():
    assert cpe_filter.OSGate.is_compatible("CVE-2017-0144", "linux") is False
    assert cpe_filter.OSGate.is_compatible("CVE-2017-0144", "windows") is True
    assert cpe_filter.OSGate.is_compatible("CVE-2021-41773", "linux") is True


def test_epss_ranker_orders_kev_then_epss_then_confidence():
    hits = [
        cpe_filter.CVEHit("CVE-A", confidence=0.9, epss_score=0.05, in_kev=False),
        cpe_filter.CVEHit("CVE-B", confidence=0.9, epss_score=0.8, in_kev=False),
        cpe_filter.CVEHit("CVE-C", confidence=0.9, epss_score=0.3, in_kev=True),
    ]

    ranked = cpe_filter.EPSSRanker.rank(hits)

    assert [hit.cve for hit in ranked] == ["CVE-C", "CVE-B", "CVE-A"]


class FakeEPSS:
    def batch_lookup(self, cves):
        return {"CVE-KEEP": {"epss": 0.9}, "CVE-DROP": {"epss": 0.1}}


class FakeKEV:
    def batch_check(self, cves):
        return {"CVE-KEEP": {"is_kev": True}, "CVE-DROP": {"is_kev": False}}


def test_filter_pipeline_applies_version_os_enrichment_and_ranking():
    hits = [
        cpe_filter.CVEHit(
            "CVE-KEEP",
            confidence=0.9,
            match_type="cpe",
            source_rule={"cpe_product": "http_server", "version_regex": "2.4.0-2.4.49"},
        ),
        cpe_filter.CVEHit("CVE-2017-0144", confidence=0.9, match_type="pattern"),
        cpe_filter.CVEHit(
            "CVE-DROP",
            confidence=0.9,
            match_type="cpe",
            source_rule={"cpe_product": "http_server", "version_regex": "2.4.0-2.4.49"},
        ),
    ]

    result = cpe_filter.filter_cves(
        hits,
        ["cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"],
        [],
        target_os="linux",
        epss_plugin=FakeEPSS(),
        kev_plugin=FakeKEV(),
        top_n=None,
    )

    assert [hit.cve for hit, reason in result.dropped] == ["CVE-KEEP", "CVE-2017-0144", "CVE-DROP"]
    assert result.stats["dropped_count"] == 3


def test_vuln_analyzer_match_tech_rule_returns_pipeline_enriched_dicts():
    analyzer = VulnAnalyzer.__new__(VulnAnalyzer)
    analyzer.tech_rules = [
        {
            "pattern": "apache 2.4.49",
            "cve": "CVE-2021-41773",
            "version_regex": "2.4.0-2.4.49",
            "severity": "high",
            "description": "Apache path traversal",
        }
    ]
    analyzer._epss_plugin = None
    analyzer._kev_plugin = None
    analyzer._last_httpx_tech = ["Apache"]
    analyzer._last_target_os = "linux"

    matches = analyzer._match_tech_rule(
        "Apache 2.4.49",
        ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
    )

    assert matches == [
        {
            "cve": "CVE-2021-41773",
            "confidence": 0.9,
            "description": "Apache path traversal",
            "match_type": "pattern",
            "version_mismatch": False,
            "epss_score": 0.0,
            "in_kev": False,
            "severity": "high",
        }
    ]


def test_backport_version_detection():
    assert cpe_filter.EPSSRanker.is_backport_version("2.4.41-4ubuntu3.1") is True
    assert cpe_filter.EPSSRanker.is_backport_version("2.4.37-43.module_el8") is True
    assert cpe_filter.EPSSRanker.is_backport_version("2.4.49") is False


def test_multi_factor_confidence_scoring():
    # Test backport penalty without low EPSS penalty (epss >= 0.001)
    hit_high_epss = cpe_filter.CVEHit("CVE-2021-41773", confidence=0.9, epss_score=0.05, in_kev=False)
    conf_bp = cpe_filter.EPSSRanker.calculate_multi_factor_confidence(hit_high_epss, is_backport=True)
    assert conf_bp == 0.45

    # Test combined backport + low EPSS penalty (epss < 0.001)
    hit_low_epss = cpe_filter.CVEHit("CVE-2021-41773", confidence=0.9, epss_score=0.0005, in_kev=False)
    conf_combined = cpe_filter.EPSSRanker.calculate_multi_factor_confidence(hit_low_epss, is_backport=True)
    assert conf_combined == 0.315

    # Confirmed active verification should override confidence to >= 0.95
    conf_confirmed = cpe_filter.EPSSRanker.calculate_multi_factor_confidence(hit_low_epss, is_backport=True, verification_status="confirmed")
    assert conf_confirmed == 0.95
