import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from plugins.cloud_enum_plugin import CloudEnumPlugin
from plugins.kube_hunter_plugin import KubeHunterPlugin
from plugins.s3_scanner_plugin import S3ScannerPlugin
from plugins.cloud_plugin import CloudDevOpsPlugin


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_s3_candidate_generation_uses_target_and_wordlist(tmp_path):
    wordlist = tmp_path / "s3.txt"
    wordlist.write_text("backup\nassets\n", encoding="utf-8")

    candidates = S3ScannerPlugin()._generate_bucket_names("www.example.com", str(wordlist))

    assert "example" in candidates
    assert "example-backup" in candidates
    assert "www-example-com-assets" in candidates


def test_s3_public_bucket_parses_list_result(monkeypatch):
    xml = b"""<?xml version='1.0'?><ListBucketResult><Contents><Key>public/a.txt</Key></Contents></ListBucketResult>"""
    response = MagicMock(status_code=200, content=xml, text=xml.decode(), headers={"x-amz-bucket-region": "us-east-1"})
    monkeypatch.setattr("plugins.s3_scanner_plugin.requests.get", lambda *a, **k: response)

    result = S3ScannerPlugin()._check_bucket("example-assets")

    assert result["exists"] is True
    assert result["public"] is True
    assert result["status"] == "PUBLIC_LIST"
    assert result["sample_objects"] == ["public/a.txt"]
    assert result["permissions"]["PutObject"] == "not_tested"


def test_s3_private_existing_bucket_from_403(monkeypatch):
    response = MagicMock(status_code=403, content=b"", text="", headers={"x-amz-bucket-region": "ap-southeast-1"})
    monkeypatch.setattr("plugins.s3_scanner_plugin.requests.get", lambda *a, **k: response)

    result = S3ScannerPlugin()._check_bucket("example-private")

    assert result["exists"] is True
    assert result["public"] is False
    assert result["region"] == "ap-southeast-1"
    assert result["status"] == "EXISTS_NO_LIST"


def test_cloud_enum_command_disables_unselected_providers():
    plugin = CloudEnumPlugin()

    cmd = plugin._build_command("cloud_enum", "example", ["aws", "gcp"])

    assert cmd[:3] == ["cloud_enum", "-k", "example"]
    assert "--disable-azure" in cmd
    assert "--disable-aws" not in cmd
    assert "--disable-gcp" not in cmd


def test_cloud_enum_parse_output_groups_providers():
    output = """
[+] S3 bucket found: https://example-assets.s3.amazonaws.com
[+] Azure container found: https://example.blob.core.windows.net/public
[+] Google bucket FOUND: https://storage.googleapis.com/example-data
"""

    parsed = CloudEnumPlugin()._parse_output(output)

    assert parsed["aws"][0]["resource"] == "https://example-assets.s3.amazonaws.com"
    assert parsed["azure"][0]["resource"] == "https://example.blob.core.windows.net/public"
    assert parsed["gcp"][0]["resource"] == "https://storage.googleapis.com/example-data"


def test_cloud_enum_run_normalizes_subprocess_results(monkeypatch):
    plugin = CloudEnumPlugin()
    monkeypatch.setattr(plugin, "_executable", lambda: "cloud_enum")
    monkeypatch.setattr(plugin, "_keywords", lambda target, extra_keywords=None: ["example"])

    completed = MagicMock(stdout="[+] S3 bucket found: https://example.s3.amazonaws.com\n", stderr="", returncode=0)
    with patch("plugins.cloud_enum_plugin.subprocess.run", return_value=completed) as run:
        results = plugin.run("example.com", providers=["aws"], timeout=1)

    assert run.called
    assert results["aws"][0]["resource"] == "https://example.s3.amazonaws.com"


def test_kube_hunter_command_and_summary():
    plugin = KubeHunterPlugin()

    assert plugin._build_command("https://k8s.example:6443", "remote") == [
        "kube-hunter", "--remote", "https://k8s.example:6443", "--report", "json", "--log", "level=ERROR"
    ]

    report = json.dumps({
        "nodes": [{"type": "APIServer", "location": "https://k8s.example:6443"}],
        "vulnerabilities": [
            {"severity": "high", "vulnerability": "anonymous access"},
            {"severity": "medium", "vulnerability": "dashboard exposed"},
        ],
    })
    parsed = plugin._parse_report(report)

    assert len(parsed["nodes"]) == 1
    assert parsed["summary"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0, "total": 2}


def test_kube_hunter_remote_requires_target():
    with pytest.raises(ValueError, match="target required"):
        KubeHunterPlugin().run(mode="remote")


def test_cloud_native_profile_parses_and_references_cloud_plugins():
    profile = yaml.safe_load(Path("profiles/cloud-native.yaml").read_text(encoding="utf-8"))
    steps = {step["step"]: step for step in profile["pipeline"]}

    assert steps["s3_enumeration"]["tool"] == "s3_scanner"
    assert steps["cloud_storage_enum"]["tool"] == "cloud_enum"
    assert steps["k8s_discovery"]["tool"] == "kube_hunter"
    assert "s3" in steps["vuln_scan"]["config"]["tags"]


def test_cloud_native_route_uses_specialized_plugins(monkeypatch, tmp_path):
    from core.scanner_router import ScannerRouter
    from core.registry import PluginRegistry

    class FakeS3:
        def run(self, target):
            return [{"bucket": "example-assets", "exists": True}]

    class FakeCloudEnum:
        def check_installed(self):
            return True

        def run(self, target, providers, timeout):
            return {"aws": [{"resource": "https://example.s3.amazonaws.com"}], "azure": [], "gcp": []}

    class FakeKubeHunter:
        def check_installed(self):
            return True

        def run(self, target, mode, timeout):
            return {"findings": [{"severity": "high"}], "nodes": [], "summary": {"high": 1}}

    class FakeCloudDevOps:
        def run(self, target, ip, out_dir):
            return {"bucket_findings": [], "takeover_candidates": [], "devops_exposed": [], "nuclei_cloud": []}

    plugins = {
        "S3Scanner": FakeS3(),
        "CloudEnum": FakeCloudEnum(),
        "KubeHunter": FakeKubeHunter(),
        "CloudDevOps": FakeCloudDevOps(),
    }
    monkeypatch.setattr(PluginRegistry, "get", classmethod(lambda cls, name: plugins.get(name)))
    monkeypatch.setattr("core.scanner_router.shutil.which", lambda name: None)

    router = ScannerRouter(str(tmp_path), DummyLogger())

    async def fake_nuclei_batch(*args, **kwargs):
        return []

    router._nuclei_batch_with_retry = fake_nuclei_batch

    result = asyncio.run(router._route_cloud_native("10.0.0.1", "example.com", 0, []))

    assert result["cloud_findings"]["s3_scanner"][0]["bucket"] == "example-assets"
    assert result["cloud_findings"]["cloud_enum"]["aws"][0]["resource"].endswith("amazonaws.com")
    assert result["cloud_findings"]["kube_hunter"]["summary"]["high"] == 1
    assert "cloud_devops" in result["cloud_findings"]


def test_cloud_devops_plugin_basic():
    plugin = CloudDevOpsPlugin()
    assert plugin.name() == "CloudDevOps"
    assert plugin.check_installed() is True
    assert "Cloud/DevOps" in plugin.description()


def test_cloud_devops_check_buckets(monkeypatch):
    plugin = CloudDevOpsPlugin()

    # Mock requests.head
    response = MagicMock(status_code=200)
    monkeypatch.setattr("plugins.cloud_plugin.requests.head", lambda *a, **k: response)

    findings = plugin._check_buckets("example.com")
    assert len(findings) > 0
    assert findings[0]["provider"] == "AWS_S3"
    assert findings[0]["status"] == "PUBLIC_READ"
    assert findings[0]["severity"] == "critical"
