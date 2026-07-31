import os
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from core.scanner_router import ScannerRouter
from plugins.stealth_net_plugin import StealthNetPlugin
from proxy.ja3_proxy import JA3ProfileStore, JA3Proxy, build_go_tool_proxy_args
from proxy.proxy_launcher import JA3ProbeLauncher, JA3ProxyLauncher
from plugins.ja3_proxy_plugin import JA3ProxyPlugin


class DummyLogger:
    def info(self, *args, **kwargs): pass
    def warning(self, *args, **kwargs): pass
    def error(self, *args, **kwargs): pass
    def debug(self, *args, **kwargs): pass
    def success(self, *args, **kwargs): pass
    def phase(self, *args, **kwargs): pass


def test_profile_store_loads_default_profiles():
    store = JA3ProfileStore()

    assert "chrome120" in store.profiles
    assert re.fullmatch(r"[0-9a-f]{32}", store.get("chrome120")["ja3_hash"])


def test_profile_store_missing_file_uses_empty_profiles(tmp_path):
    store = JA3ProfileStore(tmp_path / "missing.yaml")

    assert store.profiles == {}
    assert store.get("missing") == {}


def test_ja3_proxy_defaults_and_runtime_status():
    proxy = JA3Proxy()

    assert proxy.listen_host == "127.0.0.1"
    assert proxy.listen_port == 1080
    assert proxy.profile_name == "chrome120"
    assert proxy.status()["profile"] == "chrome120"
    assert proxy.status()["ja3_hash"] == proxy.profile["ja3_hash"]


def test_get_spec_without_utls_fails_gracefully():
    with patch("proxy.ja3_proxy.HAS_UTLS", False):
        proxy = JA3Proxy()
        with pytest.raises(RuntimeError, match="utls not installed"):
            proxy.get_spec()


def test_go_tool_proxy_args_are_tool_specific():
    assert build_go_tool_proxy_args("nuclei", "127.0.0.1", 1080) == ["-proxy-socks5", "127.0.0.1:1080"]
    assert build_go_tool_proxy_args("httpx", "127.0.0.1", 1080) == ["-http-proxy", "socks5://127.0.0.1:1080"]
    assert build_go_tool_proxy_args("katana", "127.0.0.1", 1080) == ["-proxy", "socks5://127.0.0.1:1080"]
    assert build_go_tool_proxy_args("unknown", "127.0.0.1", 1080) == []


def test_proxy_launcher_builds_start_command_without_running_process(tmp_path):
    launcher = JA3ProxyLauncher(listen_host="127.0.0.1", listen_port=18080, profile="firefox120")

    cmd = launcher.build_command()

    assert cmd[:3] == [sys.executable, "-m", "proxy.ja3_proxy"]
    assert "--listen" in cmd
    assert "127.0.0.1:18080" in cmd
    assert "--profile" in cmd
    assert "firefox120" in cmd


def test_go_utls_probe_launcher_points_to_real_backend():
    launcher = JA3ProbeLauncher(profile="chrome120", url="https://ja3er.com/json")

    cmd = launcher.build_command()

    assert cmd[:3] == ["go", "run", "."]
    assert launcher.workdir.name == "ja3probe"
    assert "--profile" in cmd
    assert "chrome120" in cmd
    assert "--url" in cmd
    assert "https://ja3er.com/json" in cmd


def test_go_utls_probe_source_imports_refraction_utls():
    source = Path("proxy/cmd/ja3probe/main.go").read_text(encoding="utf-8")

    assert "github.com/refraction-networking/utls" in source
    assert "HelloChrome_Auto" in source
    assert "UClient" in source


def test_plugin_exposes_env_and_run_status():
    plugin = JA3ProxyPlugin()

    result = plugin.run(action="env", host="127.0.0.1", port=1080)

    assert plugin.name() == "JA3Proxy"
    assert result["ALL_PROXY"] == "socks5h://127.0.0.1:1080"
    assert result["NMAP_PROXY_SOCKS5"] == "yes"


def test_scanner_router_ja3_env_respects_config(monkeypatch, tmp_path):
    from config import Config

    router = ScannerRouter(str(tmp_path), DummyLogger())
    monkeypatch.setattr(Config, "JA3_SPOOF_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "JA3_PROXY_HOST", "127.0.0.1", raising=False)
    monkeypatch.setattr(Config, "JA3_PROXY_PORT", 1080, raising=False)
    monkeypatch.setattr(router, "_ja3_proxy_available", lambda: True)

    env = router._setup_ja3_env()

    assert env["ALL_PROXY"] == "socks5h://127.0.0.1:1080"
    assert env["HTTP_PROXY"] == "socks5h://127.0.0.1:1080"
    assert env["HTTPS_PROXY"] == "socks5h://127.0.0.1:1080"
    assert env["NMAP_PROXY_SOCKS5"] == "yes"

    monkeypatch.setattr(Config, "JA3_SPOOF_ENABLED", False, raising=False)
    assert router._setup_ja3_env() == {}


def test_scanner_router_tool_args_respect_config(monkeypatch, tmp_path):
    from config import Config

    router = ScannerRouter(str(tmp_path), DummyLogger())
    monkeypatch.setattr(Config, "JA3_SPOOF_ENABLED", True, raising=False)
    monkeypatch.setattr(Config, "JA3_PROXY_HOST", "127.0.0.1", raising=False)
    monkeypatch.setattr(Config, "JA3_PROXY_PORT", 1080, raising=False)
    monkeypatch.setattr(router, "_ja3_proxy_available", lambda: True)

    assert router._ja3_tool_args("nuclei") == ["-proxy-socks5", "127.0.0.1:1080"]
    assert router._ja3_tool_args("katana") == ["-proxy", "socks5://127.0.0.1:1080"]


def test_stealth_net_tls_fp_returns_ja3_hash_when_curl_cffi_available(monkeypatch):
    monkeypatch.setattr("plugins.stealth_net_plugin.HAS_CURL_CFFI", True)
    fp = StealthNetPlugin().get_tls_fp("example.com")

    assert "ja3:" in fp
    assert re.search(r"hash=[0-9a-f]{32}", fp)


def test_stealth_net_tls_fp_falls_back_without_curl_cffi(monkeypatch):
    monkeypatch.setattr("plugins.stealth_net_plugin.HAS_CURL_CFFI", False)

    assert StealthNetPlugin().get_tls_fp("example.com") == "Generic Python Requests (No JA3 Spoof)"
