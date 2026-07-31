#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PENLABS — CENTRALIZED PROXY ENVIRONMENT BUILDER
=================================================
Builds proxy environment variable dicts (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY,
NO_PROXY) from Config settings, ensuring ALL child processes spawned via
process_manager route traffic through the configured proxy infrastructure.

This solves the critical gap where StealthNet only patches Python `requests`
calls but subprocess tools (nmap, nuclei, curl, httpx, etc.) were going
direct to target, leaking the operator's real IP.

Architecture:
    Config (proxy settings)
        └─> build_proxy_env(scan_mode)
                └─> returns {HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY}
                        └─> merged into subprocess env by process_manager

Usage:
    from core.proxy_env import build_proxy_env, get_proxy_env_for_mode

    # Get proxy env for a specific scan mode
    env_vars = build_proxy_env("exploit")
    # => {"HTTP_PROXY": "socks5h://127.0.0.1:9050", ...}

    # Get proxy env based on current ProxyRelay (if running)
    env_vars = build_proxy_env("recon", relay_port=8888)
    # => {"HTTP_PROXY": "http://127.0.0.1:8888", ...}
"""

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)

# Targets that should NEVER be proxied (loopback, metadata, internal)
_DEFAULT_NO_PROXY = ",".join([
    "127.0.0.1",
    "localhost",
    "::1",
    "169.254.169.254",       # AWS IMDS (scanned intentionally by SSRF plugins)
    "metadata.google.internal",
])


def build_proxy_env(
    scan_mode: Optional[str] = None,
    relay_port: Optional[int] = None,
    relay_host: str = "127.0.0.1",
    extra_no_proxy: Optional[str] = None,
) -> dict:
    """
    Build environment variables dict for routing child process traffic
    through the configured proxy infrastructure.

    Resolution priority:
        1. If relay_port is provided → use ProxyRelay (http://127.0.0.1:<port>)
           This routes traffic through StealthNet (JA3 spoof + proxy rotation).
        2. If JA3_SPOOF_ENABLED and JA3 SOCKS5 proxy is configured → use it
        3. If Config has a proxy URL for the scan_mode → use it
        4. Otherwise → return empty dict (direct connection)

    Args:
        scan_mode: One of 'recon', 'fuzz', 'exploit', or a profile name.
                   Maps to Config.RECON_PROXY / FUZZ_PROXY / EXPLOIT_PROXY.
        relay_port: If ProxyRelay is running, its port. Takes highest priority.
        relay_host: ProxyRelay listen address (default: 127.0.0.1).
        extra_no_proxy: Additional comma-separated hosts to exclude from proxy.

    Returns:
        Dict of environment variables to merge into subprocess env.
        Returns empty dict if no proxy should be used (direct mode).
    """
    proxy_url = _resolve_proxy_url(scan_mode, relay_port, relay_host)

    if not proxy_url:
        return {}

    no_proxy = _DEFAULT_NO_PROXY
    if extra_no_proxy:
        no_proxy = f"{no_proxy},{extra_no_proxy}"

    env = {
        # Standard proxy env vars (both cases for maximum tool compatibility)
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "ALL_PROXY": proxy_url,
        "all_proxy": proxy_url,
        "NO_PROXY": no_proxy,
        "no_proxy": no_proxy,
    }

    log.debug(f"[ProxyEnv] Built env: proxy={proxy_url}, no_proxy={no_proxy}")
    return env


def _resolve_proxy_url(
    scan_mode: Optional[str],
    relay_port: Optional[int],
    relay_host: str,
) -> str:
    """
    Resolve the proxy URL to use based on priority chain.

    Returns empty string if direct connection should be used.
    """
    # Priority 1: ProxyRelay (routes through StealthNet with JA3 spoofing)
    if relay_port:
        url = f"http://{relay_host}:{relay_port}"
        log.debug(f"[ProxyEnv] Using ProxyRelay: {url}")
        return url

    # Lazy import to avoid circular dependency at module load time
    try:
        from config import Config
    except ImportError:
        return ""

    # Priority 2: JA3 SOCKS5 proxy (for Go tools: nuclei, httpx, katana)
    if getattr(Config, "JA3_SPOOF_ENABLED", False):
        ja3_host = getattr(Config, "JA3_PROXY_HOST", "127.0.0.1")
        ja3_port = getattr(Config, "JA3_PROXY_PORT", 1080)
        # Only use if the proxy is actually likely running (port != 0)
        if ja3_port:
            url = f"socks5://{ja3_host}:{ja3_port}"
            log.debug(f"[ProxyEnv] Using JA3 SOCKS5 proxy: {url}")
            return url

    # Priority 3: Mode-specific proxy from Config
    if scan_mode:
        proxy_url = _get_mode_proxy(scan_mode, Config)
        if proxy_url:
            log.debug(f"[ProxyEnv] Using mode '{scan_mode}' proxy: {proxy_url}")
            return proxy_url

    # Priority 4: Check PROXY_ROUTING table for routing mode
    if scan_mode:
        routing = getattr(Config, "PROXY_ROUTING", {}).get(scan_mode, {})
        routing_mode = routing.get("mode", "direct")
        if routing_mode == "tor":
            return "socks5h://127.0.0.1:9050"
        elif routing_mode == "fast-proxy":
            # Fall through to mode-specific, which we already checked
            pass

    return ""


def _get_mode_proxy(scan_mode: str, config_cls) -> str:
    """Map scan_mode to Config proxy URL."""
    mode_lower = scan_mode.lower()

    # Direct mode mappings
    if mode_lower in ("recon", "stealth"):
        return getattr(config_cls, "RECON_PROXY", "")
    elif mode_lower in ("fuzz", "web-vuln", "api-bounty"):
        return getattr(config_cls, "FUZZ_PROXY", "")
    elif mode_lower in ("exploit",):
        return getattr(config_cls, "EXPLOIT_PROXY", "")

    # Try Config.get_proxy_url as fallback
    if hasattr(config_cls, "get_proxy_url"):
        return config_cls.get_proxy_url(mode_lower)

    return ""


# ---------------------------------------------------------------------------
# Singleton state: tracks the currently active ProxyRelay port (if any)
# Set by ProxyRelay.start(), read by build_proxy_env() callers.
# ---------------------------------------------------------------------------
_active_relay_port: Optional[int] = None


def set_active_relay(port: int) -> None:
    """Called by ProxyRelay.start() to register the active relay port."""
    global _active_relay_port
    _active_relay_port = port
    log.info(f"[ProxyEnv] Active ProxyRelay registered on port {port}")


def clear_active_relay() -> None:
    """Called by ProxyRelay.stop() to clear the active relay."""
    global _active_relay_port
    _active_relay_port = None
    log.info("[ProxyEnv] Active ProxyRelay cleared")


def get_active_relay_port() -> Optional[int]:
    """Return the currently active ProxyRelay port, if any."""
    return _active_relay_port


def build_proxy_env_auto(scan_mode: Optional[str] = None) -> dict:
    """
    Convenience wrapper: builds proxy env using the active relay port
    (if ProxyRelay is running) or falls back to Config-based resolution.

    This is the recommended function for process_manager to call.
    """
    return build_proxy_env(
        scan_mode=scan_mode,
        relay_port=_active_relay_port,
    )
