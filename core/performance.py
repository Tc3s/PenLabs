#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mode-aware performance budgets for external tool fan-out."""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass(frozen=True)
class PerformanceBudget:
    ffuf_targets: int = 5
    ffuf_concurrency: int = 2
    ffuf_threads: int = 10
    ffuf_rate: int = 150
    ffuf_timeout: int = 300
    crawler_concurrency: int = 2
    kiterunner_targets: int = 30


_MODE_BUDGETS: dict[str, PerformanceBudget] = {
    "stealth": PerformanceBudget(
        ffuf_targets=3, ffuf_concurrency=1, ffuf_threads=3, ffuf_rate=20,
        ffuf_timeout=240, crawler_concurrency=1, kiterunner_targets=10,
    ),
    "asset-discovery": PerformanceBudget(
        ffuf_targets=3, ffuf_concurrency=1, ffuf_threads=5, ffuf_rate=80,
        ffuf_timeout=240, crawler_concurrency=3, kiterunner_targets=20,
    ),
    "sniper": PerformanceBudget(
        ffuf_targets=3, ffuf_concurrency=2, ffuf_threads=8, ffuf_rate=100,
        ffuf_timeout=240, crawler_concurrency=2, kiterunner_targets=15,
    ),
    "fast": PerformanceBudget(
        ffuf_targets=3, ffuf_concurrency=2, ffuf_threads=8, ffuf_rate=120,
        ffuf_timeout=180, crawler_concurrency=2, kiterunner_targets=15,
    ),
    "web-vuln": PerformanceBudget(
        ffuf_targets=5, ffuf_concurrency=2, ffuf_threads=10, ffuf_rate=150,
        ffuf_timeout=300, crawler_concurrency=2, kiterunner_targets=30,
    ),
    "api-bounty": PerformanceBudget(
        ffuf_targets=5, ffuf_concurrency=2, ffuf_threads=10, ffuf_rate=150,
        ffuf_timeout=300, crawler_concurrency=2, kiterunner_targets=30,
    ),
    "api-breach": PerformanceBudget(
        ffuf_targets=5, ffuf_concurrency=2, ffuf_threads=10, ffuf_rate=150,
        ffuf_timeout=300, crawler_concurrency=2, kiterunner_targets=30,
    ),
    "cloud-devops": PerformanceBudget(
        ffuf_targets=3, ffuf_concurrency=2, ffuf_threads=6, ffuf_rate=80,
        ffuf_timeout=240, crawler_concurrency=2, kiterunner_targets=10,
    ),
    "cloud-native": PerformanceBudget(
        ffuf_targets=3, ffuf_concurrency=2, ffuf_threads=6, ffuf_rate=80,
        ffuf_timeout=240, crawler_concurrency=2, kiterunner_targets=10,
    ),
    "infra-smash": PerformanceBudget(
        ffuf_targets=5, ffuf_concurrency=2, ffuf_threads=12, ffuf_rate=180,
        ffuf_timeout=300, crawler_concurrency=2, kiterunner_targets=10,
    ),
    "full-audit": PerformanceBudget(
        ffuf_targets=10, ffuf_concurrency=3, ffuf_threads=15, ffuf_rate=250,
        ffuf_timeout=360, crawler_concurrency=3, kiterunner_targets=50,
    ),
    "continuous": PerformanceBudget(
        ffuf_targets=2, ffuf_concurrency=1, ffuf_threads=5, ffuf_rate=60,
        ffuf_timeout=180, crawler_concurrency=1, kiterunner_targets=10,
    ),
}


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, "").strip() or default)
        return value if value > 0 else default
    except Exception:
        return default


def performance_budget(mode: str) -> PerformanceBudget:
    """Return a bounded performance profile for a tactical mode."""
    budget = _MODE_BUDGETS.get(str(mode or "").strip().lower(), PerformanceBudget())
    return PerformanceBudget(
        ffuf_targets=_env_int("PENLABS_FFUF_TARGETS", budget.ffuf_targets),
        ffuf_concurrency=_env_int("PENLABS_FFUF_CONCURRENCY", budget.ffuf_concurrency),
        ffuf_threads=_env_int("PENLABS_FFUF_THREADS", budget.ffuf_threads),
        ffuf_rate=_env_int("PENLABS_FFUF_RATE", budget.ffuf_rate),
        ffuf_timeout=_env_int("PENLABS_FFUF_TIMEOUT", budget.ffuf_timeout),
        crawler_concurrency=_env_int("PENLABS_CRAWLER_CONCURRENCY", budget.crawler_concurrency),
        kiterunner_targets=_env_int("PENLABS_KITERUNNER_TARGETS", budget.kiterunner_targets),
    )


def unique_http_urls_by_host(urls, *, limit: int | None = None) -> list[str]:
    """Preserve the first HTTP(S) URL per host, optionally capped."""
    selected: list[str] = []
    seen_hosts: set[str] = set()
    for raw in urls or []:
        url = str(raw or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        try:
            parsed = urlparse(url)
        except Exception:
            continue
        host = (parsed.netloc or "").lower()
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        selected.append(url)
        if limit and len(selected) >= limit:
            break
    return selected
