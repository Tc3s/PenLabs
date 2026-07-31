#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical endpoint store for crawler/API discovery feedback loops."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlparse


API_HINTS = (
    "/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/users", "/user",
    "/account", "/profile", "/admin", "/orders", "/order", "/auth",
)


def _coerce_endpoint(entry: Any, source: str = "", default_method: str = "GET") -> dict[str, Any] | None:
    if isinstance(entry, str):
        url = entry.strip()
        raw = {"url": url}
    elif isinstance(entry, dict):
        url = str(entry.get("url", entry.get("path", ""))).strip()
        raw = dict(entry)
        raw.pop("raw", None)
    else:
        return None

    if not url:
        return None

    parsed = urlparse(url)
    status = raw.get("status_code", raw.get("status"))
    length = raw.get("content_length", raw.get("length"))
    params = raw.get("params")
    if params is None:
        params = sorted(name for name, _ in parse_qsl(parsed.query, keep_blank_values=True))

    path = raw.get("path") or (parsed.path if parsed.scheme else url)
    if not path:
        path = "/"

    return {
        "url": url,
        "path": path,
        "method": str(raw.get("method", default_method)).upper(),
        "status": status,
        "status_code": status,
        "length": length,
        "content_length": length,
        "source": str(raw.get("source", source or "unknown")),
        "sources": [str(raw.get("source", source or "unknown"))],
        "params": list(params or []),
        "is_parameterized": bool(params or parsed.query),
        "is_api_like": bool(raw.get("is_api_like")) or any(hint in url.lower() for hint in API_HINTS),
        "raw": raw,
    }


def _score(item: dict[str, Any]) -> int:
    return sum(
        1
        for key in ("status_code", "content_length", "params")
        if item.get(key) not in (None, "", [], "unknown")
    ) + len(item.get("sources", []))


def _primary_source(sources: list[str]) -> str:
    for source in sources:
        if source not in {"web", "api", "crawler", "unknown"}:
            return source
    return sources[0] if sources else "unknown"


@dataclass
class EndpointStore:
    """Dedupe and enrich endpoints discovered by recon/crawler/API tools."""

    target: str = ""
    _items: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)

    def add(self, entry: Any, source: str = "", default_method: str = "GET") -> dict[str, Any] | None:
        item = _coerce_endpoint(entry, source=source, default_method=default_method)
        if not item:
            return None

        key = (item["method"], item["url"])
        existing = self._items.get(key)
        if not existing:
            self._items[key] = item
            return item

        sources = list(dict.fromkeys(existing.get("sources", []) + item.get("sources", [])))
        params = sorted(set(existing.get("params", []) + item.get("params", [])))
        winner = item if _score(item) > _score(existing) else existing
        merged = {**existing, **winner}
        merged["sources"] = sources
        merged["source"] = _primary_source(sources)
        merged["params"] = params
        merged["is_parameterized"] = bool(existing.get("is_parameterized") or item.get("is_parameterized") or params)
        merged["is_api_like"] = bool(existing.get("is_api_like") or item.get("is_api_like"))
        self._items[key] = merged
        return merged

    def add_many(self, entries: list[Any] | tuple[Any, ...] | None, source: str = "", default_method: str = "GET") -> None:
        for entry in entries or []:
            self.add(entry, source=source, default_method=default_method)

    def add_hidden_params(self, hidden_params: dict[str, list[str]] | None, source: str = "arjun") -> None:
        for url, params in (hidden_params or {}).items():
            item = self.add({"url": url, "params": list(params or [])}, source=source)
            if item:
                item["hidden_params"] = sorted(set(item.get("hidden_params", []) + list(params or [])))

    def all(self) -> list[dict[str, Any]]:
        return sorted(self._items.values(), key=lambda item: (item.get("url", ""), item.get("method", "")))

    def api_like(self) -> list[dict[str, Any]]:
        return [item for item in self.all() if item.get("is_api_like")]

    def parameterized_urls(self) -> list[str]:
        return [item["url"] for item in self.all() if item.get("is_parameterized")]

    def dast_targets(self) -> list[str]:
        urls = [item["url"] for item in self.all() if item.get("is_api_like") or item.get("is_parameterized")]
        return list(dict.fromkeys(urls))

    def summary(self) -> dict[str, int]:
        items = self.all()
        return {
            "endpoints": len(items),
            "api_like": len([item for item in items if item.get("is_api_like")]),
            "parameterized": len([item for item in items if item.get("is_parameterized")]),
            "sources": len({src for item in items for src in item.get("sources", [])}),
        }


def build_endpoint_store(target: str, sources: dict[str, list[Any]]) -> EndpointStore:
    store = EndpointStore(target=target)
    for source, entries in sources.items():
        store.add_many(entries, source=source)
    return store
