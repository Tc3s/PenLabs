#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authentication context passed consistently into DAST plugins."""

from __future__ import annotations

import re
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any

import requests


CSRF_RE = re.compile(
    r"""(?i)(?:csrf|xsrf|_token)["'\s:=]+([A-Za-z0-9_\-.:]{8,})"""
)
CSRF_INPUT_RE = re.compile(
    r"""(?is)(?:csrf|xsrf|_token).{0,120}?value=["']?([A-Za-z0-9_\-.:]{8,})"""
)


def _parse_header_lines(headers: dict[str, str] | list[str] | str | None) -> dict[str, str]:
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items() if k}
    parsed: dict[str, str] = {}
    values = headers if isinstance(headers, list) else str(headers or "").splitlines()
    for line in values:
        if ":" not in str(line):
            continue
        key, value = str(line).split(":", 1)
        if key.strip():
            parsed[key.strip()] = value.strip()
    return parsed


@dataclass
class AuthIdentity:
    name: str
    token: str = ""
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def merged_headers(self, base_headers: dict[str, str] | None = None) -> dict[str, str]:
        merged = dict(base_headers or {})
        merged.update(self.headers)
        if self.token and "Authorization" not in merged:
            merged["Authorization"] = self.token if self.token.lower().startswith("bearer ") else f"Bearer {self.token}"
        if self.cookie:
            merged["Cookie"] = self.cookie
        return merged


@dataclass
class AuthContext:
    base_headers: dict[str, str] = field(default_factory=dict)
    cookie: str = ""
    user_a: AuthIdentity = field(default_factory=lambda: AuthIdentity(name="userA"))
    user_b: AuthIdentity = field(default_factory=lambda: AuthIdentity(name="userB"))
    csrf_tokens: dict[str, str] = field(default_factory=dict)
    refresh_hooks: dict[str, str] = field(default_factory=dict)
    profile: dict[str, Any] = field(default_factory=dict)
    last_refresh: float = 0.0
    refresh_error: str = ""

    @classmethod
    def from_router(cls, router: Any) -> "AuthContext":
        base_headers = _parse_header_lines(getattr(router, "headers", {}))
        cookie = str(getattr(router, "cookies", "") or "")
        user_a = AuthIdentity(name="userA", token=str(getattr(router, "auth_userA", "") or ""), cookie=cookie)
        user_b = AuthIdentity(name="userB", token=str(getattr(router, "auth_userB", "") or ""), cookie=cookie)
        profile_path = str(getattr(router, "auth_profile", "") or os.getenv("PENLABS_AUTH_PROFILE", ""))
        profile = cls.load_profile(profile_path) if profile_path else {}
        ctx = cls(base_headers=base_headers, cookie=cookie, user_a=user_a, user_b=user_b, profile=profile)
        if profile:
            ctx.apply_profile(profile)
        return ctx

    @staticmethod
    def load_profile(path: str) -> dict[str, Any]:
        if not path or not os.path.exists(path):
            return {}
        with open(path, "r", encoding="utf-8") as fh:
            if path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    return yaml.safe_load(fh) or {}
                except Exception:
                    return {}
            return json.load(fh)

    def apply_profile(self, profile: dict[str, Any]) -> None:
        self.base_headers.update(_parse_header_lines(profile.get("headers")))
        self.cookie = str(profile.get("cookie") or self.cookie or "")
        identities = profile.get("identities", {}) if isinstance(profile.get("identities"), dict) else {}
        for key, identity in (("userA", self.user_a), ("userB", self.user_b)):
            data = identities.get(key, {}) if isinstance(identities.get(key), dict) else {}
            identity.token = str(data.get("token") or identity.token or "")
            identity.cookie = str(data.get("cookie") or identity.cookie or self.cookie or "")
            identity.headers.update(_parse_header_lines(data.get("headers")))
        self.refresh_hooks = profile.get("refresh_hooks", {}) if isinstance(profile.get("refresh_hooks"), dict) else {}

    def default_headers(self) -> dict[str, str]:
        self.refresh_if_needed()
        merged = dict(self.base_headers)
        if self.cookie:
            merged["Cookie"] = self.cookie
        for token_name, token_value in self.csrf_tokens.items():
            merged.setdefault(token_name, token_value)
        return merged

    def user_headers(self, user: str = "A") -> dict[str, str]:
        identity = self.user_b if str(user).upper() == "B" else self.user_a
        return identity.merged_headers(self.default_headers())

    def has_dual_user(self) -> bool:
        return bool(self.user_a.token and self.user_b.token)

    def extract_csrf(self, html: str, header_name: str = "X-CSRF-Token") -> str:
        match = CSRF_INPUT_RE.search(html or "") or CSRF_RE.search(html or "")
        token = match.group(1) if match else ""
        if token:
            self.csrf_tokens[header_name] = token
        return token

    @staticmethod
    def _extract_path(data: Any, path: str) -> Any:
        cur = data
        for part in str(path or "").split("."):
            if not part:
                continue
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur

    def refresh_if_needed(self, force: bool = False, session: requests.Session | None = None) -> bool:
        refresh = self.profile.get("refresh") if isinstance(self.profile.get("refresh"), dict) else {}
        if not refresh:
            return False
        interval = int(refresh.get("interval_seconds", refresh.get("refresh_interval", 600)) or 600)
        now = time.time()
        if not force and self.last_refresh and now - self.last_refresh < interval:
            return False

        url = refresh.get("url") or refresh.get("login_url")
        if not url:
            return False
        method = str(refresh.get("method", "POST")).upper()
        client = session or requests.Session()
        try:
            resp = client.request(
                method,
                url,
                json=refresh.get("json", refresh.get("payload")),
                data=refresh.get("data"),
                headers=_parse_header_lines(refresh.get("headers")),
                timeout=int(refresh.get("timeout", 15)),
                verify=bool(refresh.get("verify_tls", False)),
            )
            if resp.status_code >= 400:
                self.refresh_error = f"refresh failed with status {resp.status_code}"
                self.last_refresh = now
                return False
            try:
                body = resp.json()
            except ValueError:
                body = {"text": resp.text}

            token = self._extract_path(body, refresh.get("token_path", refresh.get("token_extract_path", "token")))
            if token:
                header = refresh.get("auth_header_key", "Authorization")
                prefix = refresh.get("auth_header_prefix", "Bearer ")
                self.base_headers[str(header)] = f"{prefix}{token}" if prefix and not str(token).startswith(prefix) else str(token)
                self.user_a.headers[str(header)] = self.base_headers[str(header)]

            cookie = refresh.get("cookie_path")
            cookie_value = self._extract_path(body, cookie) if cookie else ""
            if cookie_value:
                self.cookie = str(cookie_value)
            elif getattr(resp, "cookies", None) is not None:
                cookie_items = list(resp.cookies.items())
                if cookie_items:
                    self.cookie = "; ".join(f"{k}={v}" for k, v in cookie_items)

            csrf_path = refresh.get("csrf_path")
            csrf_value = self._extract_path(body, csrf_path) if csrf_path else ""
            if csrf_value:
                self.csrf_tokens[refresh.get("csrf_header", "X-CSRF-Token")] = str(csrf_value)

            self.last_refresh = now
            self.refresh_error = ""
            return True
        except Exception as exc:
            self.refresh_error = str(exc)
            self.last_refresh = now
            return False

    def as_plugin_kwargs(self, user: str = "A") -> dict[str, Any]:
        return {
            "headers": self.user_headers(user),
            "auth_token": self.user_a.token if str(user).upper() != "B" else self.user_b.token,
            "cookies": self.cookie,
            "has_dual_user": self.has_dual_user(),
        }
