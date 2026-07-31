#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Centralized Authentication & Session Manager
======================================================
Manages cookies, authorization headers, tokens, and CSRF token extraction.
"""

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class AuthManager:
    """
    Centralized Auth & Session State Manager for PenLabs.
    Allows plugins and DAST tools to run in authenticated context.
    """
    def __init__(self, auth_token: str = "", cookie_str: str = "", auth_header: str = ""):
        self.auth_token = auth_token.strip() if auth_token else ""
        self.cookie_str = cookie_str.strip() if cookie_str else ""
        self.auth_header = auth_header.strip() if auth_header else ""
        self.headers = {}
        self.cookies = {}
        self._initialize()

    def _initialize(self):
        if self.auth_header:
            if ":" in self.auth_header:
                k, v = self.auth_header.split(":", 1)
                self.headers[k.strip()] = v.strip()
        elif self.auth_token:
            if self.auth_token.lower().startswith("bearer "):
                self.headers["Authorization"] = self.auth_token
            else:
                self.headers["Authorization"] = f"Bearer {self.auth_token}"

        if self.cookie_str:
            for pair in self.cookie_str.split(";"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    self.cookies[k.strip()] = v.strip()

    def apply_to_session(self, session):
        """Apply authentication headers and cookies to a requests.Session instance."""
        if self.headers:
            session.headers.update(self.headers)
        if self.cookies:
            session.cookies.update(self.cookies)
        return session

    def extract_csrf_token(self, html_content: str) -> str:
        """Attempt to extract CSRF token from HTML forms or meta tags."""
        if not html_content:
            return ""
        # Search meta tags
        meta_match = re.search(r'<meta[^>]*name=["\'](?:csrf-token|_token|csrf)["\'][^>]*content=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        if meta_match:
            return meta_match.group(1)
        # Search input tags
        input_match = re.search(r'<input[^>]*name=["\'](?:csrf_token|_token|csrf|authenticity_token)["\'][^>]*value=["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        if input_match:
            return input_match.group(1)
        return ""

    def is_authenticated(self) -> bool:
        """Check if any authentication mechanism is configured."""
        return bool(self.headers or self.cookies or self.auth_token)
