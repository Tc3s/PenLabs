#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tests for PenLabs Apex Upgrades (AuthManager, EndpointScorer, BS4 Form Parsing).
"""

import pytest
from core.auth_manager import AuthManager
from core.endpoint_scorer import EndpointScorer
from plugins.blind_xss_plugin import BlindXSSPlugin

def test_auth_manager_initialization():
    auth = AuthManager(auth_token="Bearer mytoken123", cookie_str="session=abc12345; user=admin")
    assert auth.is_authenticated() is True
    assert auth.headers.get("Authorization") == "Bearer mytoken123"
    assert auth.cookies.get("session") == "abc12345"
    assert auth.cookies.get("user") == "admin"

def test_auth_manager_csrf_extraction():
    auth = AuthManager()
    html_meta = '<head><meta name="csrf-token" content="secret_token_123"></head>'
    assert auth.extract_csrf_token(html_meta) == "secret_token_123"

    html_input = '<form><input type="hidden" name="authenticity_token" value="input_token_456"></form>'
    assert auth.extract_csrf_token(html_input) == "input_token_456"

def test_endpoint_scorer():
    high_risk_url = "https://target.com/api/v1/user/profile?id=100&action=update"
    low_risk_url = "https://target.com/about-us"
    
    high_score = EndpointScorer.score_url(high_risk_url)
    low_score = EndpointScorer.score_url(low_risk_url)

    assert high_score > low_score
    assert high_score >= 50

    prioritized = EndpointScorer.prioritize_urls([low_risk_url, high_risk_url])
    assert prioritized[0] == high_risk_url

def test_bs4_form_extraction():
    plugin = BlindXSSPlugin()
    html = """
    <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" value="" />
                <input type="password" name="password" value="" />
                <input type="hidden" name="csrf" value="token123" />
            </form>
            <input type="text" name="search_q" value="standalone" />
        </body>
    </html>
    """
    forms = plugin._extract_forms(html, "https://example.com")
    assert len(forms) >= 1
    form_names = [f["name"] for f in forms[0]["fields"]]
    assert "username" in form_names
    assert "password" in form_names
