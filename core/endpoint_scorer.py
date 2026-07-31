#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Endpoint Risk Scorer & Targeted DAST Router
=====================================================
Scores and prioritizes high-risk business logic and API endpoints for targeted DAST fuzzing.
"""

from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)

# Keywords indicating potential business logic or vulnerable endpoints
HIGH_RISK_KEYWORDS = frozenset({
    "login", "auth", "oauth", "signin", "signup", "register", "token",
    "password", "reset", "user", "profile", "account", "admin", "dashboard",
    "upload", "file", "download", "image", "doc", "pdf", "export",
    "pay", "payment", "checkout", "cart", "billing", "order", "invoice",
    "api", "v1", "v2", "v3", "graphql", "rest", "swagger", "json",
    "search", "query", "filter", "find", "view", "details", "id", "uuid",
})

class EndpointScorer:
    """
    Evaluates URLs and assigns a Risk Score (0-100) to prioritize DAST testing.
    """

    @classmethod
    def score_url(cls, url: str) -> int:
        if not url:
            return 0
        score = 10
        try:
            parsed = urlparse(url)
            path_lower = parsed.path.lower()
            query_params = parse_qs(parsed.query)

            # Score based on path keywords
            for kw in HIGH_RISK_KEYWORDS:
                if kw in path_lower:
                    score += 15

            # Score based on presence of query parameters (XSS/SQLi targets)
            if query_params:
                score += 20
                for param in query_params.keys():
                    if any(kw in param.lower() for kw in ["id", "user", "file", "url", "redirect", "token", "key"]):
                        score += 15

            # Score based on API pathing
            if "/api/" in path_lower or path_lower.endswith(".json"):
                score += 25

        except Exception as e:
            logger.debug(f"[EndpointScorer] Scoring error for {url}: {e}")

        return min(score, 100)

    @classmethod
    def prioritize_urls(cls, urls: list, top_n: int = 50) -> list:
        """
        Sorts a list of URLs by risk score in descending order.
        """
        if not urls:
            return []
        scored = [(url, cls.score_url(url)) for url in urls]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [url for url, score in scored[:top_n]]
