#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — User-Agent Rotator
Rotate User-Agent để giảm OPSEC fingerprint khi thực hiện HTTP requests.
"""

import random


# Pool UA đa dạng — trộn browser, crawler, pentest recon tools
_USER_AGENTS = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    # Firefox / Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # curl (để blend với legitimate automation)
    "curl/7.88.1",
    "curl/8.5.0",
    # Googlebot (crawl-friendly targets)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
]


def get_random_ua() -> str:
    """Trả về một User-Agent ngẫu nhiên từ pool."""
    return random.choice(_USER_AGENTS)


def get_browser_ua() -> str:
    """Trả về UA trông như browser thật (loại bỏ curl, python)."""
    browser_uas = [ua for ua in _USER_AGENTS if not ua.startswith(("curl", "python"))]
    return random.choice(browser_uas)


def get_random_headers(include_referer: bool = False) -> dict:
    """
    [V1.0-APEX] Trả về headers HTTP đồng bộ hóa (Synchronized Headers).
    Đảm bảo UA, Platform, và Sec-Ch-Ua khớp nhau 100% để lách AI Bot Detection.
    """
    import collections
    
    # Danh sách các profile trình duyệt đồng bộ
    profiles = [
        {
            "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "platform": '"Windows"',
            "ch_ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"'
        },
        {
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
            "platform": '"macOS"',
            "ch_ua": '"Chromium";v="121", "Not(A:Brand";v="24", "Google Chrome";v="121"'
        },
        {
            "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "platform": '"Linux"',
            "ch_ua": '"Chromium";v="120", "Not(A:Brand";v="24", "Google Chrome";v="120"'
        }
    ]
    
    profile = random.choice(profiles)
    
    headers = collections.OrderedDict()
    headers["Host"] = None # Sẽ được điền bởi requests/curl_cffi
    headers["Connection"] = "keep-alive"
    headers["Cache-Control"] = "max-age=0"
    headers["sec-ch-ua"] = profile["ch_ua"]
    headers["sec-ch-ua-mobile"] = "?0"
    headers["sec-ch-ua-platform"] = profile["platform"]
    headers["Upgrade-Insecure-Requests"] = "1"
    headers["User-Agent"] = profile["ua"]
    headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    headers["Sec-Fetch-Site"] = "none"
    headers["Sec-Fetch-Mode"] = "navigate"
    headers["Sec-Fetch-User"] = "?1"
    headers["Sec-Fetch-Dest"] = "document"
    headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
    headers["Accept-Language"] = "en-US,en;q=0.9,vi;q=0.8"

    if include_referer:
        referers = ["https://www.google.com/", "https://www.bing.com/", "https://duckduckgo.com/"]
        headers["Referer"] = random.choice(referers)
        
    return headers
