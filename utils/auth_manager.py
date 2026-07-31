#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PENLABS — AUTH MANAGER (V1.0)
Quản lý xác thực tập trung và tự động làm mới Token (JWT, Session Cookies).
"""

import time
import threading
import logging
import requests
from config import Config

class AuthManager:
    """
    Singleton Auth Manager — Đảm bảo session luôn "sống" trong suốt quá trình quét.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(AuthManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, auth_config: dict = None):
        if self._initialized:
            return
            
        self.config = auth_config or {}
        self._current_headers = {}
        self._last_refresh = 0
        self._refresh_interval = self.config.get("refresh_interval", 600) # Default 10 mins
        self._lock = threading.Lock()
        
        if self.config:
            self._start_refresh_daemon()
        self._initialized = True

    def _start_refresh_daemon(self):
        """Khởi động luồng chạy ngầm để refresh token."""
        def _daemon():
            while True:
                try:
                    self.refresh_session()
                except Exception as e:
                    logging.error(f"[AuthManager] Refresh failed: {e}")
                time.sleep(self._refresh_interval)
        
        t = threading.Thread(target=_daemon, daemon=True)
        t.start()
        logging.info("[AuthManager] Auth Refresh Daemon started.")

    def refresh_session(self):
        """Thực hiện login để lấy token mới."""
        login_url = self.config.get("login_url")
        if not login_url:
            return

        method = self.config.get("method", "POST")
        payload = self.config.get("payload", {})
        
        logging.info(f"[AuthManager] Refreshing session via {login_url}...")
        
        try:
            resp = requests.request(method, login_url, json=payload, verify=False, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                
                new_headers = {}
                # Extract token dựa trên config (vd: data.token)
                token_path = self.config.get("token_extract_path", "token")
                token = data
                for part in token_path.split("."):
                    if isinstance(token, dict):
                        token = token.get(part)
                
                if token:
                    header_key = self.config.get("auth_header_key", "Authorization")
                    header_prefix = self.config.get("auth_header_prefix", "Bearer ")
                    new_headers[header_key] = f"{header_prefix}{token}"
                    
                    with self._lock:
                        self._current_headers.update(new_headers)
                        self._last_refresh = time.time()
                    logging.info("[AuthManager] Session refreshed successfully.")
            else:
                logging.error(f"[AuthManager] Login failed with status {resp.status_code}")
        except Exception as e:
            logging.error(f"[AuthManager] Error during refresh: {e}")

    def get_headers(self) -> dict:
        """Lấy headers xác thực mới nhất."""
        with self._lock:
            return self._current_headers.copy()

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = AuthManager()
        return cls._instance

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    test_cfg = {
        "login_url": "https://httpbin.org/post",
        "method": "POST",
        "payload": {"user": "admin", "pass": "admin"},
        "token_extract_path": "json.user", # Giả lập extract từ httpbin
        "auth_header_key": "X-Test-Token",
        "refresh_interval": 5
    }
    am = AuthManager(test_cfg)
    time.sleep(2)
    print(f"Current Headers: {am.get_headers()}")
