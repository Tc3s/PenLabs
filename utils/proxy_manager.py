#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PENLABS — PROXY MANAGER (V1.0)
Hệ thống quản lý Proxy tập trung: Health-check, Rotation, và Blacklisting.
Hỗ trợ định dạng: ip:port, ip:port:user:pass, scheme://ip:port...
"""

import os
import random
import threading
import logging
import socket
import time
from collections import deque
from config import Config

class ProxyManager:
    """
    Singleton Proxy Manager — Quản lý vòng lặp proxy và lọc proxy chết.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ProxyManager, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, proxy_file: str = None):
        if self._initialized:
            return
            
        self.proxy_file = proxy_file or Config.PROXY_FILE
        self._all_proxies = []      # Raw proxy strings
        self._live_pool = deque()   # Queue chứa proxies đã verify
        self._dead_pool = set()     # Proxies bị lỗi
        self._last_load_time = 0
        self._lock = threading.Lock()
        
        self.load_proxies()
        self._initialized = True

    def load_proxies(self):
        """Nạp danh sách proxy từ file cấu hình."""
        with self._lock:
            if not os.path.exists(self.proxy_file):
                # Fallback: check các file phổ biến khác
                alt_files = ["proxies.txt", "GOOD PROXIES.txt", "config/proxies.txt"]
                found = False
                for af in alt_files:
                    if os.path.exists(af):
                        self.proxy_file = af
                        found = True
                        break
                if not found:
                    logging.debug(f"[ProxyManager] Không tìm thấy file proxy: {self.proxy_file}")
                    return

            try:
                new_proxies = []
                with open(self.proxy_file, "r") as f:
                    for line in f:
                        p = line.strip().replace(" ", "")
                        if not p or p.startswith("#"):
                            continue
                        
                        # Chuẩn hoá format
                        if not p.startswith(("http://", "https://", "socks5://", "socks5h://")):
                            parts = p.split(":")
                            if len(parts) == 4: # ip:port:user:pass
                                p = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
                            else:
                                p = f"http://{p}"
                        
                        new_proxies.append(p)
                
                self._all_proxies = list(set(new_proxies)) # Deduplicate
                self._live_pool = deque(self._all_proxies)
                self._dead_pool.clear()
                self._last_load_time = time.time()
                logging.info(f"[ProxyManager] Đã nạp {len(self._all_proxies)} proxies từ {self.proxy_file}")
                
            except Exception as e:
                logging.error(f"[ProxyManager] Lỗi nạp file proxy: {e}")

    def get_proxy(self, sticky_key: str = None) -> str:
        """
        Lấy một proxy từ pool theo cơ chế Round-Robin.
        Hỗ trợ sticky_key để giữ cùng 1 IP cho cùng 1 target.
        """
        with self._lock:
            # Nếu pool sống trống, thử nạp lại hoặc hồi sinh dead pool
            if not self._live_pool:
                if self._dead_pool:
                    logging.debug("[ProxyManager] Live pool trống. Hồi sinh dead pool để retry...")
                    self._live_pool = deque(list(self._dead_pool))
                    self._dead_pool.clear()
                else:
                    return None

            if sticky_key:
                # Deterministic selection dựa trên hash của sticky_key
                import hashlib
                idx = int(hashlib.md5(sticky_key.encode()).hexdigest(), 16) % len(self._all_proxies)
                return self._all_proxies[idx]

            # Round-robin
            p = self._live_pool.popleft()
            self._live_pool.append(p) # Quay lại cuối hàng đợi
            return p

    def report_dead(self, proxy_url: str):
        """Đánh dấu proxy bị lỗi và đẩy vào dead pool."""
        with self._lock:
            if proxy_url in self._live_pool:
                # deque không hỗ trợ remove() hiệu quả, chúng ta sẽ lọc khi get
                # Nhưng ở đây chúng ta có thể convert sang list tạm
                try:
                    tmp = list(self._live_pool)
                    if proxy_url in tmp:
                        tmp.remove(proxy_url)
                        self._live_pool = deque(tmp)
                        self._dead_pool.add(proxy_url)
                        logging.debug(f"[ProxyManager] Proxy {proxy_url} bị đánh dấu DEAD. Pool còn {len(self._live_pool)}")
                except Exception:
                    pass

    def check_health(self, timeout: int = 5):
        """
        [Background Task] Kiểm tra sức khoẻ toàn bộ pool.
        Chạy không đồng bộ để tránh block pipeline.
        """
        def _worker():
            logging.info("[ProxyManager] Bắt đầu health-check toàn bộ proxy pool...")
            live = []
            dead = []
            
            for p in self._all_proxies:
                if self._test_connectivity(p, timeout):
                    live.append(p)
                else:
                    dead.append(p)
            
            with self._lock:
                self._live_pool = deque(live)
                self._dead_pool = set(dead)
            logging.info(f"[ProxyManager] Health-check hoàn tất: {len(live)} Live, {len(dead)} Dead.")

        threading.Thread(target=_worker, daemon=True).start()

    @staticmethod
    def _test_connectivity(proxy_url: str, timeout: int = 5) -> bool:
        """Test kết nối TCP tới proxy."""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(proxy_url)
            host = parsed.hostname
            port = parsed.port or 8080
            
            # Simple TCP connect check
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except Exception:
            return False

    @property
    def total_proxies(self):
        return len(self._all_proxies)

    @property
    def live_count(self):
        return len(self._live_pool)

if __name__ == "__main__":
    # Test
    logging.basicConfig(level=logging.INFO)
    pm = ProxyManager()
    print(f"Total: {pm.total_proxies}")
    print(f"Next: {pm.get_proxy()}")
    print(f"Next: {pm.get_proxy()}")
