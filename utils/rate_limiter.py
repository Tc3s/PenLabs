#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Rate Limiter
Giới hạn tần suất gửi lệnh để tránh DoS từ operator hoặc automation loop.
"""

import time
import threading
import random
from collections import defaultdict, deque


class RateLimiter:
    """
    Token-bucket style rate limiter theo từng user_id.
    Thread-safe với Lock.
    """

    def __init__(self, max_calls: int = 5, period: int = 60):
        """
        Args:
            max_calls: Số lần gọi tối đa trong 1 period
            period:    Khoảng thời gian tính bằng giây
        """
        self.max_calls = max_calls
        self.period = period
        self._calls: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def is_allowed(self, user_id: str) -> bool:
        """
        Kiểm tra user có được phép gọi tiếp không.
        Trả về True nếu còn quota, False nếu đã vượt limit.
        """
        now = time.monotonic()
        with self._lock:
            calls = self._calls[user_id]
            # Xoá các record cũ hơn window
            while calls and calls[0] < now - self.period:
                calls.popleft()
            if len(calls) >= self.max_calls:
                return False
            calls.append(now)
            return True

    def remaining(self, user_id: str) -> int:
        """Trả về số lần gọi còn lại trong window hiện tại."""
        now = time.monotonic()
        with self._lock:
            calls = self._calls[user_id]
            while calls and calls[0] < now - self.period:
                calls.popleft()
            return max(0, self.max_calls - len(calls))

    def reset_after(self, user_id: str) -> float:
        """Trả về số giây còn lại đến khi window reset (slot đầu tiên expire)."""
        now = time.monotonic()
        with self._lock:
            calls = self._calls[user_id]
            if not calls:
                return 0.0
            oldest = calls[0]
            return max(0.0, (oldest + self.period) - now)


class OutboundRateLimiter:
    """
    Global Pacer cho Outbound HTTP Traffic.
    Sử dụng Token-Bucket kết hợp Jitter delay để giả lập human pacing.
    Singleton pattern để dùng chung cho toàn bộ engine.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(OutboundRateLimiter, cls).__new__(cls)
        return cls._instance

    def __init__(self, requests_per_second: float = 2.0):
        if not hasattr(self, 'initialized'):
            self.requests_per_second = requests_per_second
            self.capacity = max(1.0, requests_per_second)
            self.tokens = self.capacity
            self.last_update = time.monotonic()
            self._token_lock = threading.Lock()
            self.initialized = True

    def set_rate(self, requests_per_second: float):
        """Thay đổi RPS động nếu phát hiện WAF chặn."""
        with self._token_lock:
            self.requests_per_second = requests_per_second
            self.capacity = max(1.0, requests_per_second)

    def wait(self):
        """
        Đợi cho đến khi có token, sau đó thêm Jitter delay (chỉ áp dụng khi rate thấp).
        """
        while True:
            with self._token_lock:
                now = time.monotonic()
                elapsed = now - self.last_update
                self.tokens += elapsed * self.requests_per_second
                self.last_update = now
                
                if self.tokens > self.capacity:
                    self.tokens = self.capacity

                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    break
                else:
                    sleep_time = (1.0 - self.tokens) / self.requests_per_second
            
            # Đợi ngoài lock để thread khác có thể chạy
            time.sleep(sleep_time)

        # Thêm Jitter ngẫu nhiên giả lập human pacing (chỉ khi RPS thấp <= 10 req/s để tránh làm nghẽn các tác vụ tốc độ cao)
        if self.requests_per_second <= 10.0:
            jitter = random.uniform(0.1, 0.5)
            time.sleep(jitter)
