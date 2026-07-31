#!/usr/bin/env python3
"""
CIRCUIT BREAKER — PenLabs V1.0
================================
Tham khảo reconFTW: Tự động skip plugin sau N lần fail liên tiếp.
Ngăn chặn 1 tool bị treo/crash làm block toàn bộ pipeline.

Cách dùng:
    from core.circuit_breaker import CircuitBreaker
    
    cb = CircuitBreaker(max_failures=3, reset_timeout=300)
    
    if cb.can_execute("Amass"):
        try:
            result = amass_plugin.run(...)
            cb.record_success("Amass")
        except Exception:
            cb.record_failure("Amass")
    else:
        logging.warning("[CB] Amass đã bị circuit breaker skip.")
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class PluginState:
    """Trạng thái của 1 plugin trong circuit breaker."""
    failure_count: int = 0
    last_failure_time: float = 0.0
    is_open: bool = False  # True = circuit "mở" = plugin bị skip
    total_calls: int = 0
    total_failures: int = 0
    total_successes: int = 0


class CircuitBreaker:
    """
    Circuit Breaker Pattern cho Plugin Execution.
    
    States:
        CLOSED  → Plugin chạy bình thường
        OPEN    → Plugin bị skip (đã fail quá nhiều lần)
        HALF-OPEN → Thử lại sau reset_timeout giây
    
    Args:
        max_failures: Số lần fail liên tiếp trước khi mở circuit (default: 3)
        reset_timeout: Số giây chờ trước khi thử lại (default: 300s = 5 phút)
    """
    
    def __init__(self, max_failures: int = 3, reset_timeout: int = 300):
        self.max_failures = max_failures
        self.reset_timeout = reset_timeout
        self._states: Dict[str, PluginState] = {}
    
    def _get_state(self, plugin_name: str) -> PluginState:
        """Lấy hoặc tạo state cho plugin."""
        if plugin_name not in self._states:
            self._states[plugin_name] = PluginState()
        return self._states[plugin_name]
    
    def can_execute(self, plugin_name: str) -> bool:
        """
        Kiểm tra xem plugin có được phép chạy không.
        
        Returns:
            True nếu circuit CLOSED hoặc HALF-OPEN (sẵn sàng thử lại)
            False nếu circuit OPEN (đã fail quá nhiều, chưa hết cooldown)
        """
        state = self._get_state(plugin_name)
        
        if not state.is_open:
            return True
        
        # Check half-open: đã hết reset_timeout chưa?
        elapsed = time.time() - state.last_failure_time
        if elapsed >= self.reset_timeout:
            logging.info(
                f"[CircuitBreaker] {plugin_name}: HALF-OPEN — thử lại sau {elapsed:.0f}s cooldown"
            )
            return True
        
        remaining = self.reset_timeout - elapsed
        logging.warning(
            f"[CircuitBreaker] ⚡ {plugin_name}: OPEN — skip (đã fail {state.failure_count}x liên tiếp, "
            f"thử lại sau {remaining:.0f}s)"
        )
        return False
    
    def record_success(self, plugin_name: str):
        """Ghi nhận plugin chạy thành công → reset circuit."""
        state = self._get_state(plugin_name)
        state.failure_count = 0
        state.is_open = False
        state.total_calls += 1
        state.total_successes += 1
        logging.debug(f"[CircuitBreaker] {plugin_name}: SUCCESS — circuit CLOSED")
    
    def record_failure(self, plugin_name: str, error: str = ""):
        """Ghi nhận plugin fail → tăng counter, có thể mở circuit."""
        state = self._get_state(plugin_name)
        state.failure_count += 1
        state.last_failure_time = time.time()
        state.total_calls += 1
        state.total_failures += 1
        
        if state.failure_count >= self.max_failures:
            state.is_open = True
            logging.warning(
                f"[CircuitBreaker] ⚡ {plugin_name}: CIRCUIT OPENED — "
                f"{state.failure_count} failures liên tiếp. "
                f"Auto-skip trong {self.reset_timeout}s. "
                f"Last error: {error[:200]}"
            )
        else:
            logging.info(
                f"[CircuitBreaker] {plugin_name}: FAILURE #{state.failure_count}/{self.max_failures} — "
                f"circuit vẫn CLOSED. Error: {error[:200]}"
            )
    
    def force_open(self, plugin_name: str, reason: str = "manual"):
        """Bắt buộc mở circuit cho plugin (admin override)."""
        state = self._get_state(plugin_name)
        state.is_open = True
        state.last_failure_time = time.time()
        logging.warning(f"[CircuitBreaker] {plugin_name}: FORCE OPENED — {reason}")
    
    def force_close(self, plugin_name: str):
        """Bắt buộc đóng circuit (cho phép chạy lại)."""
        state = self._get_state(plugin_name)
        state.is_open = False
        state.failure_count = 0
        logging.info(f"[CircuitBreaker] {plugin_name}: FORCE CLOSED")
    
    def get_stats(self) -> dict:
        """Trả về thống kê toàn bộ plugins cho report."""
        stats = {}
        for name, state in self._states.items():
            stats[name] = {
                "status": "OPEN" if state.is_open else "CLOSED",
                "consecutive_failures": state.failure_count,
                "total_calls": state.total_calls,
                "total_failures": state.total_failures,
                "total_successes": state.total_successes,
                "success_rate": f"{(state.total_successes / state.total_calls * 100):.1f}%" if state.total_calls > 0 else "N/A",
            }
        return stats
    
    def summary(self) -> str:
        """In summary dạng text cho terminal."""
        lines = ["[CircuitBreaker] Plugin Health Summary:"]
        for name, state in self._states.items():
            status_icon = "🔴" if state.is_open else "🟢"
            rate = f"{(state.total_successes / state.total_calls * 100):.0f}%" if state.total_calls > 0 else "—"
            lines.append(
                f"  {status_icon} {name:<20} | calls={state.total_calls} "
                f"ok={state.total_successes} fail={state.total_failures} rate={rate}"
            )
        return "\n".join(lines)
