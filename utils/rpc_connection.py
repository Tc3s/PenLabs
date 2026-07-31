"""
Stateful MSFRPC connection manager với auto-reconnect.

State machine:
    DISCONNECTED ──connect()──> CONNECTING ──success──> CONNECTED
        ↑                                                     │
        └──────────── heartbeat fail / RPC error ─────────────┘

Khi ở CONNECTED mà RPC call raise → tự động transition về CONNECTING
và retry với exponential backoff, đồng thời re-enqueue job nếu có.
"""
from __future__ import annotations

import time
import socket
import logging
import threading
from enum import Enum
from typing import Optional, Callable, Any

log = logging.getLogger("RPC-Conn")


class ConnState(Enum):
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DEAD = "dead"  # unrecoverable (e.g. bad credentials)


class RpcConnection:
    """
    Thread-safe wrapper quanh MsfRpcClient với:
    - Auto-reconnect on heartbeat fail
    - Exponential backoff (capped 30s)
    - Re-entrancy: nếu đang connect, callers khác sẽ đợi
    - Heartbeat thread chạy nền
    """

    def __init__(self, host: str, port: int, password: str, ssl: bool = True,
                 heartbeat_interval: int = 30,
                 connect_timeout: float = 10.0,
                 max_backoff: float = 30.0,
                 on_reconnect: Optional[Callable] = None,
                 on_dead: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self.heartbeat_interval = heartbeat_interval
        self.connect_timeout = max(1.0, float(connect_timeout or 10.0))
        self.max_backoff = max_backoff

        self._client = None
        self._state = ConnState.DISCONNECTED
        self._state_lock = threading.RLock()
        self._connect_lock = threading.Lock()  # ensure single connect attempt
        self._cond = threading.Condition(self._state_lock)
        self._last_attempt_ts = 0.0
        self._attempt = 0
        self._heartbeat_thread = None
        self._stop_event = threading.Event()

        self.on_reconnect = on_reconnect
        self.on_dead = on_dead

    @property
    def state(self) -> ConnState:
        with self._state_lock:
            return self._state

    @property
    def is_connected(self) -> bool:
        return self.state == ConnState.CONNECTED

    def start(self):
        """Khởi động background heartbeat thread + initial connect."""
        self._stop_event.clear()
        if not (self._heartbeat_thread and self._heartbeat_thread.is_alive()):
            self._heartbeat_thread = threading.Thread(
                target=self._heartbeat_loop, daemon=True, name="msfrpc-heartbeat"
            )
            self._heartbeat_thread.start()
        # Initial connect (non-blocking-ish)
        threading.Thread(target=self._ensure_connected, daemon=True).start()

    def stop(self):
        """Dừng heartbeat, ngắt connection."""
        self._stop_event.set()
        with self._state_lock:
            self._client = None
            self._state = ConnState.DISCONNECTED
            self._cond.notify_all()

    def call(self, method_name: str, *args, **kwargs) -> Any:
        """
        Safe RPC call. Nếu chưa connected, tự connect.
        Nếu đang connected nhưng call raise → reconnect + retry 1 lần.
        """
        last_exc = None
        for retry in range(2):
            try:
                self._ensure_connected(timeout=15)
                client = self._get_client()
                if client is None:
                    raise ConnectionError("msfrpc client unavailable")
                method = getattr(client, method_name, None)
                if method is None:
                    # Try raw call
                    return client.call(method_name, list(args))
                return method(*args, **kwargs)
            except (ConnectionError, socket.error, EOFError, BrokenPipeError) as e:
                last_exc = e
                log.warning(f"[RPC-Conn] {method_name} failed: {e}. Reconnecting...")
                self._mark_disconnected()
                if retry == 0:
                    time.sleep(0.5)
                    continue
        raise ConnectionError(f"msfrpc call failed after retry: {last_exc}")

    def _ensure_connected(self, timeout: float = 15.0):
        """Đảm bảo connected, hoặc block chờ (max `timeout`s)."""
        with self._state_lock:
            if self._state == ConnState.CONNECTED:
                return
            if self._state == ConnState.DEAD:
                raise ConnectionError("Connection marked DEAD (bad credentials?)")
            # Wait if another thread is connecting
            if self._state == ConnState.CONNECTING:
                self._cond.wait(timeout=timeout)
                if self._state == ConnState.CONNECTED:
                    return
                raise ConnectionError("Connect timeout")

        # Acquire global connect lock
        if not self._connect_lock.acquire(timeout=timeout):
            raise ConnectionError("Could not acquire connect lock")
        try:
            with self._state_lock:
                if self._state == ConnState.CONNECTED:
                    return
                self._state = ConnState.CONNECTING
            self._do_connect()
        finally:
            self._connect_lock.release()

    def _do_connect(self):
        """Thực sự tạo MsfRpcClient, set state CONNECTED hoặc DEAD."""
        try:
            from pymetasploit3.msfrpc import MsfRpcClient
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(self.connect_timeout)
            try:
                client = MsfRpcClient(self.password, server=self.host,
                                      port=self.port, ssl=self.ssl)
            finally:
                socket.setdefaulttimeout(old_timeout)

            with self._state_lock:
                self._client = client
                self._state = ConnState.CONNECTED
                self._attempt = 0
                self._cond.notify_all()
            log.info(f"[RPC-Conn] Connected to {self.host}:{self.port}")
            if self.on_reconnect:
                try:
                    self.on_reconnect()
                except Exception as e:
                    log.debug(f"[RPC-Conn] on_reconnect callback error: {e}")
        except Exception as e:
            err_str = str(e).lower()
            with self._state_lock:
                # Bad credentials → DEAD (don't retry)
                if "auth" in err_str or "password" in err_str or "401" in err_str:
                    self._state = ConnState.DEAD
                    self._cond.notify_all()
                    log.error(f"[RPC-Conn] Authentication failed: {e}")
                    if self.on_dead:
                        try: self.on_dead()
                        except Exception: pass
                    return
                # Other error → backoff
                self._state = ConnState.DISCONNECTED
                self._attempt += 1
                backoff = min(2 ** self._attempt, self.max_backoff)
                log.warning(f"[RPC-Conn] Connect failed: {e}. Next retry in {backoff}s")
                self._last_attempt_ts = time.monotonic()
                self._cond.notify_all()

    def _get_client(self) -> Any:
        with self._state_lock:
            return self._client

    def _mark_disconnected(self):
        with self._state_lock:
            if self._state == ConnState.CONNECTED:
                self._state = ConnState.DISCONNECTED
                self._client = None
                self._cond.notify_all()

    def _heartbeat_loop(self):
        """Background ping mỗi heartbeat_interval giây."""
        while not self._stop_event.is_set():
            self._stop_event.wait(self.heartbeat_interval)
            if self._stop_event.is_set():
                break
            if self.state != ConnState.CONNECTED:
                # Try to reconnect silently
                try:
                    self._ensure_connected(timeout=5)
                except Exception:
                    pass
                continue
            try:
                # Ping bằng cách list jobs
                client = self._get_client()
                if client:
                    _ = client.jobs.list
                    log.debug("[RPC-Conn] Heartbeat OK")
            except Exception as e:
                log.warning(f"[RPC-Conn] Heartbeat failed: {e}. Marking disconnected.")
                self._mark_disconnected()
                if self.on_reconnect:
                    try:
                        self.on_reconnect()
                    except Exception:
                        pass
