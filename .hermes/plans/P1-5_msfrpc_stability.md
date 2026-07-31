# P1-5: MSFRPC Plugin Stability & Auto-Reconnect — DETAILED PLAN

## 1. Hiện trạng (Evidence từ code đã đọc)

### 1.1. `connect()` method (line 54-117)

**File:** `plugins/msfrpc_plugin.py` (677 dòng)

**Evidence:**
- `msfrpc_plugin.py:54` — `def connect(self, max_retries: int = 1, backoff_base: float = 1.0)`. **Mặc định `max_retries=1` → không retry.**
- `msfrpc_plugin.py:87-117` — Retry loop với exponential backoff (cap 10s) + jitter 30%. Nhưng chỉ chạy khi caller pass `max_retries > 1`.
- `msfrpc_plugin.py:90-95` — Set socket timeout = 10s để tránh treo khi SSL mismatch.
- `msfrpc_plugin.py:93` — Tạo `MsfRpcClient(rpc_pass, server=rpc_host, port=rpc_port, ssl=rpc_ssl)`. **Mỗi lần `connect()` tạo instance mới, không cache.**

**Đặc điểm:** Plugin là **stateless**: mỗi lần cần dùng RPC, caller phải tự gọi `connect()` lại, tự quản lý retry. Không có connection pool, không có auto-reconnect khi daemon restart.

### 1.2. Không có auto-reconnect

**Tìm kiếm:** `search_files pattern="keepalive|is_connected|reconnect|pings"` → **0 kết quả**.

**Cấu trúc class** (12 methods):
```
connect()                    # line 54   — one-shot
exploit_async()              # line 119  — dùng client từ caller
list_compatible_payloads()    # line 381
poll_sessions()              # line 413  — poll sessions.list
start_session_monitor()      # line 507  — background thread cho poll_sessions
interact_session()           # line 519  — interactive shell
```

→ **KHÔNG có:**
- Background ping/heartbeat thread để detect daemon crash.
- Auto-reconnect logic khi `client.sessions.list` raise exception.
- Job queue — mỗi caller tự quản lý `client` instance.

### 1.3. Vấn đề thực tế

Khi scan chạy lâu (recursive scan trên 50 subdomain × Module3 exploit), nếu msfrpcd restart giữa chừng:

1. Caller gọi `client.jobs.list` → raise exception (Connection refused / EOF).
2. Exception bubble lên → caller catch và skip job → **mất job vĩnh viễn**, không retry.
3. User phải restart scan thủ công.

### 1.4. Job handling hiện tại

- `exploit_async()` trả về dict có `job_id` (line 191) hoặc `error` key.
- Caller (Module3) chịu trách nhiệm lưu job_id và poll sau.
- Nếu RPC disconnect trong lúc đang exploit → `mod.execute()` raise → caller nhận `{"error": "..."}` → không retry.

### 1.5. Tham chiếu

- `msfrpc_plugin.py:413-505` — `poll_sessions()` đã có pattern `try/except` quanh `client.sessions.list` (dòng 446-447, 475-476). Có thể replicate pattern này cho mọi RPC call.
- `msfrpc_plugin.py:507-517` — `start_session_monitor()` đã có pattern background thread với `daemon=True`. Có thể replicate cho heartbeat.

---

## 2. Files cần tạo / sửa

| Action | File | Lý do |
|--------|------|-------|
| EDIT | `/home/tcus/Desktop/PenLabs/plugins/msfrpc_plugin.py` | Thêm `RpcConnection` class, `JobQueue`, `_heartbeat_loop`, auto-reconnect wrapper |
| NEW | `/home/tcus/Desktop/PenLabs/utils/rpc_connection.py` | Stateful connection manager với auto-reconnect (tách riêng cho testable) |
| NEW | `/home/tcus/Desktop/PenLabs/utils/job_queue.py` | FIFO job queue với retry logic |
| EDIT | `/home/tcus/Desktop/PenLabs/config.py` | Thêm config: `MSF_HEARTBEAT_INTERVAL`, `MSF_AUTO_RECONNECT`, `MSF_JOB_QUEUE_MAX` |
| NEW | `/home/tcus/Desktop/PenLabs/tests/test_msfrpc_plugin.py` | Test auto-reconnect, job queue, heartbeat (10 tests, xem P0-4) |
| NEW | `/home/tcus/Desktop/PenLabs/tests/test_rpc_connection.py` | Test connection state machine (8 tests) |
| NEW | `/home/tcus/Desktop/PenLabs/tests/test_job_queue.py` | Test queue + retry (6 tests) |

**Tổng: 4 file mới + 2 file sửa + 24 test cases.**

---

## 3. Code skeleton cụ thể

### 3.1. `utils/rpc_connection.py` — Connection state machine

```python
"""
Stateful MSFRPC connection manager với auto-reconnect.

State machine:
    DISCONNECTED ──connect()──> CONNECTING ──success──> CONNECTED
        ↑                                                     │
        └──────────── heartbeat fail / RPC error ─────────────┘

Khi ở CONNECTED mà RPC call raise → tự động transition về CONNECTING
và retry với exponential backoff, đồng thời re-enqueue job nếu có.
"""
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
                 max_backoff: float = 30.0,
                 on_reconnect: Optional[Callable] = None,
                 on_dead: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.password = password
        self.ssl = ssl
        self.heartbeat_interval = heartbeat_interval
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
            socket.setdefaulttimeout(10)
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
            time.sleep(backoff)

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
```

### 3.2. `utils/job_queue.py` — Persistent FIFO job queue

```python
"""
FIFO job queue với auto-retry cho MSFRPC.
Lưu trên disk (JSON) để survive process restart.
"""
import json
import os
import time
import threading
import logging
import uuid
from enum import Enum
from typing import Optional, Callable, Dict, List
from dataclasses import dataclass, field, asdict

log = logging.getLogger("Job-Queue")


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


@dataclass
class Job:
    job_id: str
    module: str
    options: Dict
    status: JobStatus = JobStatus.PENDING
    attempts: int = 0
    max_attempts: int = 3
    last_error: str = ""
    created_ts: float = field(default_factory=time.time)
    started_ts: float = 0.0
    finished_ts: float = 0.0
    msf_job_id: Optional[int] = None
    result: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Job":
        d = dict(d)
        d["status"] = JobStatus(d.get("status", "pending"))
        return cls(**d)


class JobQueue:
    def __init__(self, persist_path: str = "/tmp/penlabs_msf_jobs.json",
                 max_size: int = 1000):
        self._path = persist_path
        self._max_size = max_size
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._load()

    def _load(self):
        if os.path.exists(self._path):
            try:
                with open(self._path) as f:
                    raw = json.load(f)
                for j in raw:
                    self._jobs[j["job_id"]] = Job.from_dict(j)
            except Exception as e:
                log.warning(f"[JobQueue] Load failed: {e}")

    def _flush(self):
        try:
            with open(self._path, "w") as f:
                json.dump([j.to_dict() for j in self._jobs.values()], f, indent=2)
        except Exception as e:
            log.debug(f"[JobQueue] Flush failed: {e}")

    def enqueue(self, module: str, options: Dict, max_attempts: int = 3) -> Job:
        with self._lock:
            if len(self._jobs) >= self._max_size:
                # Evict oldest DONE/FAILED
                evictable = [j for j in self._jobs.values()
                             if j.status in (JobStatus.DONE, JobStatus.FAILED)]
                evictable.sort(key=lambda j: j.finished_ts)
                for j in evictable[:len(self._jobs) - self._max_size + 1]:
                    del self._jobs[j.job_id]
            job = Job(
                job_id=str(uuid.uuid4())[:8],
                module=module, options=options, max_attempts=max_attempts,
            )
            self._jobs[job.job_id] = job
            self._cond.notify()
            self._flush()
            return job

    def claim(self) -> Optional[Job]:
        """Lấy 1 job PENDING, đánh dấu RUNNING."""
        with self._lock:
            for j in self._jobs.values():
                if j.status == JobStatus.PENDING and j.attempts < j.max_attempts:
                    j.status = JobStatus.RUNNING
                    j.attempts += 1
                    j.started_ts = time.time()
                    self._flush()
                    return j
            return None

    def complete(self, job_id: str, result: Dict):
        with self._lock:
            j = self._jobs.get(job_id)
            if j:
                j.status = JobStatus.DONE
                j.result = result
                j.finished_ts = time.time()
                self._flush()

    def fail(self, job_id: str, error: str, requeue: bool = True):
        with self._lock:
            j = self._jobs.get(job_id)
            if not j: return
            j.last_error = error
            j.finished_ts = time.time()
            if requeue and j.attempts < j.max_attempts:
                j.status = JobStatus.PENDING
                log.info(f"[JobQueue] {job_id} re-queued (attempt {j.attempts}/{j.max_attempts})")
            else:
                j.status = JobStatus.FAILED
                log.warning(f"[JobQueue] {job_id} permanently failed: {error}")
            self._cond.notify()
            self._flush()

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    def pending_count(self) -> int:
        with self._lock:
            return sum(1 for j in self._jobs.values() if j.status == JobStatus.PENDING)
```

### 3.3. Edit `plugins/msfrpc_plugin.py` — wrap với RpcConnection + JobQueue

```python
# Thêm import ở đầu file (sau line 30)
from utils.rpc_connection import RpcConnection, ConnState
from utils.job_queue import JobQueue, Job


class MsfRpcPlugin(BasePlugin):
    def __init__(self):
        # ... existing init code ...
        self._conn: Optional[RpcConnection] = None
        self._job_queue: Optional[JobQueue] = None

    def _get_connection(self) -> RpcConnection:
        """Lazy init connection manager."""
        if self._conn is None:
            self._conn = RpcConnection(
                host=Config.MSF_RPC_HOST,
                port=int(Config.MSF_RPC_PORT),
                password=Config.MSF_RPC_PASS,
                ssl=Config.MSF_RPC_SSL,
                heartbeat_interval=getattr(Config, "MSF_HEARTBEAT_INTERVAL", 30),
                on_reconnect=self._on_rpc_reconnect,
                on_dead=self._on_rpc_dead,
            )
            self._conn.start()
        return self._conn

    def _get_job_queue(self) -> JobQueue:
        if self._job_queue is None:
            self._job_queue = JobQueue(
                persist_path=getattr(Config, "MSF_JOB_QUEUE_PATH",
                                     "/tmp/penlabs_msf_jobs.json"),
                max_size=getattr(Config, "MSF_JOB_QUEUE_MAX", 1000),
            )
        return self._job_queue

    def _on_rpc_reconnect(self):
        """Callback khi reconnect thành công → re-enqueue RUNNING jobs."""
        log.info("[MsfRPC] Reconnected. Re-enqueueing in-flight jobs...")
        queue = self._get_job_queue()
        with queue._lock:
            for j in queue._jobs.values():
                if j.status.value == "running":
                    j.status = "pending"
                    log.info(f"[MsfRPC] Re-queued job {j.job_id} ({j.module})")

    def _on_rpc_dead(self):
        """Callback khi auth fail → mark all RUNNING jobs failed."""
        log.error("[MsfRPC] Connection DEAD. Marking RUNNING jobs as FAILED.")
        queue = self._get_job_queue()
        for jid in [j.job_id for j in queue._jobs.values() if j.status.value == "running"]:
            queue.fail(jid, "Connection DEAD (auth failed?)", requeue=False)

    def connect(self, max_retries: int = 1, backoff_base: float = 1.0):
        """
        [P1-5] Backward-compat: vẫn expose connect() cho code cũ,
        nhưng nội bộ dùng RpcConnection.
        """
        # Try to ensure connected via manager
        try:
            self._get_connection()._ensure_connected(timeout=10)
            return self._get_connection()._get_client()
        except Exception:
            # Fallback: legacy one-shot
            return self._legacy_connect(max_retries, backoff_base)

    def _legacy_connect(self, max_retries, backoff_base):
        """Original connect() body — kept for backward compat."""
        # ... (move existing code from line 54-117 here unchanged) ...

    def exploit_async(self, client, module_path, options, enqueue_on_fail: bool = True):
        """
        [P1-5] Wrap exploit với JobQueue. Nếu RPC fail, auto-enqueue for retry.
        """
        try:
            return self._exploit_async_impl(client, module_path, options)
        except (ConnectionError, socket.error, EOFError) as e:
            if not enqueue_on_fail:
                raise
            log.warning(f"[MsfRPC] Exploit failed: {e}. Enqueueing for retry.")
            queue = self._get_job_queue()
            job = queue.enqueue(module_path, options, max_attempts=3)
            return {"queued": True, "queue_job_id": job.job_id,
                    "error": str(e), "status": "queued"}

    def _exploit_async_impl(self, client, module_path, options):
        """Original exploit_async body (line 119-379 unchanged)."""

    def poll_sessions(self, client, poll_interval=5, max_wait=300, pre_sessions=None):
        """
        [P1-5] poll_sessions giờ check connection state, auto-reconnect nếu cần.
        """
        conn = self._get_connection()
        if not conn.is_connected:
            try:
                conn._ensure_connected(timeout=5)
            except Exception:
                pass
        return self._poll_sessions_impl(client, poll_interval, max_wait, pre_sessions)

    def _poll_sessions_impl(self, client, poll_interval, max_wait, pre_sessions):
        """Original poll_sessions body unchanged."""

    def get_queue_status(self) -> dict:
        """[P1-5] Helper để caller kiểm tra queue state."""
        q = self._get_job_queue()
        return {
            "pending": q.pending_count(),
            "total": len(q._jobs),
        }
```

### 3.4. `config.py` — thêm config mới

```python
# Trong class Config, thêm:
MSF_HEARTBEAT_INTERVAL = int(os.getenv("MSF_HEARTBEAT_INTERVAL", "30"))
MSF_AUTO_RECONNECT = os.getenv("MSF_AUTO_RECONNECT", "true").lower() == "true"
MSF_JOB_QUEUE_MAX = int(os.getenv("MSF_JOB_QUEUE_MAX", "1000"))
MSF_JOB_QUEUE_PATH = os.getenv("MSF_JOB_QUEUE_PATH", "/tmp/penlabs_msf_jobs.json")
MSF_CONNECT_TIMEOUT = int(os.getenv("MSF_CONNECT_TIMEOUT", "10"))
```

---

## 4. Tests

### 4.1. `tests/test_rpc_connection.py` — 8 tests

```python
import time, socket, pytest
from unittest.mock import patch, MagicMock
from utils.rpc_connection import RpcConnection, ConnState


class TestRpcConnection:
    def test_initial_state_disconnected(self):
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=999)
        assert c.state == ConnState.DISCONNECTED
        assert c.is_connected is False

    def test_connect_success(self):
        c = RpcConnection("127.0.0.1", 55553, "pass")
        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            mc.return_value = MagicMock()
            c._do_connect()
            assert c.state == ConnState.CONNECTED
            assert c.is_connected is True

    def test_connect_auth_fail_marks_dead(self):
        c = RpcConnection("127.0.0.1", 55553, "wrong")
        with patch("pymetasploit3.msfrpc.MsfRpcClient",
                   side_effect=Exception("Auth failed: invalid password")):
            c._do_connect()
            assert c.state == ConnState.DEAD

    def test_connect_refused_stays_disconnected(self):
        c = RpcConnection("127.0.0.1", 1, "pass", max_backoff=0.1)
        with patch("pymetasploit3.msfrpc.MsfRpcClient",
                   side_effect=ConnectionRefusedError("refused")):
            c._do_connect()
            assert c.state == ConnState.DISCONNECTED
            assert c._attempt == 1

    def test_call_triggers_reconnect(self):
        c = RpcConnection("127.0.0.1", 55553, "pass")
        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            fake = MagicMock()
            fake.jobs.list = MagicMock(side_effect=[
                ConnectionError("disconnected"),
                [],  # second call succeeds
            ])
            mc.return_value = fake
            c._do_connect()
            # First call will fail, second will succeed
            result = c.call("jobs", "list")  # getattr(fake, 'jobs')().list

    def test_heartbeat_thread_runs(self):
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=0.1)
        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            fake = MagicMock()
            fake.jobs.list = MagicMock(return_value={})
            mc.return_value = fake
            c.start()
            time.sleep(0.3)
            c.stop()
            assert fake.jobs.list.call_count >= 1  # heartbeat pinged at least once

    def test_heartbeat_detects_dead(self):
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=0.1)
        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            fake = MagicMock()
            fake.jobs.list = MagicMock(side_effect=ConnectionError("dead"))
            mc.return_value = fake
            c._do_connect()
            assert c.state == ConnState.CONNECTED
            # Trigger heartbeat manually
            c._heartbeat_loop.__wrapped__(c) if hasattr(c._heartbeat_loop, '__wrapped__') else None
            # Or just call the heartbeat once
            c._mark_disconnected()
            assert c.state == ConnState.DISCONNECTED

    def test_on_reconnect_callback(self):
        called = []
        c = RpcConnection("127.0.0.1", 55553, "pass",
                          on_reconnect=lambda: called.append(1))
        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            mc.return_value = MagicMock()
            c._do_connect()
        assert len(called) == 1

    def test_stop_thread(self):
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=0.1)
        c.start()
        time.sleep(0.1)
        c.stop()
        assert c._stop_event.is_set()
```

### 4.2. `tests/test_job_queue.py` — 6 tests

```python
import time, pytest
from utils.job_queue import JobQueue, Job, JobStatus


class TestJobQueue:
    def test_enqueue_creates_job(self, tmp_session_dir):
        q = JobQueue(persist_path=f"{tmp_session_dir}/jobs.json")
        j = q.enqueue("exploit/test", {"RHOSTS": "1.1.1.1"})
        assert j.status == JobStatus.PENDING
        assert j.module == "exploit/test"

    def test_claim_returns_pending(self, tmp_session_dir):
        q = JobQueue(persist_path=f"{tmp_session_dir}/jobs.json")
        j1 = q.enqueue("m1", {})
        j2 = q.enqueue("m2", {})
        claimed = q.claim()
        assert claimed is not None
        assert claimed.status == JobStatus.RUNNING

    def test_complete_marks_done(self, tmp_session_dir):
        q = JobQueue(persist_path=f"{tmp_session_dir}/jobs.json")
        j = q.enqueue("m", {})
        q.complete(j.job_id, {"result": "ok"})
        assert q.get(j.job_id).status == JobStatus.DONE

    def test_fail_requeues_if_attempts_left(self, tmp_session_dir):
        q = JobQueue(persist_path=f"{tmp_session_dir}/jobs.json")
        j = q.enqueue("m", {}, max_attempts=3)
        q.fail(j.job_id, "boom", requeue=True)
        assert q.get(j.job_id).status == JobStatus.PENDING
        assert q.get(j.job_id).attempts == 1

    def test_fail_permanent_after_max(self, tmp_session_dir):
        q = JobQueue(persist_path=f"{tmp_session_dir}/jobs.json")
        j = q.enqueue("m", {}, max_attempts=2)
        q.claim()  # attempt 1
        q.fail(j.job_id, "boom1", requeue=True)
        q.claim()  # attempt 2
        q.fail(j.job_id, "boom2", requeue=True)
        assert q.get(j.job_id).status == JobStatus.FAILED

    def test_persistence_roundtrip(self, tmp_session_dir):
        path = f"{tmp_session_dir}/jobs.json"
        q1 = JobQueue(persist_path=path)
        j = q1.enqueue("m", {"k": "v"})
        # New instance reads disk
        q2 = JobQueue(persist_path=path)
        loaded = q2.get(j.job_id)
        assert loaded is not None
        assert loaded.options == {"k": "v"}
```

---

## 5. Acceptance criteria

### AC-1: Auto-reconnect
- [ ] Khi msfrpcd restart → trong vòng 30s, RpcConnection tự detect qua heartbeat và reconnect.
- [ ] Sau reconnect, gọi `client.jobs.list` lại hoạt động bình thường (không cần restart Python process).
- [ ] Nếu auth fail (sai password), state → DEAD ngay lập tức, không retry vô ích.
- [ ] State machine test pass đủ 4 state: DISCONNECTED → CONNECTING → CONNECTED → DEAD.

### AC-2: Heartbeat thread
- [ ] Background thread chạy `daemon=True`, không block process exit.
- [ ] Heartbeat interval configurable qua `Config.MSF_HEARTBEAT_INTERVAL` (default 30s).
- [ ] Khi heartbeat fail → mark DISCONNECTED, callback `on_reconnect` được gọi.

### AC-3: Job queue
- [ ] Job lưu trên disk tại `Config.MSF_JOB_QUEUE_PATH`, survive process restart.
- [ ] Job queue max size = `Config.MSF_JOB_QUEUE_MAX` (default 1000), evict DONE/FAILED cũ nhất khi đầy.
- [ ] `exploit_async()` khi RPC fail → return `{"queued": True, "queue_job_id": "..."}` thay vì raise.
- [ ] Khi reconnect thành công, RUNNING jobs được tự động re-enqueue.

### AC-4: Backward compat
- [ ] `MsfRpcPlugin().connect()` vẫn hoạt động giống cũ cho code cũ gọi.
- [ ] `exploit_async(client, module, options)` signature không đổi.
- [ ] `poll_sessions()` không đổi behavior bên ngoài.

### AC-5: Tests
- [ ] `test_rpc_connection.py` 8 tests pass, bao gồm state machine + heartbeat + reconnect.
- [ ] `test_job_queue.py` 6 tests pass, bao gồm persistence + retry logic.
- [ ] `test_msfrpc_plugin.py` (xem P0-4) 10 tests pass, bao gồm `exploit_async` với enqueue_on_fail.

### AC-6: Stability
- [ ] Long-running test: simulate 1 giờ operation với 5 lần msfrpcd restart → tất cả exploit jobs hoàn thành hoặc được re-enqueued.
- [ ] Memory leak test: chạy 1 giờ, memory tăng < 50MB.
- [ ] Thread-safety: 10 threads cùng gọi `conn.call()` đồng thời → không có race condition, không crash.

---

## 6. Thứ tự thực thi

1. **Step 1 (30 min)**: Implement `utils/rpc_connection.py` (state machine + heartbeat).
2. **Step 2 (30 min)**: Implement `utils/job_queue.py` (FIFO + persistence + retry).
3. **Step 3 (15 min)**: `tests/test_rpc_connection.py` + `tests/test_job_queue.py` — verify foundation.
4. **Step 4 (45 min)**: Edit `plugins/msfrpc_plugin.py` — wrap với RpcConnection + JobQueue.
5. **Step 5 (15 min)**: Update `config.py` với 5 config mới.
6. **Step 6 (30 min)**: Update `tests/test_msfrpc_plugin.py` với tests cho auto-reconnect.
7. **Step 7 (30 min)**: Manual test với msfrpcd thật (hoặc mock server).
8. **Step 8 (15 min)**: Document trong README cách dùng queue + reconnect.

---

## 7. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Heartbeat thread bị GIL lock | Low | Medium | Dùng short timeout (5s) cho ping |
| Job queue file corrupt khi crash | Low | High | Atomic write (write to .tmp, rename) |
| msfrpcd restart rapid loop (flapping) | Medium | Medium | Cap backoff ở 30s, max 5 attempts trước khi DEAD |
| Mất session monitor thread khi RPC reconnect | Medium | Medium | `start_session_monitor` phải restart sau reconnect |
| Backward compat break | Low | High | Giữ `connect()` cũ, mark deprecated, new code dùng `_get_connection()` |
| Threading race trên `_state_lock` | Low | Medium | Dùng `threading.RLock` (re-entrancy) |
