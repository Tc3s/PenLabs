"""
FIFO job queue với auto-retry cho MSFRPC.
Lưu trên disk (JSON) để survive process restart.
"""
from __future__ import annotations

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
            # Atomic write via tmp file swap
            tmp_path = self._path + ".tmp"
            with open(tmp_path, "w") as f:
                json.dump([j.to_dict() for j in self._jobs.values()], f, indent=2)
            os.replace(tmp_path, self._path)
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
