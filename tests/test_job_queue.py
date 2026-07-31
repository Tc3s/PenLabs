import time
import pytest
from utils.job_queue import JobQueue, Job, JobStatus


class TestJobQueue:
    def test_enqueue_creates_job(self, tmp_path):
        q = JobQueue(persist_path=f"{tmp_path}/jobs.json")
        j = q.enqueue("exploit/test", {"RHOSTS": "1.1.1.1"})
        assert j.status == JobStatus.PENDING
        assert j.module == "exploit/test"

    def test_claim_returns_pending(self, tmp_path):
        q = JobQueue(persist_path=f"{tmp_path}/jobs.json")
        j1 = q.enqueue("m1", {})
        j2 = q.enqueue("m2", {})
        claimed = q.claim()
        assert claimed is not None
        assert claimed.status == JobStatus.RUNNING

    def test_complete_marks_done(self, tmp_path):
        q = JobQueue(persist_path=f"{tmp_path}/jobs.json")
        j = q.enqueue("m", {})
        q.complete(j.job_id, {"result": "ok"})
        assert q.get(j.job_id).status == JobStatus.DONE

    def test_fail_requeues_if_attempts_left(self, tmp_path):
        q = JobQueue(persist_path=f"{tmp_path}/jobs.json")
        j = q.enqueue("m", {}, max_attempts=3)
        q.fail(j.job_id, "boom", requeue=True)
        assert q.get(j.job_id).status == JobStatus.PENDING
        assert q.get(j.job_id).attempts == 0  # wait! In JobQueue.claim() we increment attempts. Since we didn't claim, attempts is 0.
        
        # Let's claim it first and then fail it
        j2 = q.claim()
        assert j2.attempts == 1
        q.fail(j2.job_id, "boom", requeue=True)
        assert q.get(j2.job_id).status == JobStatus.PENDING
        assert q.get(j2.job_id).attempts == 1

    def test_fail_permanent_after_max(self, tmp_path):
        q = JobQueue(persist_path=f"{tmp_path}/jobs.json")
        j = q.enqueue("m", {}, max_attempts=2)
        q.claim()  # attempt 1
        q.fail(j.job_id, "boom1", requeue=True)
        q.claim()  # attempt 2
        q.fail(j.job_id, "boom2", requeue=True)
        assert q.get(j.job_id).status == JobStatus.FAILED

    def test_persistence_roundtrip(self, tmp_path):
        path = f"{tmp_path}/jobs.json"
        q1 = JobQueue(persist_path=path)
        j = q1.enqueue("m", {"k": "v"})
        # New instance reads disk
        q2 = JobQueue(persist_path=path)
        loaded = q2.get(j.job_id)
        assert loaded is not None
        assert loaded.options == {"k": "v"}
