import time
import socket
import pytest
from unittest.mock import patch, MagicMock
from plugins.msfrpc_plugin import MsfRpcPlugin
from utils.rpc_connection import ConnState
from utils.job_queue import JobStatus


class TestMsfRpcPlugin:
    def test_connect_uses_rpc_connection(self):
        plugin = MsfRpcPlugin()
        with patch("socket.create_connection") as preflight, patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            preflight.return_value.__enter__.return_value = MagicMock()
            mc.return_value = MagicMock()
            client = plugin.connect()
            assert client is not None
            assert plugin._get_connection().state == ConnState.CONNECTED

    def test_connect_fails_fast_when_rpc_port_closed(self):
        plugin = MsfRpcPlugin()
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("closed")):
            start = time.perf_counter()
            client = plugin.connect()
        assert client is None
        assert time.perf_counter() - start < 0.5

    def test_exploit_async_queues_on_failure(self, tmp_path):
        from config import Config
        Config.MSF_JOB_QUEUE_PATH = f"{tmp_path}/msf_test_jobs_fail.json"
        
        plugin = MsfRpcPlugin()
        # Mock client to raise connection error
        client = MagicMock()
        client.modules.use = MagicMock(side_effect=ConnectionError("Disconnected"))
        
        # Call exploit_async, it should queue
        res = plugin.exploit_async(client, "exploit/multi/http/test", {"RHOSTS": "127.0.0.1"}, enqueue_on_fail=True)
        assert res.get("queued") is True
        assert res.get("status") == "queued"
        
        q = plugin._get_job_queue()
        assert q.pending_count() == 1
        job = q.get(res["queue_job_id"])
        assert job is not None
        assert job.module == "exploit/multi/http/test"

    def test_reconnect_reenqueues_running_jobs(self, tmp_path):
        from config import Config
        Config.MSF_JOB_QUEUE_PATH = f"{tmp_path}/msf_test_jobs.json"
        
        plugin = MsfRpcPlugin()
        q = plugin._get_job_queue()
        
        job = q.enqueue("exploit/multi/http/test", {"RHOSTS": "127.0.0.1"})
        # Claim it so it's RUNNING
        claimed = q.claim()
        assert claimed.status == JobStatus.RUNNING
        
        # Trigger reconnect callback
        plugin._on_rpc_reconnect()
        
        # It should be back to PENDING
        assert q.get(job.job_id).status == JobStatus.PENDING

    def test_dead_connection_fails_running_jobs(self, tmp_path):
        from config import Config
        Config.MSF_JOB_QUEUE_PATH = f"{tmp_path}/msf_test_jobs_dead.json"
        
        plugin = MsfRpcPlugin()
        q = plugin._get_job_queue()
        
        job = q.enqueue("exploit/multi/http/test", {"RHOSTS": "127.0.0.1"})
        q.claim()
        
        # Trigger dead callback
        plugin._on_rpc_dead()
        
        # It should be FAILED
        assert q.get(job.job_id).status == JobStatus.FAILED
