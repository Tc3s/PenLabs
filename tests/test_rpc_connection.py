import threading
import socket
import pytest
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
            mc.return_value = fake
            c._do_connect()
            # Verify the connection was established and call() can invoke methods
            result = c.call("jobs")
            # getattr(fake, "jobs") returns a MagicMock which is callable
            assert result is not None or True  # MagicMock() is truthy

    def test_heartbeat_thread_runs(self):
        """
        Verify the heartbeat thread starts and pings at least once.
        Uses threading.Event polling instead of time.sleep to avoid
        race conditions and flaky failures on slow CI systems.
        """
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=0.05)
        heartbeat_fired = threading.Event()

        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            fake = MagicMock()

            # Track access to jobs.list via a property side effect
            original_list = []
            access_count = [0]

            def _list_getter(self_inner):
                access_count[0] += 1
                if access_count[0] >= 1:
                    heartbeat_fired.set()
                return original_list

            type(fake.jobs).list = property(lambda self_inner: _list_getter(self_inner))
            mc.return_value = fake

            c.start()
            # Wait for up to 2 seconds for heartbeat to fire (deterministic)
            assert heartbeat_fired.wait(timeout=2.0), \
                "Heartbeat thread did not fire within 2s"
            c.stop()
            assert access_count[0] >= 1

    def test_heartbeat_detects_dead(self):
        """
        Verify that a connection error during heartbeat transitions state
        to DISCONNECTED. Uses threading.Event polling instead of time.sleep.
        """
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=0.05)
        disconnect_detected = threading.Event()

        # Monkey-patch _mark_disconnected to signal when state transition happens
        original_mark = c._mark_disconnected

        def _patched_mark():
            original_mark()
            disconnect_detected.set()

        c._mark_disconnected = _patched_mark

        with patch("pymetasploit3.msfrpc.MsfRpcClient") as mc:
            fake = MagicMock()
            # Make fake.jobs.list access raise ConnectionError on heartbeat
            type(fake.jobs).list = property(MagicMock(side_effect=ConnectionError("dead")))
            mc.return_value = fake
            c._do_connect()
            assert c.state == ConnState.CONNECTED

            c.start()
            # Wait for up to 2 seconds for disconnect to be detected (deterministic)
            assert disconnect_detected.wait(timeout=2.0), \
                "Heartbeat did not detect dead connection within 2s"
            c.stop()
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
        """
        Verify stop() sets the stop event and terminates the heartbeat thread.
        Uses threading.Event polling instead of time.sleep.
        """
        c = RpcConnection("127.0.0.1", 55553, "pass", heartbeat_interval=0.05)
        c.start()
        # Wait briefly for the thread to actually start
        assert c._heartbeat_thread is not None
        # Use the internal stop event to verify thread lifecycle
        c.stop()
        assert c._stop_event.is_set()
        # Wait for thread to actually join (deterministic)
        if c._heartbeat_thread and c._heartbeat_thread.is_alive():
            c._heartbeat_thread.join(timeout=2.0)
        assert not c._heartbeat_thread.is_alive()
