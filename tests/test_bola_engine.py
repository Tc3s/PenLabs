import os
import json
import pytest
from unittest.mock import patch, MagicMock
from plugins.bola_engine_plugin import BOLAEnginePlugin


class TestBOLAEnginePlugin:
    @patch("requests.Session")
    @patch("requests.get")
    @patch("requests.post")
    def test_bola_flow_rest_and_graphql(self, mock_post, mock_get, mock_session_class, tmp_path):
        # Setup mock session and responses
        session_a = MagicMock()
        session_b = MagicMock()
        mock_session_class.side_effect = [session_a, session_b]

        # Mock harvested IDs in response from Session A
        resp_harvest = MagicMock()
        resp_harvest.status_code = 200
        resp_harvest.text = '{"id": "user-uuid-1234-abcd", "other_id": 999, "padding_data_to_satisfy_response_length_minimum_criteria": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        session_a.get.return_value = resp_harvest
        session_a.post.return_value = resp_harvest

        # Mock Replay Response with Session B (Success 200)
        resp_replay_b = MagicMock()
        resp_replay_b.status_code = 200
        resp_replay_b.text = '{"id": "user-uuid-1234-abcd", "other_id": 999, "padding_data_to_satisfy_response_length_minimum_criteria": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        session_b.get.return_value = resp_replay_b
        session_b.post.return_value = resp_replay_b

        # Mock Baseline Check Response (User A)
        resp_baseline_a = MagicMock()
        resp_baseline_a.status_code = 200
        resp_baseline_a.text = '{"id": "user-uuid-1234-abcd", "other_id": 999, "padding_data_to_satisfy_response_length_minimum_criteria": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        mock_get.return_value = resp_baseline_a
        mock_post.return_value = resp_baseline_a

        # Mock Unauth Response (Blocked 403) -> High Confidence BOLA
        resp_unauth = MagicMock()
        resp_unauth.status_code = 403
        resp_unauth.text = "Forbidden"
        # We need mock_get / mock_post to return different values depending on calls.
        # Let's use a side_effect.
        def get_side_effect(url, *args, **kwargs):
            if "Authorization" in kwargs.get("headers", {}):
                return resp_baseline_a
            return resp_unauth
        mock_get.side_effect = get_side_effect
        mock_post.side_effect = get_side_effect

        plugin = BOLAEnginePlugin()
        endpoints = [
            "http://example.com/api/users",
            "http://example.com/api/graphql"
        ]

        out_dir = str(tmp_path / "bola_output")
        results = plugin.run(
            endpoints,
            out_dir=out_dir,
            token_a="privileged-token",
            token_b="unprivileged-token",
            max_endpoints=2
        )

        assert results["ids_harvested"] > 0
        assert len(results["high_confidence_bola"]) == 1
        assert len(results["graphql_findings"]) == 1

        # Check report files generated
        assert os.path.exists(os.path.join(out_dir, "high_confidence_bola.txt"))
        assert os.path.exists(os.path.join(out_dir, "bola_report.md"))
        assert os.path.exists(os.path.join(out_dir, "bola_results.json"))

        # Verify Mermaid diagram and warning alerts are written to MD report
        with open(os.path.join(out_dir, "bola_report.md"), "r") as f:
            content = f.read()
            assert "sequenceDiagram" in content
            assert "mermaid" in content
            assert "Vulnerability Type" in content

    @patch("socket.socket")
    def test_websocket_bola_detection(self, mock_socket_class, tmp_path):
        plugin = BOLAEnginePlugin()
        
        # Mock WebSocket socket client to return handshake and text frames
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock

        # Mock Handshake response (101 Switching Protocols)
        # and mock WebSocket response frame.
        # First mock recv for handshake: returns headers
        # Then mock recv for text frame: returns ws header (2 bytes) + payload
        handshake_resp = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"
        ws_frame_head = bytes([0x81, 0x05])  # Text frame, length 5
        ws_payload = b"hello"

        mock_sock.recv.side_effect = [
            handshake_resp,
            ws_frame_head,
            ws_payload,
            handshake_resp,
            ws_frame_head,
            ws_payload,
            b"HTTP/1.1 403 Forbidden\r\n\r\n"  # unauth handshake fails
        ]

        out_dir = str(tmp_path / "bola_ws_output")
        # Run ws test helper directly
        headers_a = {"Authorization": "tokenA"}
        headers_b = {"Authorization": "tokenB"}
        
        # Test private method _ws_send_receive
        res_a = plugin._ws_send_receive("ws://example.com/ws", headers_a, "subscribe")
        assert res_a == "hello"

        res_b = plugin._ws_send_receive("ws://example.com/ws", headers_b, "subscribe")
        assert res_b == "hello"

        res_unauth = plugin._ws_send_receive("ws://example.com/ws", {}, "subscribe")
        assert res_unauth is None

    @patch("requests.Session")
    @patch("requests.get")
    def test_privilege_escalation_detection(self, mock_get, mock_session_class, tmp_path):
        session_a = MagicMock()
        session_b = MagicMock()
        mock_session_class.side_effect = [session_a, session_b]

        # Privileged endpoint
        endpoint = "http://example.com/api/admin/users"

        resp_harvest = MagicMock()
        resp_harvest.status_code = 200
        resp_harvest.text = '{"id": 42, "padding_data_to_satisfy_response_length_minimum_criteria": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        session_a.get.return_value = resp_harvest

        resp_replay_b = MagicMock()
        resp_replay_b.status_code = 200
        resp_replay_b.text = '{"id": 42, "padding_data_to_satisfy_response_length_minimum_criteria": "abcdefghijklmnopqrstuvwxyz1234567890"}'
        session_b.get.return_value = resp_replay_b

        resp_baseline_a = MagicMock()
        resp_baseline_a.status_code = 200
        resp_baseline_a.text = '{"id": 42, "padding_data_to_satisfy_response_length_minimum_criteria": "abcdefghijklmnopqrstuvwxyz1234567890"}'

        resp_unauth = MagicMock()
        resp_unauth.status_code = 401

        def get_side_effect(url, *args, **kwargs):
            if "Authorization" in kwargs.get("headers", {}):
                return resp_baseline_a
            return resp_unauth
        mock_get.side_effect = get_side_effect

        plugin = BOLAEnginePlugin()
        out_dir = str(tmp_path / "priv_esc_output")
        results = plugin.run(
            [endpoint],
            out_dir=out_dir,
            token_a="admin-token",
            token_b="regular-token",
            max_endpoints=1
        )

        assert len(results["privilege_escalation"]) == 1
        assert results["privilege_escalation"][0]["endpoint"] == endpoint
