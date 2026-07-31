"""
PenLabs V1.0 — BOLA/IDOR Engine Plugin (Extended)
Cross-testing 2 user sessions to detect Broken Object Level Authorization.
Supports REST APIs, GraphQL endpoints, WebSockets, and Privilege Escalation.
"""
from __future__ import annotations

import os
import re
import json
import logging
import socket
import ssl
import requests
from urllib.parse import urlparse
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)

# Regex patterns to extract IDs from responses
ID_PATTERNS = [
    re.compile(r'"(?:id|uuid|_id|guid)":\s*"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"', re.IGNORECASE),
    re.compile(r'"(?:id|user_id|order_id|account_id|doc_id|file_id|item_id|product_id|invoice_id|transaction_id|message_id|post_id|comment_id|ticket_id)":\s*(\d+)', re.IGNORECASE),
    re.compile(r'"(?:id|slug|key|ref)":\s*"([a-zA-Z0-9_-]{6,32})"', re.IGNORECASE),
]

TEST_METHODS = ["GET", "PUT", "PATCH", "DELETE"]


class BOLAEnginePlugin(BasePlugin):
    def name(self) -> str:
        return "BOLAEngine"

    def description(self) -> str:
        return "BOLA/IDOR Engine — Hỗ trợ REST APIs, GraphQL, WebSockets và Privilege Escalation."

    def check_installed(self) -> bool:
        return True

    def _attach_http_evidence(
        self,
        finding: dict,
        *,
        method: str,
        endpoint: str,
        payload=None,
        response=None,
        headers=None,
        validation: str,
        confidence: str = "high",
    ) -> dict:
        return attach_evidence(
            finding,
            make_evidence(
                method=method,
                url=endpoint,
                payload=payload,
                status_code=getattr(response, "status_code", None),
                request_headers=headers,
                response_headers=dict(getattr(response, "headers", {}) or {}),
                response_snippet=getattr(response, "text", "") or "",
                validation=validation,
                confidence=confidence,
            ),
        )

    def _attach_ws_evidence(self, finding: dict, *, payload: str, response_text: str, validation: str) -> dict:
        return attach_evidence(
            finding,
            make_evidence(
                method="WEBSOCKET",
                url=finding.get("endpoint"),
                payload=payload,
                response_snippet=response_text,
                validation=validation,
                confidence="high",
            ),
        )

    def _extract_csrf_token(self, session, endpoint, headers):
        """Extract CSRF token from page for stateful testing."""
        from bs4 import BeautifulSoup
        try:
            r = session.get(endpoint, headers=headers, timeout=5, verify=False)
            soup = BeautifulSoup(r.text, "html.parser")
            
            meta_csrf = soup.find("meta", {"name": re.compile(r"csrf|token", re.I)})
            if meta_csrf and meta_csrf.get("content"):
                return "X-CSRF-TOKEN", meta_csrf["content"]
            
            input_csrf = soup.find("input", {"name": re.compile(r"csrf|token|authenticity", re.I)})
            if input_csrf and input_csrf.get("value"):
                return input_csrf["name"], input_csrf["value"]
        except Exception:
            pass
        return None, None

    def _ws_send_receive(self, url: str, headers: dict, message: str) -> str | None:
        """Pure-socket implementation of WebSocket client to avoid pip dependency issues."""
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if not host:
                return None
            port = parsed.port or (443 if parsed.scheme in ("wss", "https") else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)

            if parsed.scheme in ("wss", "https") or port == 443:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=host)

            s.connect((host, port))

            # Send WS Handshake
            handshake = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
            )
            for k, v in headers.items():
                handshake += f"{k}: {v}\r\n"
            handshake += "\r\n"

            s.sendall(handshake.encode())

            # Read response headers
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = s.recv(512)
                if not chunk:
                    break
                resp += chunk

            if b"101 Switching Protocols" not in resp:
                s.close()
                return None

            # Prepare client frame (masked)
            data = message.encode()
            length = len(data)
            frame = bytearray()
            frame.append(0x81)  # FIN + Text

            if length <= 125:
                frame.append(0x80 | length)
            elif length <= 65535:
                frame.append(0x80 | 126)
                frame.extend(length.to_bytes(2, byteorder='big'))
            else:
                frame.append(0x80 | 127)
                frame.extend(length.to_bytes(8, byteorder='big'))

            mask = b"\x11\x22\x33\x44"
            frame.extend(mask)
            masked_data = bytearray(len(data))
            for i in range(len(data)):
                masked_data[i] = data[i] ^ mask[i % 4]
            frame.extend(masked_data)

            s.sendall(frame)

            # Read response
            res_head = s.recv(2)
            if len(res_head) < 2:
                s.close()
                return None

            payload_len = res_head[1] & 0x7F
            if payload_len == 126:
                payload_len = int.from_bytes(s.recv(2), byteorder='big')
            elif payload_len == 127:
                payload_len = int.from_bytes(s.recv(8), byteorder='big')

            payload = b""
            while len(payload) < payload_len:
                chunk = s.recv(payload_len - len(payload))
                if not chunk:
                    break
                payload += chunk

            s.close()
            return payload.decode(errors='ignore')
        except Exception as e:
            logger.debug(f"[BOLAEngine] WebSocket error on {url}: {e}")
            return None

    def run(self, endpoints: list, out_dir: str = "/tmp",
            token_a: str = "", token_b: str = "",
            timeout: int = 10, max_endpoints: int = 50) -> dict:
        
        os.makedirs(out_dir, exist_ok=True)

        if not token_a or not token_b:
            logger.warning("[BOLAEngine] Requires token_a and token_b. Skipping.")
            return {"skipped": True, "reason": "Missing auth tokens"}

        results = {
            "total_endpoints": len(endpoints),
            "ids_harvested": 0,
            "requests_replayed": 0,
            "high_confidence_bola": [],
            "suspicious": [],
            "graphql_findings": [],
            "websocket_findings": [],
            "privilege_escalation": [],
        }

        session_a = requests.Session()
        session_b = requests.Session()

        if token_a.startswith("eyJ"): token_a = f"Bearer {token_a}"
        if token_b.startswith("eyJ"): token_b = f"Bearer {token_b}"

        headers_a = {"Authorization": token_a, "Content-Type": "application/json"}
        headers_b = {"Authorization": token_b, "Content-Type": "application/json"}

        session_a.headers.update(headers_a)
        session_b.headers.update(headers_b)

        # ── Phase 1: Harvest IDs ──
        logger.info(f"[BOLAEngine] Phase 1: Harvesting IDs from endpoints...")
        endpoint_ids = {}
        
        for endpoint in endpoints[:max_endpoints]:
            try:
                # Check for GraphQL endpoint
                is_graphql = "graphql" in endpoint.lower()
                if is_graphql:
                    # Introspection/Me Query
                    query = {"query": "{ __schema { types { name } } }"}
                    resp_a = session_a.post(endpoint, json=query, timeout=timeout, verify=False)
                else:
                    resp_a = session_a.get(endpoint, timeout=timeout, verify=False)

                if resp_a.status_code != 200:
                    continue

                body = resp_a.text
                ids_found = set()
                
                for pattern in ID_PATTERNS:
                    matches = pattern.findall(body)
                    for match in matches:
                        ids_found.add(match)

                # Extract IDs from URL path
                path_ids = re.findall(r'/(\d{1,10}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)', endpoint)
                for pid in path_ids:
                    ids_found.add(pid)

                if ids_found:
                    endpoint_ids[endpoint] = list(ids_found)
                    results["ids_harvested"] += len(ids_found)

            except Exception as e:
                logger.debug(f"[BOLAEngine] Harvest error on {endpoint}: {e}")
                continue

        # ── Phase 2: Replay with Token B + Unauth ──
        logger.info("[BOLAEngine] Phase 2: Replaying with Token B + Unauth...")
        for endpoint, ids in endpoint_ids.items():
            is_graphql = "graphql" in endpoint.lower()
            is_admin_path = any(x in endpoint.lower() for x in ["admin", "manage", "control", "setting", "dashboard"])

            for method in (["POST"] if is_graphql else TEST_METHODS):
                try:
                    csrf_k, csrf_v = None, None
                    if not is_graphql and method in ["POST", "PUT", "PATCH", "DELETE"]:
                        csrf_k, csrf_v = self._extract_csrf_token(session_b, endpoint, headers_b)
                        
                    req_headers = headers_b.copy()
                    if csrf_k and csrf_k.startswith("X-"):
                        req_headers[csrf_k] = csrf_v
                        
                    req_data = {}
                    if csrf_k and not csrf_k.startswith("X-"):
                        req_data[csrf_k] = csrf_v

                    if is_graphql:
                        # GraphQL Query testing harvested IDs
                        graphql_payload = {
                            "query": f"query {{ user(id: \"{ids[0]}\") {{ id email role }} }}"
                        }
                        resp_b = session_b.post(endpoint, headers=req_headers, json=graphql_payload, timeout=timeout, verify=False)
                    else:
                        if method == "GET":
                            resp_b = session_b.get(endpoint, headers=req_headers, timeout=timeout, verify=False)
                        elif method == "PUT":
                            resp_b = session_b.put(endpoint, headers=req_headers, timeout=timeout, verify=False, json=req_data)
                        elif method == "PATCH":
                            resp_b = session_b.patch(endpoint, headers=req_headers, timeout=timeout, verify=False, json=req_data)
                        elif method == "DELETE":
                            resp_b = session_b.delete(endpoint, headers=req_headers, timeout=timeout, verify=False, json=req_data)
                        else:
                            continue

                    results["requests_replayed"] += 1

                    if resp_b.status_code == 200:
                        # Baseline check
                        if is_graphql:
                            resp_a_check = session_a.post(endpoint, headers=headers_a, json=graphql_payload, timeout=timeout, verify=False)
                            resp_unauth = requests.post(endpoint, json=graphql_payload, timeout=timeout, verify=False)
                        else:
                            resp_a_check = requests.get(endpoint, headers=headers_a, timeout=timeout, verify=False)
                            resp_unauth = requests.get(endpoint, timeout=timeout, verify=False)

                        len_diff = abs(len(resp_b.text) - len(resp_a_check.text))

                        if len_diff < 50 and len(resp_b.text) > 50:
                            if resp_unauth.status_code in (401, 403):
                                finding = {
                                    "endpoint": endpoint,
                                    "method": method,
                                    "status_a": resp_a_check.status_code,
                                    "status_b": resp_b.status_code,
                                    "status_unauth": resp_unauth.status_code,
                                    "ids_found": ids[:5],
                                    "evidence": f"User B got identical response payload as User A, but Unauthenticated was correctly BLOCKED ({resp_unauth.status_code})."
                                }
                                finding = self._attach_http_evidence(
                                    finding,
                                    method=method,
                                    endpoint=endpoint,
                                    payload=graphql_payload if is_graphql else req_data,
                                    response=resp_b,
                                    headers=req_headers,
                                    validation=(
                                        f"User A status {resp_a_check.status_code}, User B status {resp_b.status_code}; "
                                        f"body length delta {len_diff}; unauthenticated status {resp_unauth.status_code}."
                                    ),
                                )
                                if is_graphql:
                                    results["graphql_findings"].append(finding)
                                elif is_admin_path:
                                    results["privilege_escalation"].append(finding)
                                else:
                                    results["high_confidence_bola"].append(finding)
                            elif resp_unauth.status_code == 200:
                                suspicious = {
                                    "endpoint": endpoint,
                                    "method": method,
                                    "evidence": "Publicly accessible endpoint (no auth required)."
                                }
                                results["suspicious"].append(self._attach_http_evidence(
                                    suspicious,
                                    method=method,
                                    endpoint=endpoint,
                                    payload=graphql_payload if is_graphql else req_data,
                                    response=resp_unauth,
                                    headers={},
                                    validation="Unauthenticated request returned HTTP 200; public exposure or intentionally public endpoint must be reviewed.",
                                    confidence="medium",
                                ))
                except Exception as e:
                    logger.debug(f"[BOLAEngine] Replay failed: {e}")

        # ── Phase 3: WebSocket BOLA Testing ──
        logger.info("[BOLAEngine] Phase 3: Scanning WebSockets...")
        for endpoint in endpoints[:max_endpoints]:
            parsed = urlparse(endpoint)
            # Try to build matching ws/wss URL
            ws_scheme = "wss" if parsed.scheme in ("https", "wss") else "ws"
            ws_url = f"{ws_scheme}://{parsed.netloc}/ws"
            
            # Simple subscribe message mock using harvested IDs
            test_id = results["ids_harvested"] and endpoint_ids.get(endpoint, ["1"])[0] or "1"
            ws_message = json.dumps({"action": "subscribe", "id": test_id})

            # Check User A (baseline)
            res_a = self._ws_send_receive(ws_url, headers_a, ws_message)
            if res_a:
                # Check User B and Unauth
                res_b = self._ws_send_receive(ws_url, headers_b, ws_message)
                res_unauth = self._ws_send_receive(ws_url, {}, ws_message)

                if res_b and (res_unauth is None or "error" in res_unauth.lower() or "auth" in res_unauth.lower()):
                    len_diff_ws = abs(len(res_b) - len(res_a))
                    if len_diff_ws < 50:
                        finding = {
                            "endpoint": ws_url,
                            "message": ws_message,
                            "evidence": f"WebSocket server returned data to User B (length: {len(res_b)}), but rejected Unauthenticated connection/message."
                        }
                        results["websocket_findings"].append(self._attach_ws_evidence(
                            finding,
                            payload=ws_message,
                            response_text=res_b,
                            validation=(
                                f"User A and User B WebSocket responses were similar; unauthenticated connection/message was rejected; "
                                f"body length delta {len_diff_ws}."
                            ),
                        ))

        # ── Save Reports ──
        self._write_reports(out_dir, results)

        return results

    def _write_reports(self, out_dir: str, results: dict):
        # 1. Plain Text Report
        txt_report = os.path.join(out_dir, "high_confidence_bola.txt")
        with open(txt_report, "w", encoding="utf-8") as f:
            f.write(f"# PenLabs — BOLA/IDOR Findings\n")
            f.write(f"Harvested IDs: {results['ids_harvested']}\n")
            f.write(f"BOLA/IDOR findings: {len(results['high_confidence_bola'])}\n")
            f.write(f"GraphQL BOLA: {len(results['graphql_findings'])}\n")
            f.write(f"WebSocket BOLA: {len(results['websocket_findings'])}\n")
            f.write(f"Privilege Escalation: {len(results['privilege_escalation'])}\n")
            f.write("=" * 60 + "\n\n")
            
            for b in results["high_confidence_bola"]:
                f.write(f"[CRITICAL BOLA] {b['method']} {b['endpoint']}\n  Evidence: {b['evidence']}\n\n")
            for g in results["graphql_findings"]:
                f.write(f"[GRAPHQL BOLA] POST {g['endpoint']}\n  Evidence: {g['evidence']}\n\n")
            for w in results["websocket_findings"]:
                f.write(f"[WEBSOCKET BOLA] {w['endpoint']}\n  Message: {w['message']}\n  Evidence: {w['evidence']}\n\n")
            for p in results["privilege_escalation"]:
                f.write(f"[PRIVILEGE ESCALATION] {p['method']} {p['endpoint']}\n  Evidence: {p['evidence']}\n\n")

        # 2. Markdown Report with Evidence
        md_report = os.path.join(out_dir, "bola_report.md")
        with open(md_report, "w", encoding="utf-8") as f:
            f.write("# ⚔️ BOLA & IDOR Vulnerability Assessment Report\n\n")
            f.write("> [!IMPORTANT]\n")
            f.write("> Broken Object Level Authorization (BOLA/IDOR) allows attackers to access data of other users by manipulating object IDs. This report documents verified vulnerabilities using 3-Way response comparison.\n\n")
            
            f.write("## 📊 Summary of Findings\n\n")
            f.write("| Vulnerability Type | Count | Severity |\n")
            f.write("| --- | --- | --- |\n")
            f.write(f"| BOLA/IDOR (REST APIs) | {len(results['high_confidence_bola'])} | `CRITICAL` |\n")
            f.write(f"| GraphQL BOLA | {len(results['graphql_findings'])} | `HIGH` |\n")
            f.write(f"| WebSocket BOLA | {len(results['websocket_findings'])} | `HIGH` |\n")
            f.write(f"| Privilege Escalation (Unprivileged -> Admin) | {len(results['privilege_escalation'])} | `CRITICAL` |\n\n")

            f.write("## 🧬 Threat Model Flow (3-Way Check)\n\n")
            f.write("```mermaid\n")
            f.write("sequenceDiagram\n")
            f.write("    autonumber\n")
            f.write("    attacker(User B)->>API: Send Request with Object ID of User A (Auth B Token)\n")
            f.write("    alt Response status 200 and matches User A data\n")
            f.write("        API->>attacker(User B): Return sensitive data\n")
            f.write("        attacker(User B)->>API: Replay same Request without Auth Token\n")
            f.write("        alt Response status 401/403 (Blocked)\n")
            f.write("            API->>attacker(User B): Access Denied (Correctly Protected)\n")
            f.write("            Note over attacker(User B),API: BOLA Confirmed (Vulnerability!)\n")
            f.write("        end\n")
            f.write("    end\n")
            f.write("```\n\n")

            if results["high_confidence_bola"]:
                f.write("## 🔴 Verified BOLA/IDOR Findings (REST APIs)\n\n")
                for item in results["high_confidence_bola"]:
                    f.write(f"### `{item['method']}` {item['endpoint']}\n")
                    f.write(f"- **Severity:** `CRITICAL`\n")
                    f.write(f"- **Response Status A:** `{item['status_a']}` | **Response Status B:** `{item['status_b']}` | **Unauthenticated Status:** `{item['status_unauth']}`\n")
                    f.write(f"- **Evidence:** {item['evidence']}\n")
                    f.write(f"- **Target IDs Tested:** `{item['ids_found']}`\n\n")

            if results["graphql_findings"]:
                f.write("## 🟣 Verified GraphQL BOLA Findings\n\n")
                for item in results["graphql_findings"]:
                    f.write(f"### `POST` {item['endpoint']}\n")
                    f.write(f"- **Severity:** `HIGH`\n")
                    f.write(f"- **Evidence:** {item['evidence']}\n")
                    f.write(f"- **Target IDs Tested:** `{item['ids_found']}`\n\n")

            if results["websocket_findings"]:
                f.write("## 🔵 Verified WebSocket BOLA Findings\n\n")
                for item in results["websocket_findings"]:
                    f.write(f"### `{item['endpoint']}`\n")
                    f.write(f"- **Severity:** `HIGH`\n")
                    f.write(f"- **Payload Message:** `{item['message']}`\n")
                    f.write(f"- **Evidence:** {item['evidence']}\n\n")

            if results["privilege_escalation"]:
                f.write("## 💀 Verified Privilege Escalation Findings (User -> Admin Endpoints)\n\n")
                for item in results["privilege_escalation"]:
                    f.write(f"### `{item['method']}` {item['endpoint']}\n")
                    f.write(f"- **Severity:** `CRITICAL`\n")
                    f.write(f"- **Evidence:** {item['evidence']}\n")
                    f.write(f"- **Target IDs Tested:** `{item['ids_found']}`\n\n")

        # 3. JSON Output
        json_out = os.path.join(out_dir, "bola_results.json")
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, default=str)
