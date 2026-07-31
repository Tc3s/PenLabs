import os
import json
import logging
import requests
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence


class GraphQLProbePlugin(BasePlugin):
    """GraphQL Probe — Phát hiện và khai thác GraphQL endpoints."""

    # Danh sách paths phổ biến cho GraphQL endpoints
    GRAPHQL_PATHS = [
        "/graphql", "/graphiql", "/gql", "/graphql/console",
        "/v1/graphql", "/v2/graphql", "/api/graphql",
        "/altair", "/playground", "/graphql-explorer",
        "/graphql/schema", "/query",
        "/__graphql", "/graphql/v1", "/graphql/v2",
    ]

    # Introspection Query chuẩn
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields(includeDeprecated: true) {
            name
            args { name type { name kind } }
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """

    # Mini query để detect GraphQL
    DETECT_QUERY = '{"query": "{ __typename }"}'

    def name(self) -> str:
        return "GraphQLProbe"

    def description(self) -> str:
        return "GraphQL Probe — Phát hiện GraphQL endpoints, introspection, schema dump."

    def check_installed(self) -> bool:
        return True  # Pure Python — no external binary

    def run(self, base_urls: list, out_dir: str = "/tmp",
            headers: dict = None, timeout: int = 10,
            max_urls: int = 10, proxy_mode: str = "fuzz") -> dict:
        """
        Quét GraphQL endpoints trên danh sách base URLs.
        """
        os.makedirs(out_dir, exist_ok=True)
        result = {
            "endpoints_found": [],
            "introspection_enabled": [],
            "schemas": {},
            "mutations": [],
            "findings": [],
            "graphql_vulns": [],
        }

        #  Use StealthNet session for unified fingerprinting
        from plugins.stealth_net_plugin import StealthNetPlugin
        stealth_net = StealthNetPlugin(scan_mode=proxy_mode)
        stealth_net.run()
        session = stealth_net._session

        req_headers = {"Content-Type": "application/json"}
        if headers:
            req_headers.update(headers)

        for base_url in base_urls[:max_urls]:
            base_url = base_url.strip().rstrip("/")
            if not base_url:
                continue

            # Step 1: Tìm GraphQL endpoint
            for path in self.GRAPHQL_PATHS:
                endpoint = f"{base_url}{path}"
                try:
                    # Test bằng mini query
                    resp = session.post(
                        endpoint,
                        data=self.DETECT_QUERY,
                        headers=req_headers,
                        timeout=timeout
                    )

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                            # GraphQL response luôn có "data" hoặc "errors" key
                            if "data" in data or "errors" in data:
                                result["endpoints_found"].append(endpoint)
                                logging.info(f"[GraphQL] Tìm thấy endpoint: {endpoint}")

                                # Step 2: Thử Introspection
                                self._try_introspection(session, endpoint, req_headers, timeout, result, out_dir)
                                break  # Tìm thấy rồi, không cần thử path khác
                        except (json.JSONDecodeError, ValueError):
                            continue

                except Exception:
                    continue

        # Lưu results
        output_path = os.path.join(out_dir, "graphql_probe.json")
        try:
            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)
        except Exception:
            pass

        total_findings = len(result["endpoints_found"])
        introspection_count = len(result["introspection_enabled"])
        logging.info(f"[GraphQL] Tìm thấy {total_findings} endpoints, {introspection_count} có introspection enabled.")
        return result

    def _try_introspection(self, session, endpoint: str, headers: dict,
                           timeout: int, result: dict, out_dir: str):
        """Thử introspection query trên endpoint."""
        try:
            resp = session.post(
                endpoint,
                json={"query": self.INTROSPECTION_QUERY.strip()},
                headers=headers,
                timeout=timeout + 5,  # Extra time cho large schema
            )

            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data.get("data", {}):
                    introspection_finding = {
                        "url": endpoint,
                        "details": "GraphQL introspection enabled",
                        "severity": "high",
                    }
                    schema = data["data"]["__schema"]
                    result["schemas"][endpoint] = schema

                    # Extract mutations (high-value targets cho Bug Bounty)
                    types = schema.get("types", [])
                    for t in types:
                        if t.get("kind") == "OBJECT":
                            fields = t.get("fields", [])
                            if fields:
                                for field in fields:
                                    field_name = field.get("name", "")
                                    # Tìm mutations liên quan đến user/admin/data
                                    if any(kw in field_name.lower() for kw in [
                                        "create", "update", "delete", "modify",
                                        "admin", "user", "password", "role",
                                        "upload", "execute", "grant"
                                    ]):
                                        result["mutations"].append({
                                            "endpoint": endpoint,
                                            "type": t.get("name", ""),
                                            "field": field_name,
                                            "args": [a.get("name") for a in field.get("args", [])],
                                        })

                    finding = {
                        "url": endpoint,
                        "type": "graphql_introspection_enabled",
                        "severity": "high",
                        "details": f"Full schema exposed: {len(types)} types, {len(result['mutations'])} sensitive mutations",
                    }
                    finding = attach_evidence(
                        finding,
                        make_evidence(
                            method="POST",
                            url=endpoint,
                            payload={"query": "IntrospectionQuery"},
                            status_code=resp.status_code,
                            request_headers=headers,
                            response_headers=dict(resp.headers or {}),
                            response_snippet=resp.text or "",
                            validation=(
                                f"GraphQL introspection returned __schema with {len(types)} types "
                                f"and {len(result['mutations'])} mutation-like fields."
                            ),
                            confidence="high",
                            raw_artifact=os.path.join(out_dir, "graphql_schema_dump.json"),
                        ),
                    )
                    result["introspection_enabled"].append({
                        **introspection_finding,
                        "evidence": finding.get("evidence", introspection_finding["details"]),
                        "evidence_detail": finding.get("evidence_detail", {}),
                    })
                    result["findings"].append(finding)
                    result["graphql_vulns"].append(finding)

                    # Lưu schema dump riêng
                    schema_path = os.path.join(out_dir, "graphql_schema_dump.json")
                    try:
                        with open(schema_path, 'w') as f:
                            json.dump(data, f, indent=2)
                    except Exception:
                        pass

        except Exception as e:
            logging.debug(f"[GraphQL] Introspection failed for {endpoint}: {e}")
