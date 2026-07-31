"""
PenLabs V1.0 — Race Condition Tester Plugin
Phát hiện Race Condition (TOCTOU/Double-Spend) bằng concurrent requests.
Thay thế Turbo Intruder bằng Python asyncio + aiohttp.
"""
import os
import json
import asyncio
import logging
import time
from core.base_plugin import BasePlugin
from core.evidence import attach_evidence, make_evidence

logger = logging.getLogger(__name__)

# Keywords gợi ý endpoint nhạy cảm với Race Condition
RACE_KEYWORDS = [
    "checkout", "payment", "pay", "transfer", "send",
    "redeem", "coupon", "voucher", "credit", "withdraw",
    "purchase", "buy", "order", "subscribe", "upgrade",
    "invite", "join", "follow", "like", "vote",
    "delete", "remove", "cancel", "refund",
    "apply", "claim", "activate", "register",
]


class RaceConditionPlugin(BasePlugin):
    def name(self) -> str:
        return "RaceTest"

    def description(self) -> str:
        return "Race Condition Tester — Gửi N requests đồng thời phát hiện TOCTOU/Double-Spend (thay thế Turbo Intruder)."

    def check_installed(self) -> bool:
        return True  # Built-in Python

    def run(self, urls: list, out_dir: str = "/tmp",
            headers: dict = None, concurrent: int = 30,
            timeout: int = 15, max_urls: int = 20,
            method: str = "POST",
            json_body: dict = None) -> list:
        """
        [V1.0] Test Race Condition trên danh sách URLs.
        Gửi `concurrent` requests đồng thời và phân tích response.
        
        Args:
            method: HTTP method (POST/PUT/PATCH/GET). Default POST — Race Condition
                    chủ yếu xảy ra ở state-changing endpoints.
            json_body: JSON body mặc định cho POST/PUT/PATCH.
                       Default: {"amount": 100, "action": "transfer"}
        """
        os.makedirs(out_dir, exist_ok=True)
        method = method.upper()
        if json_body is None:
            json_body = {"amount": 100, "action": "transfer"}
        
        # Filter chỉ kiểm tra endpoints nhạy cảm (có keywords liên quan tiền/state)
        sensitive_urls = []
        for url in urls[:max_urls]:
            url_lower = url.lower()
            for kw in RACE_KEYWORDS:
                if kw in url_lower:
                    sensitive_urls.append(url)
                    break
        
        if not sensitive_urls:
            logger.info("[RaceTest] No sensitive endpoints found for race testing.")
            return []

        # Run async race tests
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(
                        asyncio.run,
                        self._async_race_test(sensitive_urls, headers, concurrent, timeout, method, json_body)
                    )
                    results = future.result()
            else:
                results = loop.run_until_complete(
                    self._async_race_test(sensitive_urls, headers, concurrent, timeout, method, json_body)
                )
        except RuntimeError:
            results = asyncio.run(
                self._async_race_test(sensitive_urls, headers, concurrent, timeout, method, json_body)
            )

        # Save
        out_file = os.path.join(out_dir, "race_condition_results.json")
        with open(out_file, "w") as f:
            json.dump(results, f, indent=2, default=str)

        logger.info(f"[RaceTest] Tested {len(sensitive_urls)} endpoints ({method}), found {len(results)} race candidates.")
        return results

    async def _async_race_test(self, urls: list, headers: dict = None,
                                concurrent: int = 30, timeout: int = 15,
                                method: str = "POST", json_body: dict = None,
                                proxy_mode: str = "exploit") -> list:
        """[V1.0] Thực hiện race condition test bằng asyncio với proxy support."""
        try:
            import aiohttp
        except ImportError:
            return self._sync_race_test(urls, headers, concurrent, timeout, method, json_body)

        findings = []
        
        #  Use unified proxy from Config
        from config import Config as _Cfg
        proxy_url = _Cfg.get_proxy_url(proxy_mode)
        
        async with aiohttp.ClientSession(
            headers=headers or {},
            connector=aiohttp.TCPConnector(ssl=False, limit=concurrent * 2),
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as session:
            for url in urls:
                try:
                    finding = await self._test_single_endpoint(session, url, concurrent, timeout, method, json_body, proxy_url)
                    if finding:
                        findings.append(finding)
                except Exception as e:
                    logger.debug(f"[RaceTest] Error testing {url}: {e}")

        return findings

    async def _test_single_endpoint(self, session, url: str,
                                     concurrent: int, timeout: int,
                                     method: str = "POST", json_body: dict = None,
                                     proxy: str = None) -> dict:
        """[V1.0] Test 1 endpoint: gửi N requests đồng thời với proxy support."""
        import aiohttp

        # Phase 1: Get baseline response
        try:
            if method in ("POST", "PUT", "PATCH"):
                async with session.post(url, json=json_body, proxy=proxy) as baseline_resp:
                    baseline_status = baseline_resp.status
                    baseline_body = await baseline_resp.text()
                    baseline_length = len(baseline_body)
            else:
                async with session.get(url, proxy=proxy) as baseline_resp:
                    baseline_status = baseline_resp.status
                    baseline_body = await baseline_resp.text()
                    baseline_length = len(baseline_body)
        except Exception:
            return None

        # Phase 2: Fire N concurrent requests with configured method
        async def _fire_request(idx):
            try:
                start = time.monotonic()
                if method == "POST":
                    async with session.post(url, json=json_body, proxy=proxy) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text()
                        return {"index": idx, "status": resp.status, "length": len(body), "elapsed_ms": round(elapsed * 1000, 2)}
                elif method == "PUT":
                    async with session.put(url, json=json_body, proxy=proxy) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text()
                        return {"index": idx, "status": resp.status, "length": len(body), "elapsed_ms": round(elapsed * 1000, 2)}
                elif method == "PATCH":
                    async with session.patch(url, json=json_body, proxy=proxy) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text()
                        return {"index": idx, "status": resp.status, "length": len(body), "elapsed_ms": round(elapsed * 1000, 2)}
                else:  # GET
                    async with session.get(url, proxy=proxy) as resp:
                        elapsed = time.monotonic() - start
                        body = await resp.text()
                        return {"index": idx, "status": resp.status, "length": len(body), "elapsed_ms": round(elapsed * 1000, 2)}
            except Exception as e:
                return {"index": idx, "status": 0, "error": str(e)}

        tasks = [_fire_request(i) for i in range(concurrent)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Phase 3: Analyze responses for anomalies
        valid_responses = [r for r in responses if isinstance(r, dict) and r.get("status", 0) > 0]
        if not valid_responses:
            return None

        statuses = [r["status"] for r in valid_responses]
        lengths = [r["length"] for r in valid_responses]
        
        unique_statuses = set(statuses)
        length_variance = max(lengths) - min(lengths) if lengths else 0
        success_count = sum(1 for s in statuses if s == 200)

        is_race = False
        confidence = "LOW"
        evidence = ""

        if len(unique_statuses) > 1 and 200 in unique_statuses:
            is_race = True
            confidence = "MEDIUM"
            evidence = f"Mixed statuses: {dict((s, statuses.count(s)) for s in unique_statuses)}"
        
        if length_variance > 100:
            is_race = True
            confidence = "MEDIUM"
            evidence += f" | Response length variance: {length_variance} bytes"

        if success_count == concurrent and any(kw in url.lower() for kw in ["pay", "transfer", "redeem", "credit"]):
            is_race = True
            confidence = "HIGH"
            evidence += f" | All {concurrent} {method} requests returned 200 OK for financial endpoint"

        if is_race:
            finding = {
                "url": url,
                "method": method,
                "json_body": json_body if method != "GET" else None,
                "confidence": confidence,
                "concurrent_requests": concurrent,
                "success_count": success_count,
                "unique_statuses": list(unique_statuses),
                "length_variance": length_variance,
                "evidence": evidence.strip(" |"),
                "severity": "HIGH" if confidence == "HIGH" else "MEDIUM",
                "recommendation": f"Verify with Burp Turbo Intruder using {method} method",
            }
            return attach_evidence(
                finding,
                make_evidence(
                    method=method,
                    url=url,
                    payload=json_body if method != "GET" else None,
                    status_code=baseline_status,
                    response_snippet=json.dumps({
                        "baseline_status": baseline_status,
                        "baseline_length": baseline_length,
                        "sample_responses": valid_responses[:5],
                    }, default=str),
                    validation=(
                        f"Baseline status {baseline_status}; {concurrent} concurrent requests produced statuses "
                        f"{dict((s, statuses.count(s)) for s in unique_statuses)} and length variance {length_variance}."
                    ),
                    confidence=confidence.lower(),
                ),
            )
        return None

    def _sync_race_test(self, urls: list, headers: dict = None,
                        concurrent: int = 30, timeout: int = 15,
                        method: str = "POST", json_body: dict = None) -> list:
        """[V1.0] Fallback synchronous race test với POST/PUT/PATCH/GET."""
        import requests as req
        from concurrent.futures import ThreadPoolExecutor, as_completed

        findings = []
        
        for url in urls:
            def _req(idx):
                try:
                    start = time.monotonic()
                    if method == "POST":
                        r = req.post(url, headers=headers or {}, json=json_body, timeout=timeout, verify=False)
                    elif method == "PUT":
                        r = req.put(url, headers=headers or {}, json=json_body, timeout=timeout, verify=False)
                    elif method == "PATCH":
                        r = req.patch(url, headers=headers or {}, json=json_body, timeout=timeout, verify=False)
                    else:
                        r = req.get(url, headers=headers or {}, timeout=timeout, verify=False)
                    return {"status": r.status_code, "length": len(r.text), "elapsed": time.monotonic() - start}
                except Exception:
                    return None

            with ThreadPoolExecutor(max_workers=concurrent) as pool:
                futures = [pool.submit(_req, i) for i in range(concurrent)]
                results = [f.result() for f in as_completed(futures) if f.result()]
            
            if results:
                statuses = [r["status"] for r in results]
                lengths = [r["length"] for r in results]
                unique = set(statuses)
                variance = max(lengths) - min(lengths) if lengths else 0
                
                if len(unique) > 1 or variance > 100:
                    finding = {
                        "url": url,
                        "method": method,
                        "confidence": "MEDIUM",
                        "concurrent_requests": concurrent,
                        "unique_statuses": list(unique),
                        "length_variance": variance,
                        "severity": "MEDIUM",
                        "evidence": f"Concurrent requests produced statuses {dict((s, statuses.count(s)) for s in unique)} and length variance {variance}.",
                    }
                    findings.append(attach_evidence(
                        finding,
                        make_evidence(
                            method=method,
                            url=url,
                            payload=json_body if method != "GET" else None,
                            response_snippet=json.dumps({"sample_responses": results[:5]}, default=str),
                            validation=(
                                f"Synchronous fallback produced statuses {dict((s, statuses.count(s)) for s in unique)} "
                                f"and length variance {variance}."
                            ),
                            confidence="medium",
                        ),
                    ))

        return findings
