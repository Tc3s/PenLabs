# P0-2: Plugin Cleanup — Plan chi tiết

**Ngày tạo:** 2026-06-24
**Phạm vi:** 4 plugin files trong `plugins/`
**Mục tiêu:** Sửa duplicate class, thiếu retry/rate-limit, và heuristic sai trong plugin OSINT/scan.

---

## 1. Hiện trạng (Current State)

### 1.1 File inventory

| File | Dòng | Trạng thái |
|---|---|---|
| `plugins/shodan_plugin.py` | 22 | **TRÙNG class name** với `shodan_internetdb_plugin.py` |
| `plugins/shodan_internetdb_plugin.py` | 131 | Đầy đủ chức năng, có StealthNet integration |
| `plugins/virustotal_plugin.py` | 25 | Thiếu retry + rate-limit (VT API: 4 req/min cho free tier) |
| `plugins/mass_assignment_plugin.py` | 57 | Heuristic dễ false-positive |

### 1.2 Evidence trích từ file thật

**`shodan_plugin.py` (line 5–7):**
```python
class ShodanInternetDBPlugin(BasePlugin):
    def name(self) -> str:
        return "ShodanInternetDB"
```
Class này TRÙNG TÊN `ShodanInternetDBPlugin` với file khác và là bản rút gọn (không có StealthNet, không có fallback `404`/`error` field). File này thực chất là stub cũ — nên đổi tên thành `ShodanHostnamePlugin` để dùng cho lookup hostname thật qua Shodan API key.

**`shodan_internetdb_plugin.py` (line 15):**
```python
class InternetDBPlugin(BasePlugin):
    return "InternetDB"  # line 31
```
Bản đầy đủ với `lookup()`, `has_web_ports()`, `hostname_matches()`. Đây là implementation canonical cho InternetDB.

**`virustotal_plugin.py` (line 15–24):**
```python
def run(self, ip: str, api_key: str) -> dict:
    if not api_key:
        return {}
    try:
        headers = {"x-apikey": api_key, "Accept": "application/json"}
        r = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json().get('data', {}).get('attributes', {})
    except Exception as e:
        logging.warning(f"VirusTotal query failed for {ip}: {e}")
    return {}
```
**Vấn đề:** Không xử lý `429 Too Many Requests` (VT free: 4 req/min, 500 req/day). Không retry. Không backoff. Không cache. Một IP hợp lệ bị rate-limit sẽ silently trả `{}` — false-negative trong báo cáo.

**`mass_assignment_plugin.py` (line 34, 46):**
```python
resp = requests.post(url, json=payload, headers=headers, timeout=timeout, verify=False)
if resp.status_code == 200 and "admin" in resp.text.lower():
    findings.append({...})
```
**Vấn đề:** Heuristic `"admin" in resp.text.lower()` quá rộng. Bất kỳ response 200 nào có chứa từ "admin" (ví dụ: footer "Admin Panel v1.0", CSS class `admin-login`, link "admin@example.com", error message "admin required") sẽ bị flag là mass assignment — false-positive rất cao. Cần so sánh diff giữa response gốc (User A không gửi payload) và response sau khi gửi payload (User B với `is_admin: true`).

---

## 2. Phân tích Duplicate: `shodan_plugin.py` vs `shodan_internetdb_plugin.py`

### 2.1 Bảng so sánh

| Thuộc tính | `shodan_plugin.py` | `shodan_internetdb_plugin.py` |
|---|---|---|
| Class name | `ShodanInternetDBPlugin` | `InternetDBPlugin` |
| Plugin name (string) | `"ShodanInternetDB"` | `"InternetDB"` |
| Endpoint | `https://internetdb.shodan.io/{ip}` | `https://internetdb.shodan.io/{ip}` |
| HTTP lib | `requests` thuần | `StealthNetPlugin` + `requests` fallback |
| Status code handling | Chỉ `200` | `200`, `404` (`no_data`), các code khác |
| Return schema | Raw `r.json()` (không key `error`) | Dict chuẩn: `{ip, ports, hostnames, tags, vulns, cpes, error}` |
| Helper methods | Không có | `has_web_ports()`, `hostname_matches()` |
| Logging | `logging.warning` | `log.info` qua named logger `"InternetDB"` |
| Yêu cầu API key | Không | Không |

### 2.2 Rủi ro thực tế

1. **Class name collision**: cả hai file định nghĩa `ShodanInternetDBPlugin` (file 22-dòng) và `InternetDBPlugin` (file 131-dòng). Khi plugin loader dùng `inspect` để discover subclass của `BasePlugin`, sẽ load cả hai — ghi đè không xác định.
2. **`shodan_plugin.py` thực ra sai về mặt ngữ nghĩa**: tên file là "shodan" nhưng implementation là InternetDB (no-key endpoint). Shodan Hostname API thật (`/shodan/host/{ip}`) CẦN API key — đó là chức năng còn thiếu.

### 2.3 Hướng xử lý

- **Giữ** `shodan_internetdb_plugin.py` (bản canonical) — không đổi class name.
- **Đổi tên class** trong `shodan_plugin.py` → `ShodanHostnamePlugin`; chuyển implementation sang gọi `https://api.shodan.io/shodan/host/{ip}` với API key (resolve thành hostnames đầy đủ, ASN, OS — khác InternetDB).

---

## 3. Code skeleton cho fix

### 3.1 Fix A — `plugins/shodan_plugin.py` (đổi tên class + Shodan Host API)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shodan Hostname Plugin — Truy vấn Shodan Host API (CẦN API Key).
Endpoint: https://api.shodan.io/shodan/host/{ip}?key={API_KEY}
Trả về: ip, hostnames, ports, vulns, asn, os, city, country, org.
"""
import logging
import os
from typing import Optional, Dict
import requests
from core.base_plugin import BasePlugin

log = logging.getLogger("ShodanHostname")


class ShodanHostnamePlugin(BasePlugin):
    """Plugin truy vấn Shodan Host API — yêu cầu SHODAN_API_KEY."""

    # Shodan Host API: 1 req/sec cho free tier
    DEFAULT_TIMEOUT = 10
    MAX_RETRIES = 3
    BACKOFF_SECONDS = 1.5

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY", "")
        self.session = requests.Session()

    def name(self) -> str:
        return "ShodanHostname"

    def description(self) -> str:
        return "OSINT Plugin — Shodan Host API lookup (yêu cầu API key)."

    def check_installed(self) -> bool:
        return bool(self.api_key)

    def run(self, ip: str, api_key: Optional[str] = None) -> Dict:
        key = api_key or self.api_key
        if not key:
            log.warning("[ShodanHostname] Missing API key; skipping.")
            return {"ip": ip, "error": "missing_api_key", "hostnames": [], "ports": [], "vulns": []}

        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": key, "minify": True}

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                r = self.session.get(url, params=params, timeout=self.DEFAULT_TIMEOUT)
                if r.status_code == 200:
                    data = r.json()
                    return {
                        "ip": ip,
                        "hostnames": data.get("hostnames", []),
                        "ports": data.get("ports", []),
                        "vulns": data.get("vulns", []),
                        "asn": data.get("asn"),
                        "os": data.get("os"),
                        "city": data.get("city"),
                        "country": data.get("country_name"),
                        "org": data.get("org"),
                        "error": None,
                    }
                if r.status_code == 401:
                    return {"ip": ip, "error": "invalid_api_key"}
                if r.status_code == 404:
                    return {"ip": ip, "error": "no_data", "hostnames": [], "ports": [], "vulns": []}
                if r.status_code == 429:
                    wait = self.BACKOFF_SECONDS * attempt
                    log.warning(f"[ShodanHostname] Rate-limited; sleeping {wait}s (attempt {attempt})")
                    import time; time.sleep(wait)
                    continue
                return {"ip": ip, "error": f"HTTP {r.status_code}"}
            except requests.RequestException as e:
                log.warning(f"[ShodanHostname] {ip} attempt {attempt} failed: {e}")
                if attempt == self.MAX_RETRIES:
                    return {"ip": ip, "error": str(e), "hostnames": [], "ports": [], "vulns": []}
        return {"ip": ip, "error": "max_retries_exceeded"}
```

### 3.2 Fix B — `plugins/virustotal_plugin.py` (retry + rate-limit)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal Plugin — OSINT IP lookup qua VT API v3.
Free tier: 4 req/min, 500 req/day, 15.5K req/month.
BẮT BUỘC xử lý 429 + 204 (quota exceeded cho public API).
"""
import logging
import os
import time
from typing import Optional, Dict, Any
import requests
from core.base_plugin import BasePlugin

log = logging.getLogger("VirusTotal")


class VirusTotalPlugin(BasePlugin):
    """Plugin truy vấn VirusTotal API v3 — có retry + rate-limit handling."""

    BASE_URL = "https://www.virustotal.com/api/v3"
    TIMEOUT = 15
    MAX_RETRIES = 4
    # 4 req/min cho free tier → an toàn 16s/req
    MIN_INTERVAL_SECONDS = 16.0
    # VT trả Retry-After header; default nếu không có
    DEFAULT_BACKOFF = 16

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        self.session = requests.Session()
        self._last_call_ts = 0.0

    def name(self) -> str:
        return "VirusTotal"

    def description(self) -> str:
        return "OSINT Plugin — VirusTotal API v3 IP lookup (4 req/min free tier)."

    def check_installed(self) -> bool:
        return bool(self.api_key)

    def _rate_limit(self) -> None:
        """Đảm bảo khoảng cách tối thiểu giữa 2 request."""
        elapsed = time.time() - self._last_call_ts
        if elapsed < self.MIN_INTERVAL_SECONDS:
            sleep_for = self.MIN_INTERVAL_SECONDS - elapsed
            log.debug(f"[VirusTotal] Sleeping {sleep_for:.1f}s to respect rate-limit.")
            time.sleep(sleep_for)

    def run(self, ip: str, api_key: Optional[str] = None) -> Dict[str, Any]:
        key = api_key or self.api_key
        if not key:
            log.warning("[VirusTotal] Missing API key; skipping.")
            return {"ip": ip, "error": "missing_api_key", "reputation": None, "malicious_vendors": 0}

        headers = {"x-apikey": key, "Accept": "application/json"}
        url = f"{self.BASE_URL}/ip_addresses/{ip}"

        for attempt in range(1, self.MAX_RETRIES + 1):
            try:
                self._rate_limit()
                r = self.session.get(url, headers=headers, timeout=self.TIMEOUT)
                self._last_call_ts = time.time()

                if r.status_code == 200:
                    attrs = r.json().get("data", {}).get("attributes", {})
                    return {
                        "ip": ip,
                        "reputation": attrs.get("reputation"),
                        "malicious_vendors": attrs.get("last_analysis_stats", {}).get("malicious", 0),
                        "country": attrs.get("country"),
                        "asn": attrs.get("asn"),
                        "as_owner": attrs.get("as_owner"),
                        "error": None,
                    }
                if r.status_code == 401:
                    return {"ip": ip, "error": "invalid_api_key"}
                if r.status_code in (429, 204):
                    # 429 = rate-limit; 204 = quota exceeded (public API không có header)
                    retry_after = int(r.headers.get("Retry-After", self.DEFAULT_BACKOFF))
                    wait = retry_after if retry_after > 0 else self.DEFAULT_BACKOFF * attempt
                    log.warning(f"[VirusTotal] {r.status_code} on {ip}; backing off {wait}s (attempt {attempt}/{self.MAX_RETRIES})")
                    if attempt == self.MAX_RETRIES:
                        return {"ip": ip, "error": f"http_{r.status_code}_exhausted"}
                    time.sleep(wait)
                    continue
                if r.status_code == 404:
                    return {"ip": ip, "error": "not_found"}
                return {"ip": ip, "error": f"HTTP {r.status_code}"}
            except requests.RequestException as e:
                log.warning(f"[VirusTotal] {ip} attempt {attempt} failed: {e}")
                if attempt == self.MAX_RETRIES:
                    return {"ip": ip, "error": str(e)}
                time.sleep(self.DEFAULT_BACKOFF * attempt)
        return {"ip": ip, "error": "max_retries_exceeded"}
```

### 3.3 Fix C — `plugins/mass_assignment_plugin.py` (response diff thay vì heuristic)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mass Assignment Plugin — phát hiện bằng response diff.
So sánh response gốc (User A, không gửi privileged field) vs
response sau khi inject (User B, gửi is_admin/role=admin).
Nếu response khác biệt VÀ phản ánh escalation (chứa "admin", "role", "privilege"
TRONG JSON body hoặc phần khác biệt so với baseline) → vulnerable.
"""
import json
import logging
from difflib import SequenceMatcher
from typing import List, Dict, Optional
import requests
from core.base_plugin import BasePlugin

log = logging.getLogger("MassAssignment")

PRIVILEGE_KEYS = {"is_admin", "is_staff", "role", "privilege", "permissions", "scope", "admin", "user_type"}
PRIVILEGE_VALUES = {"admin", "administrator", "root", "superuser", "staff"}


def _extract_indicators(body: str) -> set:
    """Trích các cặp key:value nhạy cảm từ JSON response."""
    indicators = set()
    try:
        obj = json.loads(body)
        _walk(obj, indicators)
    except (ValueError, TypeError):
        # Không phải JSON — fallback keyword scan trong vùng khác biệt
        pass
    return indicators


def _walk(node, out: set) -> None:
    if isinstance(node, dict):
        for k, v in node.items():
            if k.lower() in PRIVILEGE_KEYS:
                out.add(f"{k}={v}")
            _walk(v, out)
    elif isinstance(node, list):
        for item in node:
            _walk(item, out)


class MassAssignmentPlugin(BasePlugin):

    # Response phải khác biệt ít nhất một lượng này (0.0–1.0) mới tính
    DIFF_THRESHOLD = 0.05

    def name(self) -> str:
        return "MassAssignment"

    def description(self) -> str:
        return "Detect Mass Assignment via response diff (baseline vs injected)."

    def check_installed(self) -> bool:
        return True

    def _baseline(self, url: str, method: str, headers: Optional[dict], timeout: int) -> Optional[str]:
        """Request gốc KHÔNG gửi privileged payload."""
        try:
            r = requests.request(method, url, headers=headers, timeout=timeout, verify=False)
            return r.text
        except requests.RequestException as e:
            log.debug(f"[MassAssignment] baseline {method} {url} failed: {e}")
            return None

    def _request(self, method: str, url: str, payload: dict, headers: Optional[dict], timeout: int):
        return requests.request(method, url, json=payload, headers=headers, timeout=timeout, verify=False)

    def _diff_score(self, a: str, b: str) -> float:
        if not a:
            return 1.0 if b else 0.0
        return SequenceMatcher(None, a, b).ratio()

    def run(self, urls: List[str], headers: dict = None, timeout: int = 15) -> List[Dict]:
        findings = []
        payload = {"is_admin": True, "role": "admin"}

        for url in urls:
            for method in ("POST", "PUT"):
                try:
                    baseline_text = self._baseline(url, method, headers, timeout)
                    resp = self._request(method, url, payload, headers, timeout)
                except requests.RequestException as e:
                    log.debug(f"[MassAssignment] {method} {url} failed: {e}")
                    continue

                if resp.status_code != 200:
                    continue

                # 1) Phải có khác biệt thật sự so với baseline
                diff_score = 1.0 - self._diff_score(baseline_text or "", resp.text)
                if diff_score < self.DIFF_THRESHOLD:
                    log.debug(f"[MassAssignment] {method} {url}: no meaningful diff (score={diff_score:.3f})")
                    continue

                # 2) Phần khác biệt phải chứa indicator escalation (key trong PRIVILEGE_KEYS
                #    hoặc value trong PRIVILEGE_VALUES) — KHÔNG phải match keyword tùy tiện
                base_indicators = _extract_indicators(baseline_text or "")
                resp_indicators = _extract_indicators(resp.text)
                new_indicators = resp_indicators - base_indicators
                escalation_hits = {
                    ind for ind in new_indicators
                    if any(k in PRIVILEGE_KEYS for k in ind.split("=", 1)[0].lower().split())
                       or any(v.lower() in PRIVILEGE_VALUES for v in ind.split("=", 1)[-1:])
                }

                if not escalation_hits:
                    log.debug(f"[MassAssignment] {method} {url}: diff={diff_score:.3f} nhưng không có escalation indicator")
                    continue

                findings.append({
                    "url": url,
                    "method": method,
                    "vulnerability": "Mass Assignment",
                    "payload": payload,
                    "diff_score": round(diff_score, 4),
                    "indicators": sorted(escalation_hits),
                    "severity": "high",
                })
                break  # đã tìm thấy ở POST thì bỏ qua PUT

        return findings
```

---

## 4. Acceptance Criteria (đo lường được)

### 4.1 AC-1: Class name không còn collision

- [ ] `python -c "from plugins.shodan_plugin import ShodanHostnamePlugin; print(ShodanHostnamePlugin.__name__)"` → in ra `ShodanHostnamePlugin` (không exception).
- [ ] `python -c "from plugins.shodan_internetdb_plugin import InternetDBPlugin; print(InternetDBPlugin.__name__)"` → in ra `InternetDBPlugin`.
- [ ] `grep -nE "^class.*BasePlugin" plugins/shodan_plugin.py plugins/shodan_internetdb_plugin.py` → chỉ ra 2 class với tên khác nhau, không còn `ShodanInternetDBPlugin` ở `shodan_plugin.py`.

### 4.2 AC-2: `ShodanHostnamePlugin` dùng đúng Shodan Host API

- [ ] Method `run()` gọi URL chứa `api.shodan.io/shodan/host/` (không phải `internetdb.shodan.io`).
- [ ] Có truyền `key=` query param từ `api_key`.
- [ ] Khi `api_key=""` → trả `{"error": "missing_api_key"}`, KHÔNG raise exception.
- [ ] Khi HTTP 401 → trả `{"error": "invalid_api_key"}`.
- [ ] Khi HTTP 429 → log warning + retry tối đa 3 lần với backoff 1.5s/3s/4.5s.

### 4.3 AC-3: `VirusTotalPlugin` xử lý rate-limit đúng

- [ ] Test đơn vị: mock 2 lần liên tiếp trả 429, lần thứ 3 trả 200 → assert kết quả là dict thành công, không phải `{}`.
- [ ] Test đơn vị: mock trả 204 với header `Retry-After: 30` → assert method `run()` sleep ≥ 30s trước khi retry (hoặc ≥ 16s cho default backoff).
- [ ] Test đơn vị: 4 lần liên tiếp trả 429 → assert kết quả cuối cùng chứa `error: "http_429_exhausted"` (KHÔNG silent return `{}`).
- [ ] Test đơn vị: `_rate_limit()` đảm bảo khoảng cách tối thiểu 16s giữa 2 call (assert bằng mock `time.sleep`).

### 4.4 AC-4: `MassAssignmentPlugin` dùng response diff, false-positive giảm

- [ ] Test đơn vị với URL mock trả `"Welcome to Admin Panel v1.0"` (chứa "admin" nhưng không phải escalation):
  - Baseline giống hệt response sau inject → assert `findings == []`.
- [ ] Test đơn vị với URL mock:
  - Baseline body = `{"user": "guest", "role": "user"}`
  - Injected body = `{"user": "guest", "role": "admin"}`
  - Assert có 1 finding với `indicators` chứa `"role=admin"`.
- [ ] Test đơn vị với URL mock trả JSON lỗi `"admin required"` không có field JSON escalation:
  - Assert `findings == []` (không còn flag heuristic cũ).
- [ ] `diff_score` phải ≥ `DIFF_THRESHOLD` (0.05) để xét tiếp — kiểm tra bằng test gần ngưỡng.

### 4.5 AC-5: Backward compatibility

- [ ] `python -c "from plugins.virustotal_plugin import VirusTotalPlugin; from plugins.mass_assignment_plugin import MassAssignmentPlugin; from plugins.shodan_plugin import ShodanHostnamePlugin"` → tất cả import thành công không exception.
- [ ] Plugin loader (nếu có) discover đúng 4 plugin (canonical) không bị overwrite.
- [ ] `unittest discover tests/` (nếu đã có test directory) → không có test cũ nào broken do đổi tên class.

### 4.6 AC-6: Code quality

- [ ] Không còn `import requests` đứng riêng lẻ mà không wrap trong `requests.Session()` (dùng session cho connection pooling).
- [ ] Tất cả `except` đều log cụ thể (không bare `except Exception` nuốt lỗi).
- [ ] Mỗi plugin có docstring mô tả endpoint + rate-limit tier.

---

## 5. Plan triển khai (thứ tự)

| Bước | Hành động | File | Rủi ro |
|---|---|---|---|
| 1 | Đổi tên class `ShodanInternetDBPlugin` → `ShodanHostnamePlugin`, viết lại `run()` gọi Host API với API key + retry/backoff | `shodan_plugin.py` | Thấp — class hiện không có consumer nào import trực tiếp (cần grep xác nhận trước khi merge) |
| 2 | Refactor `VirusTotalPlugin` thêm `Session`, `_rate_limit()`, retry 4 lần, xử lý 204 + 429 + `Retry-After` header | `virustotal_plugin.py` | Thấp — chỉ thêm behavior, signature `run()` giữ nguyên |
| 3 | Viết lại `MassAssignmentPlugin`: thêm baseline request, diff `SequenceMatcher`, indicator extractor, bỏ keyword `"admin" in resp.text` | `mass_assignment_plugin.py` | Trung bình — thay đổi logic phát hiện, cần test lại trên URL thật |
| 4 | Thêm unit test cho 3 plugin (mock `requests`) | `tests/test_plugins_*.py` | — |
| 5 | Chạy full test suite, đối chiếu AC-1 → AC-6 | — | — |

---

## 6. File liên quan (out-of-scope nhưng cần biết)

- `core/base_plugin.py` — base class cha, cần xác nhận signature `name()`, `description()`, `check_installed()`, `run()` để 3 plugin trên tuân thủ.
- `plugins/stealth_net_plugin.py` — `shodan_internetdb_plugin.py` import class này để làm HTTP client; không thay đổi trong plan này.
- Bất kỳ file nào đang `from plugins.shodan_plugin import ShodanInternetDBPlugin` (cần grep trước khi đổi tên — **KHÔNG làm trong plan này**, ghi nhận là blocker cần check ở bước 1).
