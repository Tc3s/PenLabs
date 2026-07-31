# PENLABS V1.0 — UPGRADE PLAN
## Mục tiêu: Nâng cao khả năng thực chiến (bỏ qua pháp lý ở giai đoạn này)

## UPDATE 2026-07-17 — Automation Contract Sync

Các phần sau đã được triển khai và đồng bộ với README:

- `core/endpoint_store.py`: feedback loop Katana/LinkFinder/Kiterunner/Arjun/web URLs -> endpoint store.
- `core/dast_contract.py` và `core/operational_contract.py`: contract chuẩn cho DAST và recon/cloud/infra.
- `core/auth_context.py`: User A/B, cookie, CSRF, auth profile và token refresh.
- `core/verification.py` + `core/verification_replay.py`: buckets `confirmed/suspected/manual_review/noise` và replay pass 2 có giới hạn.
- `core/plugin_strategy.py`: strategy cho Nuclei, SQLMap, Dalfox, WPScan, Nmap; router đã áp vào runtime.
- `core/correlation.py`: attack chain scoring.
- `core/cloud_infra_depth.py`: cloud/infra triage.
- `core/dry_run_snapshot.py`: snapshot ổn định cho regression/diff.
- `core/reporter.py`: report hiển thị verification buckets, evidence path và attack chain score.
- `tests/test_automation_contracts.py`: regression tests cho các contract trên.

Kết quả verification gần nhất: `PYTHONPATH=. pytest -q` -> 99 tests pass.

Mốc 70% automation được hiểu là coverage cho recon + initial DAST + triage/report/handoff. Business logic, exploit impact và workflow multi-step vẫn cần manual testing.

## PHASE 0 — CRITICAL FOUNDATION (Tuần 1-2)

### P0-1: Fix wordlist/data corrupt
**Hiện trạng đã verify** (qua execute_code):
- wordlists/top-1000.txt = 0 dòng (silent fail khi setup.sh wget)
- data/kev_cache/kev_catalog.json = 0 KB (main code sẽ crash khi json.load)
- wordlists/common.txt chứa unix dotfiles thay vì web content paths
- wordlists/pass.txt chỉ 5 dòng (admin/123456/password/root/tomcat) — không dùng được

**Files cần fix**:
1. setup.sh — thêm verify sau wget
2. core/notifier.py / main.py — wrap json.load() cho kev_catalog
3. Download lại common.txt đúng URL
4. Expand pass.txt hoặc đổi sang wordlist khác

**Acceptance criteria**:
- top-1000.txt có ≥100 dòng sau khi fix
- kev_catalog.json parse được, không crash
- common.txt chứa web paths (admin/, api/, .git/, etc.)
- setup.sh có validate function check size > 0

---

### P0-2: Plugin stubs cleanup
**Hiện trạng đã verify**:
- plugins/shodan_plugin.py (22 dòng) class tên ShodanInternetDBPlugin → trùng plugins/shodan_internetdb_plugin.py
- plugins/virustotal_plugin.py (25 dòng) thiếu error handling cho rate limit
- plugins/mass_assignment_plugin.py (57 dòng) heuristic chỉ check "admin" in resp.text → false positive cực cao

**Files cần fix**:
1. plugins/shodan_plugin.py → đổi tên class thành ShodanHostnamePlugin (dùng Shodan API key)
2. plugins/virustotal_plugin.py — thêm retry, rate limit handling, hash reputation
3. plugins/mass_assignment_plugin.py — so sánh response User A vs User B (BOLA-style)

**Acceptance criteria**:
- Không còn class name trùng giữa các plugin
- VT plugin handle 429 response đúng cách
- MassAssignment plugin có false positive rate < 20% trên test cases

---

### P0-3: Smart CPE filter implementation
**Hiện trạng đã verify**:
- Config.SMART_CPE_FILTER = True mặc định
- Code trong Module2_VulnAnalysis.py filter CVE theo CPE nhưng implementation đơn giản
- Không cross-validate Nmap CPE với httpx tech-detect
- Không filter CVE theo OS (Windows CVE apply cho Linux server)

**Files cần thêm/sửa**:
1. core/cpe_filter.py (mới) — SmartCPEFilter class
2. scripts/Module2_VulnAnalysis.py — dùng SmartCPEFilter thay vì logic cũ
3. tests/test_cpe_filter.py — unit test

**Acceptance criteria**:
- Cross-validate CPE từ 2 nguồn (Nmap + httpx)
- Version range matching (vd: Apache 2.4.49-2.4.50)
- OS-based filtering (Windows CVE chỉ apply cho Windows target)
- Reduce false positive ≥ 60% so với baseline

---

### P0-4: Test coverage 30%
**Hiện trạng đã verify**:
- `tests/test_integration.py` chỉ 55 dòng, 1 test function (`test_m1_m2_m3_contract`)
- `pytest.ini` chỉ có `asyncio_mode = auto`; chưa có `testpaths`, `addopts`, `--cov`, markers
- `tests/conftest.py` chưa tồn tại, thiếu fixtures chung cho tmp session/scope/proxy và reset singleton
- `requirements.txt` chưa có `pytest-cov`
- 48 plugin files nhưng plugins gần như chưa có coverage; chỉ nên smoke-test 6 plugin đại diện để tránh CI phụ thuộc external binaries

**Files cần thêm/sửa**:
1. `tests/conftest.py` — fixtures `tmp_session_dir`, `tmp_scope_file`, `tmp_proxy_file`, `reset_singletons`
2. `tests/test_scope_engine.py` — 7 tests cho fail-closed/permissive/CIDR/wildcard/check_or_exit/summary
3. `tests/test_checkpoint.py` — 6-8 tests cho load/create/corrupt JSON/atomic write/resume/fail/complete
4. `tests/test_circuit_breaker.py` — 7 tests cho CLOSED/OPEN/HALF-OPEN, force open/close, stats
5. `tests/test_url_dedup.py` — 6 tests cho query dedup/static asset filter/tracking param strip/invalid inputs
6. `tests/test_proxy_manager.py` — 6 tests cho proxy format normalize/round-robin/sticky/report_dead/singleton
7. `tests/test_rate_limiter.py` — 6 tests cho per-user token bucket + outbound singleton/set_rate
8. `tests/test_audit_log.py` — 6 tests cho SHA256 hash chain, tamper detection, export JSON, singleton warning
9. `tests/test_plugins.py` — 6 smoke tests cho 6 plugin đại diện (`subdomain`, `sqlmap_detect`, `dalfox`, `nuclei`, `report`, `payload`)
10. `pytest.ini` — thêm `testpaths`, naming rules, strict markers, `--cov=core --cov=utils --cov=plugins`, reports, `--cov-fail-under=25`
11. `requirements.txt` — thêm `pytest-cov>=4.1.0`

**Acceptance criteria**:
- ≥30 test functions (target plan: 50)
- `pytest -v` exit code 0
- `pytest --cov` báo `core/` ≥30%, `utils/` ≥30% bonus, `plugins/` ≥10%, total gate ≥25%
- `pytest.ini` có coverage reports: terminal missing, `htmlcov/`, `coverage.xml`
- `requirements.txt` có `pytest-cov>=4.1.0`
- Security-critical tests pass: checkpoint atomic write, audit hash-chain tamper detection, scope fail-closed, circuit breaker state transitions

---

## PHASE 1 — HIGH IMPACT (Tuần 3-6)

### P1-1: JA3 spoofing cho Go tools
**Hiện trạng đã verify**:
- curl_cffi impersonate='chrome120' chỉ áp dụng cho Python HTTP calls (stealth_net_plugin.py:228-230)
- Nmap, Katana, Nuclei (Go binaries) vẫn dùng native TLS fingerprint
- → WAF phân biệt được Go tools vs Chrome thật

**Approach**:
1. Wrap Go tools qua SOCKS5 proxy với utls-like library (hoặc viết wrapper)
2. Hoặc: dùng --proxies option của từng Go tool + custom proxy server với utls

**Files cần thêm/sửa**:
1. utils/tls_spoof_proxy.py (mới) — SOCKS5 proxy với utls
2. plugins/stealth_net_plugin.py — extend cho Go tools
3. config.py — thêm TLS_SPOOF_PROXY config

**Acceptance criteria**:
- WAF test (Cloudflare free) không phát hiện Go tools là bot
- curl_cffi fingerprint match với fingerprint của Go tools qua proxy

---

### P1-2: Cloud-native plugin chuyên biệt
**Hiện trạng đã verify**:
- cloud-native mode chỉ có Nuclei generic templates
- Không có S3Scanner, cloud_enum, kube-hunter, ScoutSuite
- Cloud-native mode rating 5/10 (yếu)

**Files cần thêm**:
1. plugins/s3_scanner_plugin.py — wrap S3Scanner
2. plugins/cloud_enum_plugin.py — wrap cloud_enum (multi-cloud)
3. plugins/kube_hunter_plugin.py — wrap kube-hunter
4. plugins/scout_suite_plugin.py — wrap ScoutSuite
5. setup.sh — install các tools
6. requirements.txt — thêm deps

**Status 2026-07-17**:
- Đã có S3Scanner, CloudEnum, KubeHunter wiring trong cloud-native route.
- Đã có `cloud_infra_depth` để gom high-value services, cloud counts, Nuclei high findings và triage items.
- ScoutSuite chưa được triển khai; cloud permission impact vẫn cần manual.

**Acceptance criteria còn lại**:
- 4 cloud plugins hoạt động đúng
- cloud-native mode rating tăng từ 5/10 lên 8/10
- Test trên AWS mock account phát hiện được bucket public

---

### P1-3: Output normalization
**Hiện trạng đã verify**:
- Mỗi tool (Nuclei, Nmap, Naabu, Dalfox, Corsy, Sqlmap) có output format riêng
- Main.py parse 10+ format khác nhau (xem scanner_router.py)
- Khi tool update version → format thay đổi → PenLabs crash

**Files cần thêm**:
1. core/output_normalizer.py (mới) — OutputNormalizer class
2. core/schemas.py — thêm NormalizedFinding schema
3. scripts/Module2_VulnAnalysis.py — dùng normalizer
4. tests/test_output_normalizer.py

**Status 2026-07-17**:
- Đã có `core/output_normalizer.py`, `core/dast_contract.py`, `core/operational_contract.py`, `core/endpoint_store.py`.
- Router/report/DB tiêu thụ contract chuẩn tốt hơn trước.
- DAST group bounty/web-vuln đã normalize rộng hơn: XSS, SQLi, SSRF, CORS, GraphQL, Blind XSS, Mass Assignment, 403 bypass, Cache Poisoning, Open Redirect, CRLF, Race, BOLA, WordPress.

**Acceptance criteria còn lại**:
- Mỗi tool output → Pydantic NormalizedFinding
- Schema stable khi tool update minor version
- Backward compat: format cũ vẫn parse được

---

### P1-4: Speed optimization
**Hiện trạng đã verify**:
- main.py:1051 RECURSIVE_MAX = 50 (hard cap)
- scanner_router.py có MAX_CONCURRENT_TASKS = 5
- Chưa cache Nuclei results per-host

**Files cần sửa**:
1. main.py — RECURSIVE_MAX tăng lên 200 cho full-audit mode
2. core/scanner_router.py — tăng concurrency, thêm Nuclei cache
3. core/db.py — thêm scan_cache table

**Status 2026-07-17**:
- Đã có scan cache cho Nuclei, target dedupe, endpoint dedupe và chunking ở nhiều route.
- Cần benchmark thực tế với 200 subdomains để xác nhận SLA <1 giờ.

**Acceptance criteria còn lại**:
- Scan 200 subdomains trong < 1 giờ (hiện tại 50 subs = 30 phút)
- Nuclei không scan lại host đã scan trong cùng session
- Cache hit rate ≥ 30%

---

### P1-5: MsfRpcPlugin stability
**Hiện trạng đã verify**:
- plugins/msfrpc_plugin.py = 677 dòng
- Có fallback cho pymetasploit3 bug (line 172-196)
- NHƯNG không có auto-reconnect khi MSF daemon restart

**Files cần sửa**:
1. plugins/msfrpc_plugin.py — thêm auto-reconnect, job queue
2. core/circuit_breaker.py — extend cho MSF operations
3. tests/test_msfrpc_stability.py

**Acceptance criteria**:
- Auto-reconnect khi msfrpcd restart (test với kill -9 msfrpcd)
- Queue exploit jobs khi MSF busy
- Không crash khi session timeout

---

## PHASE 2 — MEDIUM (Tuần 7-10)

### P2-1: BOLA Engine mở rộng
- Thêm GraphQL endpoint testing
- Thêm WebSocket testing
- Detect privilege escalation (User A → Admin endpoints)
- Auto-generate BOLA report với evidence

### P2-2: Rate limit intelligence
- Auto-detect X-RateLimit-Remaining, Retry-After headers
- Adaptive rate limit
- Per-endpoint rate limit

### P2-3: Nuclei template auto-update
- Auto-check template version mỗi scan
- Custom template path validation
- YAML syntax check

### P2-4: Diff Engine optimization
- Detect CHANGED findings
- Priority scoring
- Group related findings

### P2-5: Tách elephant files
- scanner_router.py 3205 dòng → 8 files
- Module3_Exploit.py 2840 dòng → 3 files

---

## VERIFICATION APPROACH

Mỗi phase hoàn thành:
1. Chạy pytest, đảm bảo pass
2. Dispatch subagent review code changes
3. Cross-check evidence: số dòng, test pass, behavior
4. Update progress trong todo list

## TIMELINE

| Tuần | Phase | Output |
|---|---|---|
| 1 | P0-1, P0-2 | Data integrity + Plugin quality |
| 2 | P0-3 | Smart CPE filter |
| 3-4 | P0-4 | Test coverage 30% |
| 5-6 | P1-1, P1-2 | JA3 spoofing + Cloud plugins |
| 7-8 | P1-3, P1-4 | Output normalization + Speed |
| 9-10 | P1-5, P2-* | MSF stability + Medium features |
