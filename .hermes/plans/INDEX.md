# PENLABS V1.0 UPGRADE — PLAN INDEX

## Tổng quan
**Mục tiêu**: Nâng cao khả năng thực chiến (bỏ qua pháp lý ở giai đoạn này)
**Tổng số plan**: 11 files, 167 KB
**Ngày tạo**: 2026-06-24
**Cập nhật đồng bộ**: 2026-07-17

## Trạng thái hiện tại sau triển khai 70% automation

Các hạng mục đã được đưa vào codebase và có regression tests:
- Endpoint feedback loop chuẩn hóa qua `core/endpoint_store.py`.
- DAST finding contract + operational contract cho recon/cloud/infra.
- Auth context User A/B, cookie, CSRF, token refresh profile qua `core/auth_context.py`.
- Verification buckets và replay pass 2 qua `core/verification.py` và `core/verification_replay.py`.
- Strategy profiles được áp vào Nuclei, SQLMap, Dalfox, WPScan, Nmap.
- Correlation/chaining engine có score qua `core/correlation.py`.
- Cloud/infra depth triage qua `core/cloud_infra_depth.py`.
- Report confirmed/suspected/manual_review/noise và dry-run snapshot.
- Regression suite hiện tại: `PYTHONPATH=. pytest -q` -> 99 tests pass tại thời điểm cập nhật.

## Plan tổng quan
- [Upgrade Plan](./upgrade_plan.md) — Tổng quan 14 phases + timeline
- [INDEX](./INDEX.md) — File này (navigation)

## Phase 0 — CRITICAL FOUNDATION (Tuần 1-2)

### P0-1: Fix wordlist/data corrupt [146 dòng]
- **File**: [P0-1_wordlist_data_fix.md](./P0-1_wordlist_data_fix.md)
- **Vấn đề**: top-1000.txt empty, kev_catalog.json empty, common.txt sai nội dung
- **Acceptance**: top-1000.txt ≥100 dòng, kev_catalog parse được, common.txt chứa web paths

### P0-2: Plugin stubs cleanup [474 dòng]
- **File**: [P0-2_plugin_cleanup.md](./P0-2_plugin_cleanup.md)
- **Vấn đề**: shodan_plugin duplicate với shodan_internetdb_plugin (cùng class name pattern), VT plugin thiếu retry, mass_assignment heuristic yếu
- **Acceptance**: Không class name trùng, VT handle 429, MassAssignment FP rate <20%

### P0-3: Smart CPE filter [864 dòng]
- **File**: [P0-3_smart_cpe.md](./P0-3_smart_cpe.md)
- **Vấn đề**: CPE filter rải rác trong Module2 (1292 dòng), hard-code keyword map 3 chỗ
- **Acceptance**: Tách thành cpe_filter + version_range + cpe_kb + cpe_ranker, FP giảm ≥60%

### P0-4: Test coverage 30% [433 dòng]
- **File**: [P0-4_tests.md](./P0-4_tests.md)
- **Vấn đề**: Chỉ 1 test integration (55 dòng), `pytest.ini` chỉ có `asyncio_mode`, chưa có `tests/conftest.py`, chưa có `pytest-cov`, plugins gần như không có coverage
- **Scope**: Tạo `tests/conftest.py` + 8 test files mới (`scope_engine`, `checkpoint`, `circuit_breaker`, `url_dedup`, `proxy_manager`, `rate_limiter`, `audit_log`, `plugins`), cập nhật `pytest.ini` và `requirements.txt`
- **Acceptance**: ≥30 test functions (target 50), `pytest -v` pass, coverage `core/` ≥30%, `utils/` ≥30% bonus, `plugins/` ≥10%, total gate `--cov-fail-under=25`

## Phase 1 — HIGH IMPACT (Tuần 3-6)

### P1-1: JA3 spoofing cho Go tools [595 dòng]
- **File**: [P1-1_ja3_spoof.md](./P1-1_ja3_spoof.md)
- **Vấn đề**: curl_cffi impersonate chỉ áp dụng cho Python, Go tools (Nmap/Nuclei/Katana) dùng native TLS
- **Approach**: A) SOCKS5 proxy với utls (recommended), B) Go wrapper binary, C) patch runtime
- **Acceptance**: WAF không phát hiện Go tools là bot

### P1-2: Cloud-native plugin chuyên biệt [370 dòng]
- **File**: [P1-2_cloud_plugins.md](./P1-2_cloud_plugins.md)
- **Vấn đề**: Cloud-native mode chỉ có Nuclei generic templates
- **Plugins mới**: S3Scanner, cloud_enum, kube-hunter, ScoutSuite
- **Status 2026-07-17**: Partially implemented. Đã có S3Scanner, CloudEnum, KubeHunter wiring và `cloud_infra_depth` triage; ScoutSuite vẫn chưa được triển khai.
- **Acceptance**: 4 cloud plugins hoạt động, mode rating 5→8

### P1-3: Output normalization [320 dòng]
- **File**: [P1-3_output_normalize.md](./P1-3_output_normalize.md)
- **Vấn đề**: Mỗi tool có output format riêng, scan_router parse 10+ format
- **Approach**: core/output_normalizer.py với NormalizedFinding Pydantic schema
- **Status 2026-07-17**: Implemented for current automation contract. Có `core/output_normalizer.py`, `core/dast_contract.py`, `core/operational_contract.py`, `endpoint_store`, verification buckets và report consumers.
- **Acceptance**: Schema stable khi tool update minor version

### P1-4: Speed optimization [192 dòng]
- **File**: [P1-4_speed.md](./P1-4_speed.md)
- **Vấn đề**: RECURSIVE_MAX=50, MAX_CONCURRENT=5, không có Nuclei cache
- **Fix**: Dynamic cap theo mode (full-audit=200), parallel scan, scan_cache table
- **Status 2026-07-17**: Partially implemented. Có Nuclei cache/dedupe/concurrency improvements và dry-run snapshot; recursive cap/timing cần benchmark thực tế.
- **Acceptance**: Scan 200 subs trong <1 giờ, cache hit rate ≥30%

### P1-5: MsfRpcPlugin stability [784 dòng]
- **File**: [P1-5_msfrpc_stability.md](./P1-5_msfrpc_stability.md)
- **Vấn đề**: connect(max_retries=1) one-shot, không có auto-reconnect, không có keepalive
- **Fix**: utils/rpc_connection.py (state machine), utils/job_queue.py (FIFO+persistent)
- **Acceptance**: Auto-reconnect khi msfrpcd restart, queue jobs khi MSF busy

## Phase 2 — MEDIUM (Tuần 7-10)
- P2-1: BOLA Engine mở rộng (GraphQL, WebSocket, privilege escalation)
- P2-2: Rate limit intelligence (auto-detect X-RateLimit headers)
- P2-3: Nuclei template auto-update + validate
- P2-4: Diff Engine optimization (changed findings, priority scoring)
- P2-5: Tách elephant files (scanner_router 3205 dòng, Module3 2840 dòng)

## Timeline tổng hợp

| Tuần | Phase | Status |
|---|---|---|
| 1 | P0-1, P0-2 | Plan ready |
| 2 | P0-3 | Plan ready |
| 3-4 | P0-4 | Plan ready — test coverage expansion (50 tests target) |
| 5-6 | P1-1, P1-2 | Plan ready |
| 7-8 | P1-3, P1-4 | P1-3 implemented; P1-4 partial |
| 9-10 | P1-5, P2-* | Plan ready |

## Verification approach

Mỗi phase:
1. Chạy pytest, đảm bảo pass
2. Dispatch subagent review code changes
3. Cross-check evidence: số dòng, test pass, behavior
4. Update progress trong todo list

## Subagent contribution

- **Subagent 1** (deleg_76b97902): 5 plans (P0-2, P0-3, P0-4, P1-1, P1-5) với evidence-based content
- **Subagent 2** (deleg_c669431c): P0-2 (đã merge với Subagent 1)
- **Subagent 3** (deleg_4aed8516): P0-3 (đã merge với Subagent 1)
- **Direct write** (parent): 6 plans (P0-1, P1-2, P1-3, P1-4, upgrade_plan, INDEX)
