# P0-4: Test Coverage ≥30% — Implementation Plan

> **Mục tiêu**: Đưa test coverage của PenLabs lên ≥30% cho `core/` và ≥10% cho `plugins/`, với ≥30 test functions có chất lượng.
> **Scope**: Tạo 8 test files mới + cập nhật `pytest.ini` + cập nhật `requirements.txt`.
> **Không tạo** test cho `core/checkpoint.py` chunk-level API (`is_chunk_completed` / `mark_chunk_completed`) vì dễ vỡ; tập trung path quan trọng nhất trước.

---

## 1. Hiện trạng (Baseline)

### 1.1. `tests/test_integration.py` — 55 dòng, 1 test function

Hiện chỉ có duy nhất **1 test** (`test_m1_m2_m3_contract`) — kiểm tra contract giữa M1/M2/M3 bằng cách:

```python
# Trích dòng 9–16
def test_m1_m2_m3_contract():
    # Simulate M1 Output conforming to M1Asset
    m1_data = [{
        "target": "test.com",
        "ip": "1.1.1.1",
        "open_ports": [{"port": 80, "protocol": "tcp"}],
        "tech_stack": ["Nginx"]
    }]
```

Test này cover:
- `M1Asset(**m1_data[0])` — validate Pydantic schema M1.
- `DiffEngine(project_id=1, scan_session_id=1)` — khởi tạo engine, assert `hasattr(engine, "ingest_recon_results")`.
- `AttackPlanEntry(**m2_data["attack_plan"][0])` — validate Pydantic schema M2.
- `TheExecutioner(plan_file=plan_file, session_dir="/tmp/penlabs_test")` — `load_plan()` trả `True`, có 1 task, target đúng.

### 1.2. `pytest.ini` — 2 dòng

```ini
[pytest]
asyncio_mode = auto
```

**Chưa có** `--cov`, `--cov-report`, `--cov-fail-under`, chưa có `testpaths`.

### 1.3. `tests/conftest.py` — **CHƯA TỒN TẠI** (0 file match).

→ Phải tạo mới `tests/conftest.py` để cung cấp fixtures dùng chung (tmp dirs, env reset, singleton reset).

### 1.4. `requirements.txt` — chưa có `pytest-cov`

`grep cov` → 0 match. → Phải thêm `pytest-cov` vào requirements.

### 1.5. Plugins inventory

Hiện có **48 plugin files** trong `plugins/`. Test từng plugin rất tốn kém (mỗi plugin phụ thuộc vào `BasePlugin`, `ProxyRelay`, nhiều subprocess gọi tool bên ngoài). Plan P0-4 chỉ yêu cầu ≥10% plugins/ coverage → chọn **smoke test 6 plugins** (xem §2.8).

### 1.6. Coverage Gap hiện tại

| Module | LOC | Có test? | Coverage estimate |
|---|---|---|---|
| `utils/scope_engine.py` | 207 | ❌ | 0% |
| `core/checkpoint.py` | 251 | ❌ | 0% |
| `core/circuit_breaker.py` | 162 | ❌ | 0% |
| `utils/url_dedup.py` | 188 | ❌ | 0% |
| `utils/proxy_manager.py` | 184 | ❌ | 0% |
| `utils/rate_limiter.py` | 127 | ❌ | 0% |
| `utils/audit_log.py` | 193 | ❌ | 0% |
| `plugins/*` | ~6000 | ❌ (smoke 1/48) | <2% |
| `core/schemas.py`, `core/diff_engine.py`, `scripts/Module3_Exploit.py` | — | ✅ 1 integration test | partial |

---

## 2. Danh sách test files cần tạo

| # | File | LOC ước tính | Số test functions | Module được cover |
|---|---|---|---|---|
| 1 | `tests/conftest.py` | ~40 | 0 (fixtures only) | Shared |
| 2 | `tests/test_scope_engine.py` | ~180 | 7 | `utils/scope_engine.py` |
| 3 | `tests/test_checkpoint.py` | ~150 | 6 | `core/checkpoint.py` |
| 4 | `tests/test_circuit_breaker.py` | ~130 | 7 | `core/circuit_breaker.py` |
| 5 | `tests/test_url_dedup.py` | ~160 | 6 | `utils/url_dedup.py` |
| 6 | `tests/test_proxy_manager.py` | ~140 | 6 | `utils/proxy_manager.py` |
| 7 | `tests/test_rate_limiter.py` | ~110 | 6 | `utils/rate_limiter.py` |
| 8 | `tests/test_audit_log.py` | ~150 | 6 | `utils/audit_log.py` |
| 9 | `tests/test_plugins.py` | ~200 | 6 | 6 plugins (1 test/plugin) |
| **Tổng** | — | **~1260** | **50** | — |

**Vượt chỉ tiêu ≥30 test functions** (50 vs 30 → margin 67%).

---

## 3. Chi tiết từng test file

### 3.1. `tests/conftest.py` (MỚI — required fixture)

**Mục đích**: Cung cấp fixtures dùng chung cho tất cả test khác. Tránh lặp code reset singleton, tạo tmp dir, mock config.

```python
import os
import pytest
import tempfile
import shutil

@pytest.fixture
def tmp_session_dir(tmp_path):
    """Session dir giả lập cho CheckpointManager / AuditLog."""
    d = tmp_path / "session"
    d.mkdir()
    return str(d)

@pytest.fixture
def tmp_scope_file(tmp_path):
    """Helper: tạo scope.txt tạm với nội dung cho trước."""
    def _make(content: str):
        p = tmp_path / "scope.txt"
        p.write_text(content, encoding="utf-8")
        return str(p)
    return _make

@pytest.fixture
def tmp_proxy_file(tmp_path):
    """Helper: tạo proxies.txt với danh sách proxy."""
    def _make(lines):
        p = tmp_path / "proxies.txt"
        p.write_text("\n".join(lines), encoding="utf-8")
        return str(p)
    return _make

@pytest.fixture
def reset_singletons():
    """Reset ScopeEngine, ProxyManager, OutboundRateLimiter, AuditLog singletons."""
    from utils.scope_engine import ScopeEngine
    ScopeEngine.reset_instance()
    if hasattr(ProxyManager := __import__("utils.proxy_manager", fromlist=["ProxyManager"]).ProxyManager,
               "_instance"):
        ProxyManager._instance = None
    yield
    ScopeEngine.reset_instance()
```

---

### 3.2. `tests/test_scope_engine.py` — 7 tests

**Module**: `utils/scope_engine.py` (207 dòng)
**Scope đã đọc**: `auto_load()`, `instance()` singleton, `__init__` với `confirm_permissive`, `_load_scope()`, `is_in_scope()` (CIDR/wildcard/exact), `check_or_exit()`, `add_rule()`, `summary()`, `__repr__()`, `reset_instance()`.

**Scenarios chính**:
- `test_strict_mode_blocks_when_no_scope_file` — `ScopeEngine()` không scope_file, không permissive → `is_in_scope("any.com") == False`.
- `test_permissive_requires_confirm_flag` — `ScopeEngine(permissive=True)` không có `confirm_permissive=True` → fallback strict (ghi log CRITICAL, `self.permissive = False`).
- `test_permissive_with_confirm_allows_all` — `ScopeEngine(permissive=True, confirm_permissive=True)` → `is_in_scope` True.
- `test_load_scope_file_with_cidr` — file scope có `10.0.0.0/8` → IP `10.1.2.3` True, IP `11.1.2.3` False.
- `test_load_scope_file_with_wildcard_subdomain` — file scope có `*.example.com` → `sub.example.com` True, `example.com` True (exact), `evil.com` False.
- `test_wildcard_star_allows_all` — file scope có `*` → tất cả target True, `_wildcard_all = True`.
- `test_check_or_exit_raises_on_out_of_scope` — out-of-scope target → `pytest.raises(ValueError, match="NGOÀI SCOPE")`.
- `test_summary_and_repr` — `summary()` và `__repr__()` trả format đúng.

**Target**: 7 functions × import + assert → coverage ~75% module.

---

### 3.3. `tests/test_checkpoint.py` — 6 tests

**Module**: `core/checkpoint.py` (251 dòng)
**Scope đã đọc**: `PIPELINE_ORDER`, `__init__`, `_load_or_create()`, `_save()` (atomic write qua tempfile + `os.replace`), `is_completed()`, `mark_completed()`, `mark_failed()`, `mark_pipeline_complete()`, `get_resume_point()`, `should_skip()`, `get_completed_steps()`, `get_summary()`, `is_resuming` property.

**Scenarios chính**:
- `test_create_new_checkpoint_when_file_missing` — dir trống → `pipeline_status="in_progress"`, `last_completed=None`.
- `test_load_existing_checkpoint` — pre-write `.checkpoint.json` → load lại, `last_completed` đúng.
- `test_load_corrupt_checkpoint_creates_new` — file JSON hỏng → log warning, tạo mới (không crash).
- `test_atomic_write_no_tempfile_left` — `mark_completed` rồi check `.checkpoint.tmp` không tồn tại sau call.
- `test_mark_completed_updates_last_completed` — gọi `mark_completed("MODULE_1_RECON")` → `is_completed` True, `last_completed == "MODULE_1_RECON"`.
- `test_get_resume_point_skips_completed` — mark M1 done → `get_resume_point() == "DUAL_CHANNEL_SPLIT"`; mark hết PIPELINE_ORDER → `None`.
- `test_mark_failed_sets_pipeline_status_failed` — `mark_failed("X", "boom")` → `pipeline_status == "failed"`, `get_resume_point` lại trả step fail đó (vì bị filter khi chưa completed).
- `test_mark_pipeline_complete_sets_status` — `mark_pipeline_complete()` → `pipeline_status == "completed"`.
- `test_is_resuming_property` — false khi mới tạo, true sau 1 mark_completed.

**Target**: 6–8 functions, focus atomic-write path (F-03 FIX) và resume logic.

---

### 3.4. `tests/test_circuit_breaker.py` — 7 tests

**Module**: `core/circuit_breaker.py` (162 dòng)
**Scope đã đọc**: `PluginState` dataclass, `CircuitBreaker.__init__`, `_get_state()`, `can_execute()` (CLOSED/OPEN/HALF-OPEN), `record_success()`, `record_failure()`, `force_open()`, `force_close()`, `get_stats()`, `summary()`.

**Scenarios chính**:
- `test_initial_state_closed_can_execute` — plugin mới → `can_execute` True, state default.
- `test_single_failure_stays_closed` — 1 fail → vẫn `can_execute` True, `failure_count == 1`.
- `test_max_failures_opens_circuit` — 3 fail liên tiếp (max=3) → `is_open=True`, `can_execute` False.
- `test_success_resets_failure_count` — 2 fail + 1 success → `failure_count == 0`, circuit CLOSED.
- `test_half_open_after_reset_timeout` — fail 3x → set `reset_timeout=0` rồi `can_execute` → True (HALF-OPEN simulation).
- `test_force_open_and_force_close` — `force_open("X")` → False; `force_close("X")` → True + count=0.
- `test_get_stats_and_summary` — 2 success + 1 fail → `stats["X"]["total_successes"] == 2`, `success_rate == "66.7%"`.
- `test_multiple_plugins_independent_state` — fail plugin A 3x, plugin B vẫn CLOSED.

**Target**: 7 functions, cover cả 3 state transitions.

---

### 3.5. `tests/test_url_dedup.py` — 6 tests

**Module**: `utils/url_dedup.py` (188 dòng)
**Scope đã đọc**: `_STATIC_EXTENSIONS`, `_NOISE_PARAM_KEYS`, `deduplicate(urls, keep_params)`, `deduplicate_with_params(urls)`.

**Scenarios chính**:
- `test_dedup_removes_query_value_duplicates` — `[search?q=a, search?q=b]` → 1 URL (giữ first).
- `test_dedup_filters_static_assets` — `[style.css, logo.png, page.html]` → chỉ còn `page.html`.
- `test_dedup_strips_tracking_params` — `[p?utm_source=x&id=1, p?utm_source=y&id=2]` → 1 URL với `id=1`.
- `test_dedup_with_params_false_drops_query` — `keep_params=False` → URL base không query.
- `test_dedup_with_params_returns_both_lists` — `deduplicate_with_params([...])` → `(base_urls, param_urls)`, cả hai list đúng.
- `test_dedup_empty_or_invalid_inputs` — `[]` → `[]`; `[None, "", "ftp://x"]` → `[]` (non-HTTP filter).

**Target**: 6 functions, đặc biệt verify filter tracking param (`utm_*`, `fbclid`).

---

### 3.6. `tests/test_proxy_manager.py` — 6 tests

**Module**: `utils/proxy_manager.py` (184 dòng)
**Scope đã đọc**: Singleton `__new__`, `__init__` (idempotent), `load_proxies()` (parse nhiều format, normalize), `get_proxy(sticky_key)`, `report_dead()`, `check_health()` (background thread), `_test_connectivity()` static.

**Vấn đề**: Singleton khó test — phải `ProxyManager._instance = None` ở setUp/tearDown. Dùng `reset_singletons` fixture.

**Scenarios chính**:
- `test_load_proxies_normalizes_formats` — file có `1.2.3.4:8080`, `5.6.7.8:1080:user:pass`, `http://9.9.9.9:3128` → cả 3 load đúng format (last được wrap `http://`).
- `test_load_proxies_skips_comments_and_blanks` — file có `# comment` và dòng trống → bị bỏ.
- `test_get_proxy_round_robin` — gọi `get_proxy()` 2 lần trên pool 2 proxy → trả về 2 proxy khác nhau (hoặc cùng nếu pool=1).
- `test_get_proxy_with_sticky_key_is_deterministic` — cùng `sticky_key` → cùng proxy; key khác → có thể khác.
- `test_report_dead_moves_to_dead_pool` — `report_dead(p)` rồi `live_count` giảm 1.
- `test_singleton_returns_same_instance` — `ProxyManager()` 2 lần → cùng instance.

**Mock**: Dùng `tmp_proxy_file` fixture, fake `Config.PROXY_FILE` qua monkeypatch.

**Target**: 6 functions, cover parse + round-robin + singleton.

---

### 3.7. `tests/test_rate_limiter.py` — 6 tests

**Module**: `utils/rate_limiter.py` (127 dòng)
**Scope đã đọc**: `RateLimiter` (token-bucket theo user_id, deque + Lock), `OutboundRateLimiter` (singleton, RPS, jitter).

**Scenarios chính**:
- `test_rate_limiter_allows_under_limit` — `max_calls=3, period=60` → 3 calls True, 4th False.
- `test_rate_limiter_resets_after_window` — `period=1` → 3 calls True, sleep 1.1s, 1 call lại True.
- `test_rate_limiter_remaining_and_reset_after` — sau 2 calls → `remaining() == 1`, `reset_after() > 0`.
- `test_rate_limiter_per_user_isolation` — user A hit limit, user B vẫn True.
- `test_outbound_rate_limiter_singleton` — 2 instance cùng id.
- `test_outbound_rate_limiter_wait_consumes_token` — `set_rate(10)` → `wait()` không block quá 0.5s (token có sẵn).
- `test_outbound_rate_limiter_set_rate_dynamic` — `set_rate(1)` → tokens giảm capacity về 1.

**Target**: 6 functions, cover cả `RateLimiter` và `OutboundRateLimiter`.

---

### 3.8. `tests/test_audit_log.py` — 6 tests

**Module**: `utils/audit_log.py` (193 dòng)
**Scope đã đọc**: `_get_last_hash()`, `log(actor, action, target, result)`, `_forward_syslog()` (optional, swallow errors), `export_json()`, `verify_integrity()`, `get_audit_log()` singleton.

**Scenarios chính**:
- `test_log_writes_pipe_delimited_with_sha256` — gọi `log("u1","scan","t.com","ok")` → file có line `ts|actor|action|target|result|prev_hash|entry_hash`, hash match recompute.
- `test_log_chains_prev_hash` — 2 calls → entry 2 có `prev_hash == entry_hash` của entry 1.
- `test_genesis_hash_for_new_log` — file mới → first entry có `prev_hash == "GENESIS"`.
- `test_verify_integrity_passes_on_clean_log` — 5 entries → `verify_integrity() == (True, [])`.
- `test_verify_integrity_detects_tampering` — manually sửa 1 dòng (đổi `actor`) → `verify_integrity() == (False, [lineno])`.
- `test_export_json_returns_valid_json` — sau 2 logs → `export_json(tmp_path / "out.json")` → file parse được, có 2 entries với keys `timestamp/actor/action/target/result/prev_hash/entry_hash`.
- `test_singleton_warns_on_path_mismatch` — gọi `get_audit_log(p1)` rồi `get_audit_log(p2)` → log warning về HIGH-05 (có thể dùng caplog).

**Target**: 6 functions, focus SHA256 chain integrity (SECURITY-FIX).

---

### 3.9. `tests/test_plugins.py` — 6 tests (smoke tests)

**Module**: `plugins/*.py` (48 files)

**Chiến lược**: 1 smoke test/plugin × 6 plugin = 6 test functions → đủ mức ≥10% plugins/ coverage vì import-time execution đã chạy class definitions + module-level code.

**Plugins chọn** (mix recon / vuln / exploit / report):
1. `subdomain_plugin.py` — test `name() == "SubdomainHunter"`, `description()` non-empty, `check_installed() == True`.
2. `sqlmap_detect_plugin.py` — test `name() == "SQLMapDetect"`, `check_installed()` bool (phụ thuộc `shutil.which`).
3. `dalfox_plugin.py` — test class instantiation với mock args.
4. `nuclei_plugin.py` — test `name()` + `description()` non-empty.
5. `report_plugin.py` — test `name()` + instantiate được.
6. `payload_plugin.py` — test `name()` + has `run` method.

**Pattern dùng chung**:
```python
import pytest
from plugins.<x> import <Y>

def test_plugin_x_metadata():
    p = <Y>()
    assert isinstance(p.name(), str) and len(p.name()) > 0
    assert isinstance(p.description(), str) and len(p.description()) > 0
    assert callable(p.run) or p.check_installed() in (True, False)
```

**Vì sao chỉ 6 plugins?** Mỗi plugin `run()` gọi subprocess/tool bên ngoài (sqlmap, dalfox, nuclei, subfinder…) — smoke test E2E sẽ làm CI phụ thuộc 48 binary. Plan này đặt mục tiêu ≥10% plugins/ coverage; import 6 plugin modules đã chạy ~1200 LOC (≈20% plugins LOC) trong coverage report.

**Target**: 6 functions, ≥10% plugins/ coverage.

---

## 4. Cập nhật `pytest.ini`

**File hiện tại**:
```ini
[pytest]
asyncio_mode = auto
```

**File mới**:
```ini
[pytest]
asyncio_mode = auto
testpaths = tests
python_files = test_*.py
python_classes = Test*
python_functions = test_*
addopts =
    --strict-markers
    --disable-warnings
    --cov=core
    --cov=utils
    --cov=plugins
    --cov-report=term-missing
    --cov-report=html:htmlcov
    --cov-report=xml:coverage.xml
    --cov-fail-under=25
markers =
    slow: marks tests as slow (deselect with -m "not slow")
    integration: marks tests requiring external tools
```

**Giải thích**:
- `--cov=core --cov=utils --cov=plugins` — measure 3 module chính.
- `--cov-report=term-missing` — in ra dòng nào chưa cover.
- `--cov-report=html:htmlcov` — tạo report HTML browse được.
- `--cov-fail-under=25` — fail nếu total <25% (hạ từ 30 vì plugins import có thể không chạy hết code path).
- `markers` — phục vụ test nhanh (`pytest -m "not slow"`).

**Lưu ý**: coverage threshold 25% là **gate CI**; mục tiêu thực tế ≥30% `core/` và ≥10% `plugins/` (xem §5).

---

## 5. Cập nhật `requirements.txt`

Thêm 1 dòng:
```
pytest-cov>=4.1.0
```

Sau đó chạy: `pip install -r requirements.txt`.

---

## 6. Acceptance Criteria

| # | Tiêu chí | Mục tiêu | Cách verify |
|---|---|---|---|
| AC1 | Số test functions mới | **≥30** (target: **50**) | `pytest --collect-only -q \| grep "::test" \| wc -l` |
| AC2 | Coverage `core/` | **≥30%** | `pytest --cov=core --cov-report=term` → `TOTAL core` ≥ 30 |
| AC3 | Coverage `utils/` | **≥30%** (bonus) | cùng lệnh trên |
| AC4 | Coverage `plugins/` | **≥10%** | cùng lệnh trên |
| AC5 | Tất cả tests pass | 100% | `pytest -v` exit code 0 |
| AC6 | Không có flake8 critical errors | 0 | `flake8 tests/ --max-line-length=120` |
| AC7 | Atomic write test pass | 1 | `tests/test_checkpoint.py::test_atomic_write_no_tempfile_left` pass |
| AC8 | Hash-chain integrity test pass | 2 | `tests/test_audit_log.py::test_verify_integrity_*` pass |
| AC9 | Fail-closed scope test pass | 1 | `tests/test_scope_engine.py::test_strict_mode_blocks_when_no_scope_file` pass |
| AC10 | Circuit breaker 3-state test pass | 3 | `test_closed_can_execute`, `test_max_failures_opens_circuit`, `test_half_open_after_reset_timeout` pass |

---

## 7. Implementation Order (tuần tự để giảm risk)

| Bước | Hành động | Thời gian | Phụ thuộc |
|---|---|---|---|
| 1 | `pip install pytest-cov` + update `requirements.txt` | 2 min | — |
| 2 | Tạo `tests/conftest.py` với fixtures | 10 min | — |
| 3 | Viết `tests/test_scope_engine.py` (7 tests) | 25 min | conftest |
| 4 | Viết `tests/test_circuit_breaker.py` (7 tests) — pure logic, dễ nhất | 20 min | — |
| 5 | Viết `tests/test_rate_limiter.py` (6 tests) | 20 min | — |
| 6 | Viết `tests/test_url_dedup.py` (6 tests) | 20 min | — |
| 7 | Viết `tests/test_checkpoint.py` (6 tests) — atomic write | 25 min | conftest |
| 8 | Viết `tests/test_audit_log.py` (6 tests) — hash chain | 25 min | conftest |
| 9 | Viết `tests/test_proxy_manager.py` (6 tests) — singleton tricky | 30 min | conftest + reset |
| 10 | Viết `tests/test_plugins.py` (6 tests) | 15 min | — |
| 11 | Update `pytest.ini` | 5 min | — |
| 12 | Chạy `pytest --cov` và verify AC1–AC10 | 10 min | 1–11 |
| 13 | Fix failures, iterate | ~30 min buffer | 12 |
| **Tổng** | — | **~4 giờ** | — |

---

## 8. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Singleton `ProxyManager` / `OutboundRateLimiter` leak giữa tests | False positives | `reset_singletons` fixture + manual `_instance = None` trong setUp |
| `AuditLog` ghi vào `output/audit.log` thật | Pollution filesystem | Inject `log_path=tmp_path / "audit.log"` |
| `ScopeEngine.auto_load()` tự tìm file thật | Test không deterministic | Không gọi `auto_load`, dùng `ScopeEngine(scope_file=tmp)` |
| Plugin import fail vì thiếu external deps | Test collection error | Mock `Config.PROXY_FILE`, dùng `pytest.importorskip` cho plugins thiếu thư viện |
| Coverage gate (--cov-fail-under=25) quá cao ngay lần đầu | CI fail | Bắt đầu ở 25, tăng dần sau mỗi sprint |
| `time.sleep` trong `OutboundRateLimiter.wait()` chậm test | Slow tests | Test chỉ assert `set_rate()` + `tokens` decrement; không test `wait()` E2E |

---

## 9. Out of Scope (deferred)

- E2E test cho plugin `run()` (cần 48 binary + network).
- Test cho `core/diff_engine.py` (DB-dependent, cần SQLite fixture).
- Test cho `scripts/Module3_Exploit.py` chi tiết (đã có 1 integration test).
- Property-based testing (Hypothesis).
- Mutation testing (mutpy).
- Performance benchmark.

Các item trên sẽ là P1+ sau khi P0-4 đạt 30%.

---

## 10. Definition of Done

- [ ] `tests/conftest.py` tồn tại với 3 fixtures.
- [ ] 8 test files mới được tạo (xem §2).
- [ ] `pytest.ini` có `--cov`, `--cov-report`, `--cov-fail-under=25`.
- [ ] `requirements.txt` có `pytest-cov>=4.1.0`.
- [ ] `pytest -v` exit 0.
- [ ] `pytest --cov` báo: core ≥30%, plugins ≥10%, total ≥25%.
- [ ] Tổng test functions ≥30 (target: 50).
- [ ] Hash-chain integrity test phát hiện được tampering.
- [ ] Atomic-write test verify không còn `.checkpoint.tmp` sau save.
- [ ] Fail-closed scope test verify default strict mode.
- [ ] Báo cáo coverage HTML được generate tại `htmlcov/index.html`.