# P1-4: Speed Optimization — DETAILED PLAN

## Hiện trạng đã verify

### Vấn đề
- main.py:1051 RECURSIVE_MAX = 50 (hard cap, quá thấp)
- scanner_router.py MAX_CONCURRENT_TASKS = 5
- Chưa cache Nuclei results per-host (scan lại host đã scan)
- Mỗi subdomain chạy M1+M2 tuần tự (không reuse kết quả)

### Evidence từ code
- main.py:1051: `RECURSIVE_MAX = 50  # Hard cap để tránh OOM / runaway`
- scanner_router.py:104: `MAX_CONCURRENT_TASKS = int(os.getenv("PENLABS_MAX_CONCURRENT", "5"))`
- main.py:1087: `live_subdomains = list(dict.fromkeys(live_subdomains))[:RECURSIVE_MAX]`
- Không có Nuclei cache table trong core/db.py

## Files cần sửa

### 1. main.py — RECURSIVE_MAX tăng lên 200 cho full-audit mode
**Path**: /home/tcus/Desktop/PenLabs/main.py
**Dòng 1051**: Thay đổi:
```python
# Trước:
RECURSIVE_MAX = 50  # Hard cap để tránh OOM / runaway

# Sau:
def _get_recursive_max(mode: str) -> int:
    """Dynamic cap theo mode — full-audit cho phép scan rộng hơn."""
    caps = {
        "stealth": 20,
        "sniper": 50,
        "web-vuln": 50,
        "cloud-devops": 30,
        "full-audit": 200,
        "api-bounty": 100,
        "api-breach": 100,
        "cloud-native": 50,
        "infra-smash": 30,
        "asset-discovery": 100,
    }
    return caps.get(mode, 50)

RECURSIVE_MAX = _get_recursive_max(mode)  # set trong main()
```

### 2. scanner_router.py — tăng concurrency
**Path**: /home/tcus/Desktop/PenLabs/core/scanner_router.py
**Dòng 104-105**:
```python
# Trước:
MAX_CONCURRENT_TASKS = int(os.getenv("PENLABS_MAX_CONCURRENT", "5"))
_heavy_task_semaphore = asyncio.Semaphore(int(os.getenv("PENLABS_MAX_HEAVY_TASKS", "2")))

# Sau: dynamic theo mode
@classmethod
def get_concurrency_for_mode(cls, mode: str) -> tuple:
    """Return (max_concurrent, max_heavy) based on mode."""
    config = {
        "stealth":      (2, 1),
        "sniper":       (5, 2),
        "web-vuln":     (8, 3),
        "cloud-devops": (5, 2),
        "full-audit":   (15, 5),  # Tăng mạnh
        "api-bounty":   (10, 4),
        "api-breach":   (10, 4),
        "cloud-native": (5, 2),
        "infra-smash":  (5, 2),
        "asset-discovery": (10, 4),
    }
    return config.get(mode, (5, 2))
```

### 3. core/db.py — thêm scan_cache table
**Path**: /home/tcus/Desktop/PenLabs/core/db.py
**Thêm vào sau Asset class**:

```python
class ScanCache(Base):
    """Cache kết quả scan per-host để tránh scan lại."""
    __tablename__ = "scan_cache"
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    host: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    tool: Mapped[str] = mapped_column(String(64), nullable=False)  # nuclei, nmap, dalfox
    cache_key: Mapped[str] = mapped_column(String(512), nullable=False)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    
    __table_args__ = (
        UniqueConstraint("project_id", "host", "tool", "cache_key", name="uq_scan_cache"),
        Index("idx_cache_expires", "expires_at"),
    )

def get_cached_result(session, project_id: int, host: str, tool: str, cache_key: str, ttl_hours: int = 24):
    """Get cached result nếu chưa expire."""
    from datetime import timedelta
    expiry = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    cache = session.query(ScanCache).filter_by(
        project_id=project_id, host=host, tool=tool, cache_key=cache_key
    ).filter(ScanCache.created_at > expiry).first()
    if cache:
        return json.loads(cache.result_json)
    return None

def save_to_cache(session, project_id: int, host: str, tool: str, cache_key: str, result: dict, ttl_hours: int = 24):
    """Save scan result to cache."""
    from datetime import timedelta
    expiry = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    cache = ScanCache(
        project_id=project_id, host=host, tool=tool,
        cache_key=cache_key, result_json=json.dumps(result, default=str),
        expires_at=expiry
    )
    session.merge(cache)
    session.flush()
```

### 4. scanner_router.py — dùng cache cho Nuclei
Trong `_route_*` methods, sau khi scan Nuclei:
```python
from core.db import get_cached_result, save_to_cache

def _get_nuclei_findings(self, target: str) -> list:
    """Get Nuclei findings với cache."""
    cache_key = f"nuclei:{','.join(sorted(self.tags))}:{self.severity_filter}"
    cached = get_cached_result(self.db_session, self.project_id, target, "nuclei", cache_key, ttl_hours=24)
    if cached:
        self.log.info(f"[Nuclei] Cache HIT for {target}")
        return cached
    
    # Run Nuclei
    findings = self._run_nuclei_actual(target)
    
    # Save to cache
    save_to_cache(self.db_session, self.project_id, target, "nuclei", cache_key, findings)
    return findings
```

### 5. main.py — parallel recursive scan
**Path**: /home/tcus/Desktop/PenLabs/main.py
**Dòng 1101**: Thay vòng for tuần tự:
```python
# Trước (line 1101):
for idx, sub_target in enumerate(live_subdomains, 1):
    # ... run M1+M2 sequential

# Sau: dùng asyncio + semaphore
import asyncio
from concurrent.futures import ThreadPoolExecutor

async def _scan_subdomain(self, sub_target: str) -> dict:
    """Async wrapper cho subprocess.run."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        self.executor, self._scan_subdomain_sync, sub_target
    )

async def _scan_all_subdomains(self, subdomains: list, max_concurrent: int = 10):
    """Parallel scan với semaphore limit."""
    sem = asyncio.Semaphore(max_concurrent)
    async def _limited_scan(sub):
        async with sem:
            return await self._scan_subdomain(sub)
    
    tasks = [_limited_scan(s) for s in subdomains]
    return await asyncio.gather(*tasks, return_exceptions=True)
```

### 6. config.py — thêm cache TTL config
```python
# === [P1-4] Scan Cache Configuration ===
NUCLEI_CACHE_TTL_HOURS = int(os.getenv("NUCLEI_CACHE_TTL_HOURS", "24"))
HTTPX_CACHE_TTL_HOURS = int(os.getenv("HTTPX_CACHE_TTL_HOURS", "12"))
NMAP_CACHE_TTL_HOURS = int(os.getenv("NMAP_CACHE_TTL_HOURS", "168"))  # 1 tuần
```

## Acceptance Criteria

1. **Scan 200 subdomains** trong < 1 giờ (hiện tại 50 subs = 30 phút)
2. **Nuclei không scan lại** host đã scan trong 24h (cache hit)
3. **Cache hit rate ≥ 30%** trong full-audit mode
4. **No regression**: existing sequential scan vẫn hoạt động
5. **Memory usage** không tăng quá 2x (kiểm tra qua psutil)

## Verification Steps

1. Benchmark scan 50 subs (old) vs 200 subs (new) — measure wall time
2. Run scan 2 lần liên tiếp, second run phải hit cache
3. pytest tests/test_scan_cache.py
4. Dispatch subagent review
