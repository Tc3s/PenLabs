"""
PenLabs V1.0 — Recon History Database (SQLite)
Theo dõi lịch sử endpoints, subdomains, params, JS hashes qua các lần quét.
Hỗ trợ compute_diff() cho Continuous Recon mode.
"""
import os
import json
import sqlite3
import hashlib
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    """Kết quả so sánh giữa 2 lần quét."""
    new_subdomains: List[str] = field(default_factory=list)
    new_endpoints: List[str] = field(default_factory=list)
    new_params: List[dict] = field(default_factory=list)
    changed_js: List[dict] = field(default_factory=list)
    removed_endpoints: List[str] = field(default_factory=list)
    
    @property
    def has_changes(self) -> bool:
        return bool(self.new_subdomains or self.new_endpoints or 
                    self.new_params or self.changed_js)

    @property
    def summary(self) -> str:
        parts = []
        if self.new_subdomains:
            parts.append(f"{len(self.new_subdomains)} new subdomains")
        if self.new_endpoints:
            parts.append(f"{len(self.new_endpoints)} new endpoints")
        if self.new_params:
            parts.append(f"{len(self.new_params)} new params")
        if self.changed_js:
            parts.append(f"{len(self.changed_js)} changed JS files")
        if self.removed_endpoints:
            parts.append(f"{len(self.removed_endpoints)} removed endpoints")
        return ", ".join(parts) if parts else "No changes"


class ReconDB:
    """SQLite-backed history for continuous differential reconnaissance."""

    SCHEMA_VERSION = 1

    def __init__(self, db_path: str = ""):
        if not db_path:
            db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output", "penlabs_history.db")
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        """Tạo schema nếu chưa tồn tại."""
        cursor = self.conn.cursor()

        # Bảng metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS schema_info (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Bảng scan sessions
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                total_endpoints INTEGER DEFAULT 0,
                total_findings INTEGER DEFAULT 0
            )
        """)

        # Bảng subdomains
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                UNIQUE(target, subdomain)
            )
        """)

        # Bảng endpoints
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT DEFAULT 'GET',
                status_code INTEGER,
                content_type TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                times_seen INTEGER DEFAULT 1,
                UNIQUE(target, url, method)
            )
        """)

        # Bảng parameters (hidden + normal)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS params (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                endpoint_url TEXT NOT NULL,
                param_name TEXT NOT NULL,
                param_type TEXT DEFAULT 'query',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_hidden INTEGER DEFAULT 0,
                UNIQUE(target, endpoint_url, param_name)
            )
        """)

        # Bảng JS file hashes (phát hiện thay đổi code)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS js_hashes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                js_url TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                content_length INTEGER,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(target, js_url, content_hash)
            )
        """)

        # Bảng findings (vuln tracking)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                session_id INTEGER,
                finding_type TEXT NOT NULL,
                url TEXT NOT NULL,
                severity TEXT DEFAULT 'INFO',
                details TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_verified INTEGER DEFAULT 0,
                UNIQUE(target, finding_type, url)
            )
        """)

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_target ON endpoints(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_subdomains_target ON subdomains(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_params_target ON params(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_js_hashes_target ON js_hashes(target)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target)")

        # Set schema version
        cursor.execute(
            "INSERT OR REPLACE INTO schema_info (key, value) VALUES ('version', ?)",
            (str(self.SCHEMA_VERSION),)
        )
        self.conn.commit()

    # ─── Session Management ───

    def start_session(self, target: str, mode: str) -> int:
        """Bắt đầu một scan session mới. Trả về session_id."""
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO scan_sessions (target, mode, started_at) VALUES (?, ?, ?)",
            (target, mode, datetime.now().isoformat())
        )
        self.conn.commit()
        return cursor.lastrowid

    def end_session(self, session_id: int, total_endpoints: int = 0, total_findings: int = 0):
        """Kết thúc scan session."""
        self.conn.execute(
            "UPDATE scan_sessions SET finished_at=?, total_endpoints=?, total_findings=? WHERE id=?",
            (datetime.now().isoformat(), total_endpoints, total_findings, session_id)
        )
        self.conn.commit()

    # ─── Subdomain Tracking ───

    def upsert_subdomains(self, target: str, subdomains: List[str]) -> List[str]:
        """Thêm subdomains mới. Trả về danh sách subdomains MỚI (chưa từng thấy)."""
        now = datetime.now().isoformat()
        new_subs = []
        cursor = self.conn.cursor()
        
        for sub in subdomains:
            sub = sub.strip().lower()
            if not sub:
                continue
            try:
                cursor.execute(
                    "INSERT INTO subdomains (target, subdomain, first_seen, last_seen) VALUES (?, ?, ?, ?)",
                    (target, sub, now, now)
                )
                new_subs.append(sub)
            except sqlite3.IntegrityError:
                # Đã tồn tại — update last_seen
                cursor.execute(
                    "UPDATE subdomains SET last_seen=?, status='active' WHERE target=? AND subdomain=?",
                    (now, target, sub)
                )
        self.conn.commit()
        return new_subs

    def get_subdomains(self, target: str) -> List[str]:
        """Lấy tất cả subdomains đã biết cho target."""
        rows = self.conn.execute(
            "SELECT subdomain FROM subdomains WHERE target=? AND status='active' ORDER BY first_seen",
            (target,)
        ).fetchall()
        return [r["subdomain"] for r in rows]

    # ─── Endpoint Tracking ───

    def upsert_endpoints(self, target: str, endpoints: List[dict]) -> List[str]:
        """
        Thêm endpoints mới. 
        Input: [{"url": "...", "method": "GET", "status": 200, "content_type": "..."}]
        Trả về danh sách URLs MỚI.
        """
        now = datetime.now().isoformat()
        new_eps = []
        cursor = self.conn.cursor()
        
        for ep in endpoints:
            url = ep if isinstance(ep, str) else ep.get("url", "")
            method = "GET" if isinstance(ep, str) else ep.get("method", "GET")
            status = None if isinstance(ep, str) else ep.get("status")
            ct = None if isinstance(ep, str) else ep.get("content_type")
            
            if not url:
                continue
            try:
                cursor.execute(
                    """INSERT INTO endpoints (target, url, method, status_code, content_type, first_seen, last_seen) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (target, url, method, status, ct, now, now)
                )
                new_eps.append(url)
            except sqlite3.IntegrityError:
                cursor.execute(
                    "UPDATE endpoints SET last_seen=?, times_seen=times_seen+1, status_code=COALESCE(?, status_code) WHERE target=? AND url=? AND method=?",
                    (now, status, target, url, method)
                )
        self.conn.commit()
        return new_eps

    def get_endpoints(self, target: str) -> List[dict]:
        """Lấy tất cả endpoints đã biết."""
        rows = self.conn.execute(
            "SELECT url, method, status_code, content_type, times_seen, first_seen, last_seen FROM endpoints WHERE target=? ORDER BY first_seen",
            (target,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ─── Parameter Tracking ───

    def upsert_params(self, target: str, endpoint_url: str, params: List[str], is_hidden: bool = False) -> List[str]:
        """Thêm params cho một endpoint. Trả về danh sách params MỚI."""
        now = datetime.now().isoformat()
        new_params = []
        cursor = self.conn.cursor()
        
        for param in params:
            param = param.strip()
            if not param:
                continue
            try:
                cursor.execute(
                    """INSERT INTO params (target, endpoint_url, param_name, first_seen, last_seen, is_hidden) 
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (target, endpoint_url, param, now, now, 1 if is_hidden else 0)
                )
                new_params.append(param)
            except sqlite3.IntegrityError:
                cursor.execute(
                    "UPDATE params SET last_seen=? WHERE target=? AND endpoint_url=? AND param_name=?",
                    (now, target, endpoint_url, param)
                )
        self.conn.commit()
        return new_params

    # ─── JS Hash Tracking ───

    def upsert_js_hash(self, target: str, js_url: str, content: bytes) -> Optional[dict]:
        """
        Cập nhật JS file hash. 
        Trả về dict nếu JS file ĐÃ THAY ĐỔI (hash khác), None nếu không đổi.
        """
        now = datetime.now().isoformat()
        content_hash = hashlib.sha256(content).hexdigest()
        cursor = self.conn.cursor()
        
        # Kiểm tra hash cũ nhất (latest)
        existing = cursor.execute(
            "SELECT content_hash FROM js_hashes WHERE target=? AND js_url=? ORDER BY last_seen DESC LIMIT 1",
            (target, js_url)
        ).fetchone()
        
        if existing and existing["content_hash"] == content_hash:
            # Không đổi — update last_seen
            cursor.execute(
                "UPDATE js_hashes SET last_seen=? WHERE target=? AND js_url=? AND content_hash=?",
                (now, target, js_url, content_hash)
            )
            self.conn.commit()
            return None
        
        # Hash mới — JS đã thay đổi
        try:
            cursor.execute(
                """INSERT INTO js_hashes (target, js_url, content_hash, content_length, first_seen, last_seen) 
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (target, js_url, content_hash, len(content), now, now)
            )
        except sqlite3.IntegrityError:
            cursor.execute(
                "UPDATE js_hashes SET last_seen=? WHERE target=? AND js_url=? AND content_hash=?",
                (now, target, js_url, content_hash)
            )
        
        self.conn.commit()
        old_hash = existing["content_hash"] if existing else None
        return {
            "js_url": js_url,
            "old_hash": old_hash,
            "new_hash": content_hash,
            "size": len(content),
        }

    # ─── Finding Tracking ───

    def upsert_finding(self, target: str, session_id: int, finding_type: str, 
                       url: str, severity: str = "INFO", details: str = "") -> bool:
        """Thêm finding. Trả về True nếu là finding MỚI."""
        now = datetime.now().isoformat()
        try:
            self.conn.execute(
                """INSERT INTO findings (target, session_id, finding_type, url, severity, details, first_seen, last_seen) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (target, session_id, finding_type, url, severity, details, now, now)
            )
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            self.conn.execute(
                "UPDATE findings SET last_seen=?, session_id=?, details=COALESCE(?, details) WHERE target=? AND finding_type=? AND url=?",
                (now, session_id, details, target, finding_type, url)
            )
            self.conn.commit()
            return False

    # ─── Differential Engine ───

    def compute_diff(self, target: str, current_subdomains: List[str], 
                     current_endpoints: List[str]) -> DiffResult:
        """
        So sánh dữ liệu hiện tại với lịch sử trong DB.
        Trả về DiffResult chứa danh sách thay đổi.
        """
        diff = DiffResult()
        
        # 1. Subdomain diff
        known_subs = set(self.get_subdomains(target))
        current_subs_set = set(s.strip().lower() for s in current_subdomains if s.strip())
        diff.new_subdomains = list(current_subs_set - known_subs)
        
        # 2. Endpoint diff
        known_eps = set(ep["url"] for ep in self.get_endpoints(target))
        current_eps_set = set(current_endpoints)
        diff.new_endpoints = list(current_eps_set - known_eps)
        diff.removed_endpoints = list(known_eps - current_eps_set)
        
        # 3. Persist new data
        if diff.new_subdomains:
            self.upsert_subdomains(target, list(current_subs_set))
        if diff.new_endpoints:
            self.upsert_endpoints(target, diff.new_endpoints)
        
        return diff

    # ─── Stats ───

    def get_stats(self, target: str) -> dict:
        """Lấy thống kê cho target."""
        cursor = self.conn.cursor()
        
        total_subs = cursor.execute(
            "SELECT COUNT(*) FROM subdomains WHERE target=?", (target,)
        ).fetchone()[0]
        
        total_eps = cursor.execute(
            "SELECT COUNT(*) FROM endpoints WHERE target=?", (target,)
        ).fetchone()[0]
        
        total_params = cursor.execute(
            "SELECT COUNT(*) FROM params WHERE target=?", (target,)
        ).fetchone()[0]
        
        total_findings = cursor.execute(
            "SELECT COUNT(*) FROM findings WHERE target=?", (target,)
        ).fetchone()[0]
        
        total_scans = cursor.execute(
            "SELECT COUNT(*) FROM scan_sessions WHERE target=?", (target,)
        ).fetchone()[0]
        
        last_scan = cursor.execute(
            "SELECT started_at FROM scan_sessions WHERE target=? ORDER BY started_at DESC LIMIT 1",
            (target,)
        ).fetchone()
        
        return {
            "target": target,
            "total_subdomains": total_subs,
            "total_endpoints": total_eps,
            "total_params": total_params,
            "total_findings": total_findings,
            "total_scans": total_scans,
            "last_scan": last_scan["started_at"] if last_scan else None,
        }

    def close(self):
        """Đóng kết nối DB."""
        if self.conn:
            self.conn.close()
