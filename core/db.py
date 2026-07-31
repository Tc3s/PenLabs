#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — Relational Data Core (SQLAlchemy 2.0)
=====================================================
Stateful intelligence platform — inspired by reNgine's data correlation
and reconFTW's breadth of coverage.

Supports:
  - SQLite (default, zero-config CLI usage)
  - PostgreSQL (via --db-url for distributed / team deployments)

Usage:
    from core.db import get_session, init_db, Project, Asset, Vulnerability

    init_db()  # creates tables if not exist
    with get_session() as session:
        project = Project(name="HackerOne - Yahoo", slug="yahoo")
        session.add(project)
        session.commit()
"""

import os
import enum
import logging
from datetime import datetime, timezone
from typing import Optional, Any
from contextlib import contextmanager

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, Float, Boolean,
    DateTime, Enum, ForeignKey, JSON, Index, UniqueConstraint, event,
)
from sqlalchemy.orm import (
    DeclarativeBase, Mapped, mapped_column, relationship,
    sessionmaker, Session as SASession,
)

logger = logging.getLogger(__name__)


def _normalize_db_url(db_url: str = "") -> str:
    """Resolve empty db_url to the effective configured database URL."""
    return db_url or os.environ.get("PENLABS_DB_URL", _DEFAULT_DB_URL)


def _extract_endpoint_value(entry: Any) -> str:
    """Handle legacy string endpoints and canonical dict endpoints."""
    if isinstance(entry, dict):
        return str(entry.get("url", entry.get("path", ""))).strip()
    return str(entry).strip()


def _dast_contract_to_vuln(finding: dict[str, Any], scan_session_id: int | None) -> dict[str, Any] | None:
    category = str(finding.get("category", "")).lower()
    vuln_type_map = {
        "xss": "XSS",
        "sqli": "SQLi",
        "ssrf": "SSRF",
        "cors": "CORS-Misconfig",
        "graphql": "GraphQL-Exposure",
        "blind_xss": "Blind-XSS",
        "mass_assignment": "Mass-Assignment",
        "bypass_403": "Bypass-403",
        "cache_poisoning": "Cache-Poisoning",
        "open_redirect": "Open-Redirect",
        "crlf": "CRLF-Injection",
        "race_condition": "Race-Condition",
        "bola": "BOLA-IDOR",
        "wordpress": finding.get("finding_type", "WordPress-Vuln") or "WordPress-Vuln",
    }
    vuln_type = vuln_type_map.get(category)
    evidence_url = str(finding.get("matched_at") or finding.get("url") or "").strip()
    if not vuln_type or not evidence_url:
        return None
    return {
        "vuln_type": vuln_type,
        "evidence_url": evidence_url,
        "severity": str(finding.get("severity", "medium")).lower(),
        "title": finding.get("title", vuln_type),
        "description": finding.get("evidence", ""),
        "evidence_payload": finding.get("payload", ""),
        "reporter_tool": finding.get("tool", "DAST"),
        "reporter_source": "M1-DAST-Contract",
        "is_verified": True,
        "scan_session_id": scan_session_id,
    }


def _collect_dast_findings(recon_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings = recon_data.get("dast_findings", [])
    if findings:
        return [finding for finding in findings if isinstance(finding, dict)]

    from core.dast_contract import normalize_dast_findings

    collected: list[dict[str, Any]] = []
    for category, key in [
        ("xss", "xss_findings"),
        ("sqli", "sqli_findings"),
        ("ssrf", "ssrf_findings"),
        ("cors", "cors_findings"),
        ("graphql", "graphql_findings"),
        ("open_redirect", "open_redirect_findings"),
        ("crlf", "crlf_findings"),
        ("race_condition", "race_condition_findings"),
        ("bola", "bola_findings"),
        ("wordpress", "wpscan"),
        ("blind_xss", "blind_xss"),
        ("mass_assignment", "mass_assignment_findings"),
        ("bypass_403", "bypass_403"),
        ("cache_poisoning", "cache_poisoning"),
    ]:
        raw_output = recon_data.get(key)
        if raw_output:
            collected.extend(normalize_dast_findings(category, raw_output))

    return collected

# ═══════════════════════════════════════════════════════════════════
# ENUMS — Domain-specific value types
# ═══════════════════════════════════════════════════════════════════

class AssetType(str, enum.Enum):
    """Classification of discovered assets."""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ENDPOINT = "endpoint"
    JS_FILE = "js_file"
    S3_BUCKET = "s3_bucket"
    CLOUD_RESOURCE = "cloud_resource"


class ScanStatus(str, enum.Enum):
    """Lifecycle state of a scan session."""
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"          # checkpoint/resume
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"        # user cancelled


class Severity(str, enum.Enum):
    """CVSS-aligned severity bands."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnStatus(str, enum.Enum):
    """Triage lifecycle for a vulnerability."""
    NEW = "new"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    DUPLICATE = "duplicate"


class DiffEventType(str, enum.Enum):
    """Types of change events detected by the Diff Engine."""
    NEW_SUBDOMAIN = "new_subdomain"
    NEW_IP = "new_ip"
    NEW_ENDPOINT = "new_endpoint"
    NEW_PORT = "new_port"
    NEW_VULN = "new_vuln"
    NEW_JS = "new_js"
    TECH_CHANGED = "tech_changed"
    PORT_CLOSED = "port_closed"
    ASSET_REMOVED = "asset_removed"
    JS_CONTENT_CHANGED = "js_content_changed"


# ═══════════════════════════════════════════════════════════════════
# BASE
# ═══════════════════════════════════════════════════════════════════

class Base(DeclarativeBase):
    """SQLAlchemy 2.0 declarative base with common timestamp columns."""
    pass


def _utcnow():
    """Timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


# ═══════════════════════════════════════════════════════════════════
# MODEL: Project
# ═══════════════════════════════════════════════════════════════════

class Project(Base):
    """
    Top-level organizational unit — maps to a Bug Bounty program,
    a client engagement, or a CTF target.
    
    Inspired by reNgine's project-based organization where each
    project has its own dashboard, scope, and scan history.
    """
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, default="")

    # Scope definition — JSON arrays of domains/IPs/CIDRs
    in_scope: Mapped[Optional[dict]] = mapped_column(JSON, default=list)
    out_of_scope: Mapped[Optional[dict]] = mapped_column(JSON, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    scan_sessions = relationship("ScanSession", back_populates="project", cascade="all, delete-orphan")
    assets = relationship("Asset", back_populates="project", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="project", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Project(id={self.id}, slug='{self.slug}', name='{self.name}')>"


# ═══════════════════════════════════════════════════════════════════
# MODEL: ScanSession
# ═══════════════════════════════════════════════════════════════════

class ScanSession(Base):
    """
    One execution of the PenLabs pipeline.
    
    Tracks which profile was used, start/end time, status,
    and links to the CheckpointManager's JSON file for resume.
    """
    __tablename__ = "scan_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    
    # Session identity
    session_uid: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    target: Mapped[str] = mapped_column(String(512), nullable=False)
    
    # Execution context
    profile: Mapped[Optional[str]] = mapped_column(String(64), default="sniper")  # YAML profile or mode name
    status: Mapped[str] = mapped_column(
        Enum(ScanStatus, values_callable=lambda x: [e.value for e in x]),
        default=ScanStatus.QUEUED.value,
    )
    
    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), default=_utcnow)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Stats snapshot
    total_assets: Mapped[int] = mapped_column(Integer, default=0)
    total_vulns: Mapped[int] = mapped_column(Integer, default=0)
    
    # Filesystem link for checkpoint resume
    session_dir: Mapped[Optional[str]] = mapped_column(String(1024), default="")
    
    # Error info if failed
    error_message: Mapped[Optional[str]] = mapped_column(Text, default="")

    # Relationships
    project = relationship("Project", back_populates="scan_sessions")
    diffs = relationship("ScanDiff", back_populates="scan_session", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanSession(id={self.id}, uid='{self.session_uid}', status='{self.status}')>"


# ═══════════════════════════════════════════════════════════════════
# MODEL: Asset
# ═══════════════════════════════════════════════════════════════════

class Asset(Base):
    """
    A discovered asset — subdomain, IP, endpoint, JS file, S3 bucket, etc.
    
    Core of the reNgine-style data correlation engine:
    - Deduplication via UNIQUE(project_id, asset_type, value)
    - first_seen / last_seen for temporal tracking (Diff Engine)
    - Technologies and Ports as child relationships
    """
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False, index=True)

    # Identity
    asset_type: Mapped[str] = mapped_column(
        Enum(AssetType, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    value: Mapped[str] = mapped_column(String(2048), nullable=False)   # e.g., "api.target.com", "192.168.1.1"

    # HTTP metadata (for web assets)
    is_alive: Mapped[bool] = mapped_column(Boolean, default=False)
    http_status: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    http_title: Mapped[Optional[str]] = mapped_column(String(512), default="")
    content_type: Mapped[Optional[str]] = mapped_column(String(128), default="")
    content_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    
    # Web server fingerprint
    web_server: Mapped[Optional[str]] = mapped_column(String(256), default="")
    
    # JS hash tracking (for js_file type)
    content_hash: Mapped[Optional[str]] = mapped_column(String(64), default="")

    # Discovery metadata
    source_tool: Mapped[Optional[str]] = mapped_column(String(64), default="")   # e.g., "amass", "subfinder"
    resolved_ips: Mapped[Optional[dict]] = mapped_column(JSON, default=list)     # DNS resolved IPs
    
    # Temporal tracking for Diff Engine
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    project = relationship("Project", back_populates="assets")
    technologies = relationship("Technology", back_populates="asset", cascade="all, delete-orphan")
    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="asset", cascade="all, delete-orphan")

    # Deduplication constraint
    __table_args__ = (
        UniqueConstraint("project_id", "asset_type", "value", name="uq_asset_identity"),
        Index("idx_asset_alive", "project_id", "is_alive"),
        Index("idx_asset_type", "project_id", "asset_type"),
        Index("idx_asset_first_seen", "project_id", "first_seen"),
    )

    def __repr__(self):
        return f"<Asset(id={self.id}, type='{self.asset_type}', value='{self.value[:60]}')>"


# ═══════════════════════════════════════════════════════════════════
# MODEL: Technology
# ═══════════════════════════════════════════════════════════════════

class Technology(Base):
    """
    Technology / CPE detected on an asset.
    
    Maps to Wappalyzer/httpx tech detection results.
    Used by M2 Smart CPE Filter to match CVEs.
    """
    __tablename__ = "technologies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(256), nullable=False)        # e.g., "Apache httpd"
    version: Mapped[Optional[str]] = mapped_column(String(64), default="")  # e.g., "2.4.51"
    cpe: Mapped[Optional[str]] = mapped_column(String(512), default="")     # e.g., "cpe:2.3:a:apache:http_server:2.4.51"
    category: Mapped[Optional[str]] = mapped_column(String(128), default="")  # e.g., "web-server", "cms", "js-framework"

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    asset = relationship("Asset", back_populates="technologies")

    __table_args__ = (
        UniqueConstraint("asset_id", "name", "version", name="uq_tech_identity"),
    )

    def __repr__(self):
        return f"<Technology(id={self.id}, name='{self.name}', version='{self.version}')>"


# ═══════════════════════════════════════════════════════════════════
# MODEL: Port
# ═══════════════════════════════════════════════════════════════════

class Port(Base):
    """
    Open port on an IP/domain asset.
    
    Tracks service banners, protocol, and temporal changes.
    """
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id"), nullable=False, index=True)

    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), default="tcp")     # tcp / udp
    state: Mapped[str] = mapped_column(String(16), default="open")       # open / closed / filtered
    service_name: Mapped[Optional[str]] = mapped_column(String(128), default="")  # e.g., "http", "ssh"
    service_version: Mapped[Optional[str]] = mapped_column(String(256), default="")  # e.g., "OpenSSH 8.9p1"
    banner: Mapped[Optional[str]] = mapped_column(Text, default="")

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    asset = relationship("Asset", back_populates="ports")

    __table_args__ = (
        UniqueConstraint("asset_id", "port_number", "protocol", name="uq_port_identity"),
    )

    def __repr__(self):
        return f"<Port(id={self.id}, port={self.port_number}/{self.protocol}, service='{self.service_name}')>"


# ═══════════════════════════════════════════════════════════════════
# MODEL: Vulnerability
# ═══════════════════════════════════════════════════════════════════

class Vulnerability(Base):
    """
    Discovered vulnerability with full evidence chain.
    
    Links to both Project (global) and Asset (specific target).
    Supports triage workflow: New → Triaged → Confirmed → Resolved.
    """
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, ForeignKey("projects.id"), nullable=False, index=True)
    asset_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True, index=True)
    scan_session_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("scan_sessions.id"), nullable=True)

    # Classification
    vuln_type: Mapped[str] = mapped_column(String(128), nullable=False)    # e.g., "XSS", "SSRF", "BOLA"
    severity: Mapped[str] = mapped_column(
        Enum(Severity, values_callable=lambda x: [e.value for e in x]),
        default=Severity.INFO.value,
    )
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(32), default="")  # e.g., "CVE-2024-12345"
    cwe_id: Mapped[Optional[str]] = mapped_column(String(32), default="")  # e.g., "CWE-79"

    # Details
    title: Mapped[str] = mapped_column(String(512), default="")
    description: Mapped[Optional[str]] = mapped_column(Text, default="")
    
    # Evidence — PoC payload, HTTP request/response, screenshot path
    evidence_url: Mapped[Optional[str]] = mapped_column(String(2048), default="")
    evidence_request: Mapped[Optional[str]] = mapped_column(Text, default="")
    evidence_response: Mapped[Optional[str]] = mapped_column(Text, default="")
    evidence_payload: Mapped[Optional[str]] = mapped_column(Text, default="")
    evidence_screenshot: Mapped[Optional[str]] = mapped_column(String(1024), default="")
    curl_command: Mapped[Optional[str]] = mapped_column(Text, default="") # [V1.0-APEX]

    # Triage lifecycle
    status: Mapped[str] = mapped_column(
        Enum(VulnStatus, values_callable=lambda x: [e.value for e in x]),
        default=VulnStatus.NEW.value,
    )
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    # Reporter
    reporter_tool: Mapped[Optional[str]] = mapped_column(String(64), default="")  # e.g., "nuclei", "dalfox", "SmartXSS"
    reporter_source: Mapped[Optional[str]] = mapped_column(String(64), default="")  # "M1-Direct", "M2-CPE", "Plugin"

    # Temporal
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    project = relationship("Project", back_populates="vulnerabilities")
    asset = relationship("Asset", back_populates="vulnerabilities")

    __table_args__ = (
        UniqueConstraint("project_id", "vuln_type", "evidence_url", name="uq_vuln_identity"),
        Index("idx_vuln_severity", "project_id", "severity"),
        Index("idx_vuln_type", "project_id", "vuln_type"),
        Index("idx_vuln_status", "project_id", "status"),
    )

    def __repr__(self):
        return f"<Vulnerability(id={self.id}, type='{self.vuln_type}', severity='{self.severity}')>"


# ═══════════════════════════════════════════════════════════════════
# MODEL: ScanDiff — Discovery Engine Events
# ═══════════════════════════════════════════════════════════════════

class ScanDiff(Base):
    """
    Change event detected by the Diff Engine.
    
    Heart of the Continuous Recon system — tracks NEW or CHANGED assets
    for local reporting and regression review.
    """
    __tablename__ = "scan_diffs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_session_id: Mapped[int] = mapped_column(Integer, ForeignKey("scan_sessions.id"), nullable=False, index=True)

    event_type: Mapped[str] = mapped_column(
        Enum(DiffEventType, values_callable=lambda x: [e.value for e in x]),
        nullable=False,
    )
    
    # What changed
    target_asset_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("assets.id"), nullable=True)
    target_value: Mapped[str] = mapped_column(String(2048), default="")   # Human-readable: "api.target.com"
    
    # Detailed change info (JSON)
    details: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)
    
    # Alert tracking
    notified: Mapped[bool] = mapped_column(Boolean, default=False)      # Has alert been sent?
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    # Relationships
    scan_session = relationship("ScanSession", back_populates="diffs")

    __table_args__ = (
        Index("idx_diff_event_type", "scan_session_id", "event_type"),
    )

    def __repr__(self):
        return f"<ScanDiff(id={self.id}, event='{self.event_type}', target='{self.target_value[:40]}')>"


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
    import json
    from datetime import timedelta
    expiry = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    cache = session.query(ScanCache).filter_by(
        project_id=project_id, host=host, tool=tool, cache_key=cache_key
    ).filter(ScanCache.created_at > expiry).first()
    if cache:
        try:
            return json.loads(cache.result_json)
        except Exception:
            return None
    return None


def save_to_cache(session, project_id: int, host: str, tool: str, cache_key: str, result: Any, ttl_hours: int = 24):
    """Save scan result to cache."""
    import json
    from datetime import timedelta
    expiry = datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
    # Check if there is an existing cache entry to avoid duplicate key issues
    cache = session.query(ScanCache).filter_by(
        project_id=project_id, host=host, tool=tool, cache_key=cache_key
    ).first()
    if cache:
        cache.result_json = json.dumps(result, default=str)
        cache.expires_at = expiry
        cache.created_at = datetime.now(timezone.utc)
    else:
        cache = ScanCache(
            project_id=project_id, host=host, tool=tool,
            cache_key=cache_key, result_json=json.dumps(result, default=str),
            expires_at=expiry, created_at=datetime.now(timezone.utc)
        )
        session.add(cache)
    try:
        session.commit()
    except Exception as e:
        session.rollback()
        logging.warning(f"[ScanCache] Save failed: {e}")


# ═══════════════════════════════════════════════════════════════════
# ENGINE & SESSION FACTORY
# ═══════════════════════════════════════════════════════════════════

# Module-level state (lazy-init)
_engine = None
_SessionFactory = None
_ENGINE_CACHE: dict[str, Any] = {}
_SESSION_FACTORY_CACHE: dict[str, Any] = {}

# Default SQLite path (output/penlabs.db)
_DEFAULT_DB_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "output")
_DEFAULT_DB_PATH = os.path.join(_DEFAULT_DB_DIR, "penlabs.db")
_DEFAULT_DB_URL = f"sqlite:///{_DEFAULT_DB_PATH}"


def get_engine(db_url: str = ""):
    """
    Get or create the SQLAlchemy engine.
    
    Args:
        db_url: Database URL. Defaults to SQLite at output/penlabs.db.
                For PostgreSQL: "postgresql://user:pass@host:5432/penlabs"
    """
    global _engine
    url = _normalize_db_url(db_url)
    if url in _ENGINE_CACHE:
        _engine = _ENGINE_CACHE[url]
        return _engine
    
    # Ensure output directory exists for SQLite
    if url.startswith("sqlite:///"):
        db_dir = os.path.dirname(url.replace("sqlite:///", ""))
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

    connect_args = {}
    if url.startswith("sqlite"):
        # WAL mode for better concurrent read performance
        connect_args["check_same_thread"] = False

    engine = create_engine(
        url,
        echo=False,  # Set True for SQL debug logging
        pool_pre_ping=True,
        connect_args=connect_args,
    )

    # Enable WAL mode for SQLite (much better for concurrent reads)
    if url.startswith("sqlite"):
        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, _connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    _ENGINE_CACHE[url] = engine
    _engine = engine
    logger.info(f"[DB] Engine created: {url.split('@')[-1] if '@' in url else url}")
    return engine


def get_session_factory(db_url: str = ""):
    """Get or create the session factory."""
    global _SessionFactory
    url = _normalize_db_url(db_url)
    if url not in _SESSION_FACTORY_CACHE:
        engine = get_engine(url)
        _SESSION_FACTORY_CACHE[url] = sessionmaker(bind=engine, expire_on_commit=False)
    _SessionFactory = _SESSION_FACTORY_CACHE[url]
    return _SessionFactory


@contextmanager
def get_session(db_url: str = ""):
    """
    Context manager for database sessions.
    
    Usage:
        with get_session() as session:
            project = session.query(Project).filter_by(slug="yahoo").first()
    """
    factory = get_session_factory(db_url)
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(db_url: str = ""):
    """
    Create all tables if they don't exist.
    Safe to call multiple times (CREATE IF NOT EXISTS).
    """
    engine = get_engine(db_url)
    Base.metadata.create_all(engine)
    logger.info("[DB] All tables created/verified.")


def reset_db(db_url: str = ""):
    """
    ⚠️ DROP all tables and recreate. Use only in development/testing.
    """
    engine = get_engine(db_url)
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    logger.warning("[DB] All tables DROPPED and recreated.")


# ═══════════════════════════════════════════════════════════════════
# HELPER: Upsert Utilities for the Data Ingestion Pipeline
# ═══════════════════════════════════════════════════════════════════

def get_or_create_project(session: SASession, name: str, slug: str, **kwargs) -> Project:
    """Get an existing project by slug, or create a new one."""
    project = session.query(Project).filter_by(slug=slug).first()
    if project:
        return project
    project = Project(name=name, slug=slug, **kwargs)
    session.add(project)
    session.flush()  # Get the ID without committing
    logger.info(f"[DB] Created project: {slug}")
    return project


def upsert_asset(session: SASession, project_id: int, asset_type: AssetType,
                 value: str, **kwargs) -> tuple:
    """
    Insert or update an asset. Returns (asset, is_new).
    
    Deduplication key: (project_id, asset_type, value)
    """
    existing = session.query(Asset).filter_by(
        project_id=project_id,
        asset_type=asset_type.value if isinstance(asset_type, AssetType) else asset_type,
        value=value,
    ).first()

    if existing:
        # Update last_seen and any changed fields
        existing.last_seen = _utcnow()
        for k, v in kwargs.items():
            if hasattr(existing, k) and v is not None:
                setattr(existing, k, v)
        return existing, False

    asset = Asset(
        project_id=project_id,
        asset_type=asset_type.value if isinstance(asset_type, AssetType) else asset_type,
        value=value,
        **kwargs,
    )
    session.add(asset)
    session.flush()
    return asset, True


def upsert_vulnerability(session: SASession, project_id: int, vuln_type: str,
                         evidence_url: str, **kwargs) -> tuple:
    """
    Insert or update a vulnerability. Returns (vuln, is_new).
    
    Deduplication key: (project_id, vuln_type, evidence_url)
    """
    existing = session.query(Vulnerability).filter_by(
        project_id=project_id,
        vuln_type=vuln_type,
        evidence_url=evidence_url,
    ).first()

    if existing:
        existing.updated_at = _utcnow()
        for k, v in kwargs.items():
            if hasattr(existing, k) and v is not None:
                setattr(existing, k, v)
        return existing, False

    vuln = Vulnerability(
        project_id=project_id,
        vuln_type=vuln_type,
        evidence_url=evidence_url,
        **kwargs,
    )
    session.add(vuln)
    session.flush()
    return vuln, True


def bulk_upsert_assets(session: SASession, project_id: int, assets_data: list) -> int:
    """
    High-performance bulk upsert for assets using SQLite ON CONFLICT DO UPDATE.
    assets_data is a list of dicts.
    Returns the number of records processed.
    """
    if not assets_data:
        return 0
    from sqlalchemy.dialects.sqlite import insert

    values = []
    for asset in assets_data:
        a = asset.copy()
        a["project_id"] = project_id
        if "asset_type" in a and isinstance(a["asset_type"], AssetType):
            a["asset_type"] = a["asset_type"].value
        if "value" not in a:
            continue
        values.append(a)

    if not values:
        return 0

    stmt = insert(Asset).values(values)
    update_dict = {
        c.name: c
        for c in stmt.excluded
        if c.name not in ("id", "project_id", "asset_type", "value", "first_seen", "created_at")
    }
    update_dict["last_seen"] = _utcnow()

    stmt = stmt.on_conflict_do_update(
        index_elements=["project_id", "asset_type", "value"],
        set_=update_dict
    )
    session.execute(stmt)
    return len(values)


def bulk_upsert_vulnerabilities(session: SASession, project_id: int, vulns_data: list) -> int:
    """
    High-performance bulk upsert for vulnerabilities using SQLite ON CONFLICT DO UPDATE.
    vulns_data is a list of dicts.
    Returns the number of records processed.
    """
    if not vulns_data:
        return 0
    from sqlalchemy.dialects.sqlite import insert

    values = []
    for vuln in vulns_data:
        v = vuln.copy()
        v["project_id"] = project_id
        if "vuln_type" not in v or "evidence_url" not in v:
            continue
        values.append(v)

    if not values:
        return 0

    stmt = insert(Vulnerability).values(values)
    update_dict = {
        c.name: c
        for c in stmt.excluded
        if c.name not in ("id", "project_id", "vuln_type", "evidence_url", "created_at")
    }
    update_dict["updated_at"] = _utcnow()

    stmt = stmt.on_conflict_do_update(
        index_elements=["project_id", "vuln_type", "evidence_url"],
        set_=update_dict
    )
    session.execute(stmt)
    return len(values)



def persist_to_database(
    db_url: str = "",
    target: str = "",
    scan_mode: str = "sniper",
    recon_data: dict = None,
    vuln_data: list = None,
    scan_session_id: int = None,
) -> dict:
    recon_data = recon_data or {}
    vuln_data = vuln_data or []
    
    stats = {
        "assets_new": 0, "assets_updated": 0,
        "ports_new": 0, "vulns_new": 0, "vulns_updated": 0,
    }
    
    try:
        init_db(db_url)
    except Exception as e:
        logger.error(f"[DB] Failed to initialize database: {e}")
        return stats
    
    try:
        with get_session(db_url) as session:
            slug = target.replace(".", "-").replace(":", "-").lower()[:128]
            project = get_or_create_project(session, name=f"PenLabs — {target}", slug=slug)
            project_id = project.id
            
            # --- Bulk Upsert Assets ---
            assets_to_insert = [{
                "asset_type": AssetType.DOMAIN, "value": target,
                "is_alive": True, "source_tool": f"M1-Recon-{scan_mode}"
            }]
            
            ip = recon_data.get("ip", "")
            if ip:
                assets_to_insert.append({
                    "asset_type": AssetType.IP, "value": ip,
                    "is_alive": True, "source_tool": "DNS-Resolution", "resolved_ips": [ip]
                })
                
            for sub in recon_data.get("subdomains", []):
                sub_value = sub.get("sub", "") if isinstance(sub, dict) else str(sub)
                if sub_value and sub_value != target:
                    assets_to_insert.append({
                        "asset_type": AssetType.SUBDOMAIN, "value": sub_value,
                        "is_alive": True, "source_tool": "SubdomainHunter"
                    })
                    
            for url in recon_data.get("web_urls", [])[:500]:
                if str(url).strip():
                    assets_to_insert.append({
                        "asset_type": AssetType.ENDPOINT, "value": str(url).strip(),
                        "is_alive": True, "source_tool": "Katana"
                    })
                    
            for api_ep in recon_data.get("api_endpoints", [])[:200]:
                endpoint_value = _extract_endpoint_value(api_ep)
                if endpoint_value:
                    assets_to_insert.append({
                        "asset_type": AssetType.ENDPOINT, "value": endpoint_value,
                        "is_alive": True, "source_tool": "API-Discovery"
                    })
                    
            stats["assets_new"] = bulk_upsert_assets(session, project_id, assets_to_insert)
            
            target_asset = session.query(Asset).filter_by(project_id=project_id, asset_type=AssetType.DOMAIN.value, value=target).first()
            ip_asset = session.query(Asset).filter_by(project_id=project_id, asset_type=AssetType.IP.value, value=ip).first() if ip else None
            
            # --- Persist Ports ---
            if ip_asset:
                for port_info in recon_data.get("open_ports", []):
                    port_num = port_info.get("port", 0)
                    if not port_num: continue
                    existing_port = session.query(Port).filter_by(asset_id=ip_asset.id, port_number=port_num, protocol="tcp").first()
                    if existing_port:
                        existing_port.last_seen = _utcnow()
                        existing_port.state = "open"
                        existing_port.service_name = port_info.get("service", "")
                        existing_port.service_version = port_info.get("version", "")
                    else:
                        new_port = Port(asset_id=ip_asset.id, port_number=port_num, protocol="tcp", state="open", service_name=port_info.get("service", ""), service_version=port_info.get("version", ""))
                        session.add(new_port)
                        stats["ports_new"] += 1
            
            # --- Persist Technologies ---
            for tech_cpe in recon_data.get("tech_stack", []):
                tech_str = str(tech_cpe).strip()
                if not tech_str or not target_asset: continue
                existing_tech = session.query(Technology).filter_by(asset_id=target_asset.id, name=tech_str).first()
                if not existing_tech:
                    new_tech = Technology(asset_id=target_asset.id, name=tech_str, cpe=tech_str if tech_str.startswith("cpe:") else "")
                    session.add(new_tech)
            
            # --- Bulk Upsert Vulnerabilities ---
            vulns_to_insert = []
            effective_dast_findings = _collect_dast_findings(recon_data)
            
            for nf in recon_data.get("nuclei_findings", []):
                if not isinstance(nf, dict): continue
                vuln_type = nf.get("cve_id") or nf.get("template_id") or nf.get("template-id", "NUCLEI-FINDING")
                matched_at = nf.get("matched_at") or nf.get("matched-at", "")
                sev_lower = str(nf.get("severity") or nf.get("info", {}).get("severity", "info")).lower()
                if sev_lower not in ("critical", "high", "medium", "low", "info"): sev_lower = "info"
                vulns_to_insert.append({
                    "vuln_type": vuln_type, "evidence_url": matched_at, "severity": sev_lower,
                    "title": nf.get("name", vuln_type), "description": nf.get("description", ""),
                    "reporter_tool": "nuclei", "reporter_source": "M1-Direct", "is_verified": True, "scan_session_id": scan_session_id,
                    "curl_command": nf.get("curl_command", "") # [V1.0-APEX]
                })
                
            for cve in recon_data.get("cve_candidates", []):
                if not isinstance(cve, dict): continue
                if cve.get("confidence", 0.0) < 0.3: continue
                cve_id = cve.get("cve", "UNKNOWN")
                sev_lower = str(cve.get("severity", "info")).lower()
                if sev_lower not in ("critical", "high", "medium", "low", "info"): sev_lower = "info"
                vulns_to_insert.append({
                    "vuln_type": cve_id, "evidence_url": f"{target}:{cve.get('port', 'N/A')}", "severity": sev_lower,
                    "title": cve_id, "cve_id": cve_id if cve_id.startswith("CVE-") else "",
                    "reporter_tool": cve.get("source", "OSINT"), "reporter_source": "M1-CVE-Candidate", "is_verified": cve.get("verified", False), "scan_session_id": scan_session_id
                })
                
            for finding in effective_dast_findings:
                mapped = _dast_contract_to_vuln(finding, scan_session_id)
                if mapped:
                    vulns_to_insert.append(mapped)

            # --- [V1.0-SYNC] Persist New Discovery Fields as INFO Vulns ---
            for sec in recon_data.get("secrets", recon_data.get("js_secrets", [])):
                if not isinstance(sec, dict): continue
                vulns_to_insert.append({
                    "vuln_type": f"Secret: {sec.get('type', 'Unknown')}", 
                    "evidence_url": sec.get("source", target), "severity": "info",
                    "title": f"Sensitive Information Leak ({sec.get('type', 'API Key')})",
                    "description": f"Value: {sec.get('value', '...')[:50]}",
                    "reporter_tool": "LinkFinder/JS", "reporter_source": "M1-OSINT", "is_verified": True, "scan_session_id": scan_session_id
                })

            for email in recon_data.get("emails", []):
                vulns_to_insert.append({
                    "vuln_type": "Email-Leak", "evidence_url": target, "severity": "info",
                    "title": "Corporate Email Discovered", "description": f"Email: {email}",
                    "reporter_tool": "EmailFinder", "reporter_source": "M1-OSINT", "is_verified": True, "scan_session_id": scan_session_id
                })

            meta = recon_data.get("metadata", {})
            if meta and isinstance(meta, dict):
                for user in meta.get("users", []):
                    vulns_to_insert.append({
                        "vuln_type": "Identity-Metadata", "evidence_url": target, "severity": "info",
                        "title": "Internal Username from Metadata", "description": f"User: {user}",
                        "reporter_tool": "Metagoofil", "reporter_source": "M1-OSINT", "is_verified": True, "scan_session_id": scan_session_id
                    })
                
            for entry in vuln_data:
                if not isinstance(entry, dict): continue
                vuln_type = entry.get("vuln_type") or entry.get("cve") or "UNKNOWN"
                matched = entry.get("matched_at") or entry.get("target", "")
                sev_lower = str(entry.get("severity", "medium")).lower()
                if sev_lower not in ("critical", "high", "medium", "low", "info"): sev_lower = "medium"
                vulns_to_insert.append({
                    "vuln_type": vuln_type, "evidence_url": matched, "severity": sev_lower,
                    "title": entry.get("name", vuln_type), "description": entry.get("description", ""),
                    "reporter_tool": entry.get("match_source", "M2-VulnAnalysis"), "reporter_source": "M2-AttackPlan",
                    "is_verified": True if entry.get("confidence", 0.0) > 0.9 else entry.get("verified", False), 
                    "scan_session_id": scan_session_id,
                    "curl_command": entry.get("curl_command", ""), # [V1.0-APEX]
                })
                
            stats["vulns_new"] = bulk_upsert_vulnerabilities(session, project_id, vulns_to_insert)
            
            session.commit()
            
            logger.info(
                f"[DB] ✅ Successfully committed to penlabs.db: "
                f"{stats['assets_new']} assets bulk upserted, "
                f"{stats['ports_new']} new ports, "
                f"{stats['vulns_new']} vulns bulk upserted"
            )
            
    except Exception as e:
        logger.error(f"[DB] ❌ persist_to_database FAILED: {e}")
        import traceback
        logger.debug(traceback.format_exc())
    
    return stats
