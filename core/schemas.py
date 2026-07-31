#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-1] INTER-MODULE SCHEMA CONTRACTS
=====================================
Pydantic v2 models defining the data contracts between M1→M2 and M2→M3.
Ensures that external tool output format changes are caught at pipeline
boundaries instead of causing silent downstream failures.

Usage:
    from core.schemas import M1Output, M2AttackPlan, validate_m1_output, validate_m2_output
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from core.output_normalizer import NormalizedFinding
from core.operational_contract import (
    normalize_asset_findings,
    normalize_cloud_findings,
    normalize_exposure_findings,
    normalize_infra_findings,
)


# ========================================================================
# M1 → M2 Contract: Recon Output (m1_recon.json)
# ========================================================================

class PortEntry(BaseModel):
    """Single port scan result from Nmap/Naabu/httpx."""
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(default="tcp")
    service: str = Field(default="")
    product: str = Field(default="")
    version: str = Field(default="")
    banner: str = Field(default="")
    status: str = Field(default="open")
    tech: list[str] = Field(default_factory=list)
    cpe: list[str] = Field(default_factory=list)
    nse_scripts: dict[str, Any] = Field(default_factory=dict)

    @field_validator("port", mode="before")
    @classmethod
    def coerce_port(cls, v):
        """Coerce string ports to int."""
        if isinstance(v, str):
            return int(v)
        return v


class CVECandidate(BaseModel):
    """CVE candidate from OSINT (Shodan/Nmap NSE/VT)."""
    cve: str
    port: int = Field(default=80, ge=0, le=65535)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = Field(default="")
    severity: str = Field(default="")
    matched_at: str = Field(default="")
    verified: bool = Field(default=False)


class NucleiFinding(BaseModel):
    """Single Nuclei scan finding."""
    template_id: str = Field(default="")
    cve_id: str = Field(default="")
    severity: str = Field(default="unknown")
    name: str = Field(default="")
    matched_at: str = Field(default="")
    port: int = Field(default=80, ge=0, le=65535)
    tags: list[str] = Field(default_factory=list)
    interaction: bool = Field(default=False)
    description: str = Field(default="")
    
    @field_validator("severity", mode="before")
    @classmethod
    def normalize_severity(cls, v):
        if isinstance(v, str):
            return v.lower()
        return str(v).lower() if v else "unknown"


class M1Asset(BaseModel):
    """Single target asset from Module 1 reconnaissance."""
    target: str = Field(description="Target URL or domain")
    ip: str = Field(default="")
    scan_mode: str = Field(default="sniper")
    ports: list[PortEntry] = Field(default_factory=list)
    open_ports: list[PortEntry] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    cve_candidates: list[CVECandidate] = Field(default_factory=list)
    nuclei_findings: list[NucleiFinding] = Field(default_factory=list)
    cloud_findings: dict[str, Any] = Field(default_factory=dict)
    os_detection: list[Any] = Field(default_factory=list)
    web_urls: list[str] = Field(default_factory=list)
    subdomains: list[str] = Field(default_factory=list)
    dns_records: dict[str, Any] = Field(default_factory=dict)
    historical_osint: list[Any] = Field(default_factory=list)
    vt_organization: str = Field(default="")
    vt_reputation: int = Field(default=0)
    
    # [V1.0-SYNC] New Discovery Fields
    js_secrets: list[dict] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    hidden_params: dict[str, list[str]] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    api_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    xss_findings: list[dict] = Field(default_factory=list)
    sqli_findings: list[dict] = Field(default_factory=list)
    ssrf_findings: list[dict] = Field(default_factory=list)
    cors_findings: list[dict] = Field(default_factory=list)
    cors_issues: list[dict] = Field(default_factory=list)
    graphql_findings: list[dict] = Field(default_factory=list)
    graphql: dict[str, Any] = Field(default_factory=dict)
    open_redirect_findings: list[dict] = Field(default_factory=list)
    crlf_findings: list[dict] = Field(default_factory=list)
    secrets: list[dict] = Field(default_factory=list)
    bypass_403: list[dict] = Field(default_factory=list)
    bola_findings: dict[str, Any] = Field(default_factory=dict)
    dast_findings: list[dict[str, Any]] = Field(default_factory=list)
    asset_findings: list[dict[str, Any]] = Field(default_factory=list)
    exposure_findings: list[dict[str, Any]] = Field(default_factory=list)
    infra_findings: list[dict[str, Any]] = Field(default_factory=list)
    cloud_inventory_findings: list[dict[str, Any]] = Field(default_factory=list)
    knowledge_profile: dict[str, Any] = Field(default_factory=dict)
    wstg_coverage: dict[str, Any] = Field(default_factory=dict)
    manual_handoff: list[dict[str, Any]] = Field(default_factory=list)
    strategy_profiles: dict[str, Any] = Field(default_factory=dict)
    wordlist_profile: dict[str, Any] = Field(default_factory=dict)
    attack_chains: list[dict[str, Any]] = Field(default_factory=list)
    verification_summary: dict[str, Any] = Field(default_factory=dict)
    summary: dict[str, Any] = Field(default_factory=dict)

    @field_validator("api_endpoints", mode="before")
    @classmethod
    def coerce_api_endpoints(cls, v):
        if not isinstance(v, list):
            return []
        normalized = []
        for entry in v:
            if isinstance(entry, str):
                normalized.append({"url": entry, "path": entry, "method": "GET", "status": None, "status_code": None, "source": "unknown"})
            elif isinstance(entry, dict):
                normalized.append(entry)
        return normalized

    @model_validator(mode="after")
    def sync_aliases(self):
        if self.ports and not self.open_ports:
            self.open_ports = list(self.ports)
        if self.open_ports and not self.ports:
            self.ports = list(self.open_ports)
        if self.cors_issues and not self.cors_findings:
            self.cors_findings = list(self.cors_issues)
        if self.cors_findings and not self.cors_issues:
            self.cors_issues = list(self.cors_findings)
        if self.graphql and not self.graphql_findings:
            self.graphql_findings = [item for key in ("introspection_enabled", "graphql_vulns") for item in self.graphql.get(key, []) if isinstance(item, dict)]
        if self.js_secrets and not self.secrets:
            self.secrets = list(self.js_secrets)
        normalized_endpoints = []
        for entry in self.api_endpoints:
            if isinstance(entry, str):
                entry = {"url": entry, "path": entry, "method": "GET", "status": None, "status_code": None, "source": "unknown"}
            if isinstance(entry, dict) and entry.get("url"):
                entry.setdefault("path", entry["url"])
                entry.setdefault("method", "GET")
                entry.setdefault("status", entry.get("status_code"))
                entry.setdefault("status_code", entry.get("status"))
                entry.setdefault("source", "unknown")
                normalized_endpoints.append(entry)
        self.api_endpoints = normalized_endpoints
        raw_asset = self.model_dump(exclude={
            "asset_findings",
            "exposure_findings",
            "infra_findings",
            "cloud_inventory_findings",
        })
        if not self.asset_findings:
            self.asset_findings = normalize_asset_findings(raw_asset)
        if not self.exposure_findings:
            self.exposure_findings = normalize_exposure_findings(raw_asset)
        if not self.infra_findings:
            self.infra_findings = normalize_infra_findings(raw_asset)
        if not self.cloud_inventory_findings:
            self.cloud_inventory_findings = normalize_cloud_findings(raw_asset)
        return self

    @field_validator("target", mode="before")
    @classmethod
    def validate_target_nonempty(cls, v):
        if not v or not isinstance(v, str) or not v.strip():
            raise ValueError("Target must be a non-empty string")
        return v.strip()


# M1 output is a list of assets
M1Output = list[M1Asset]


# ========================================================================
# M2 → M3 Contract: Attack Plan (m2_vuln.json)
# ========================================================================

class AttackPlanEntry(BaseModel):
    """Single entry in the M2 attack plan, consumed by M3."""
    target: str
    ip: str
    cve: str
    rport: int = Field(default=80, ge=0, le=65535)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    match_source: str = Field(default="unknown")
    severity: str = Field(default="")
    matched_at: str = Field(default="")
    tech_origin: str = Field(default="")
    msf_ready: bool = Field(default=False)
    suggested_modules: list[str] = Field(default_factory=list)
    verified: bool = Field(default=False)
    
    # EPSS/KEV enrichment (optional — added by Phase 2)
    epss_score: float = Field(default=0.0, ge=0.0, le=1.0)
    epss_percentile: float = Field(default=0.0, ge=0.0, le=1.0)
    is_kev: bool = Field(default=False)
    kev_due_date: str = Field(default="")
    cvss_score: float = Field(default=0.0, ge=0.0, le=10.0)
    cvss_vector: str = Field(default="")
    cvss_severity: str = Field(default="UNKNOWN")
    priority_score: float = Field(default=0.0, ge=0.0, le=1.0)
    version_mismatch: bool = Field(default=False)

    @field_validator("rport", mode="before")
    @classmethod
    def coerce_rport(cls, v):
        if isinstance(v, str):
            return int(v)
        return v


# M2 output is a list of attack plan entries
M2AttackPlan = list[AttackPlanEntry]


# ========================================================================
# Validation Helpers
# ========================================================================

class SchemaValidationError(Exception):
    """Raised when inter-module data fails schema validation."""
    def __init__(self, module: str, errors: list, raw_data_path: str = ""):
        self.module = module
        self.errors = errors
        self.raw_data_path = raw_data_path
        super().__init__(
            f"[SCHEMA] {module} output validation failed with {len(errors)} error(s). "
            f"Data path: {raw_data_path}"
        )


def validate_m1_output(json_path: str, strict: bool = False) -> tuple[list[dict], list[str]]:
    """
    Validate m1_recon.json against the M1 schema.
    
    Args:
        json_path: Path to m1_recon.json
        strict: If True, raise SchemaValidationError on any validation failure.
                If False, log warnings and return best-effort parsed data.
    
    Returns:
        (validated_data, warnings): Tuple of validated dicts and warning messages.
    """
    warnings = []
    
    if not os.path.exists(json_path):
        if strict:
            raise SchemaValidationError("M1", ["File not found"], json_path)
        return [], [f"M1 output file not found: {json_path}"]
    
    try:
        with open(json_path, 'r') as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as e:
        msg = f"M1 output is not valid JSON: {e}"
        if strict:
            raise SchemaValidationError("M1", [msg], json_path)
        return [], [msg]
    
    if not isinstance(raw_data, list):
        msg = f"M1 output must be a JSON array, got {type(raw_data).__name__}"
        if strict:
            raise SchemaValidationError("M1", [msg], json_path)
        # Try wrapping in list
        raw_data = [raw_data] if isinstance(raw_data, dict) else []
        warnings.append(msg + " — wrapped in array")
    
    validated = []
    for i, item in enumerate(raw_data):
        try:
            asset = M1Asset.model_validate(item)
            validated.append(asset.model_dump())
        except Exception as e:
            msg = f"M1 asset[{i}] validation error: {e}"
            warnings.append(msg)
            logging.warning(f"[SCHEMA] {msg}")
            if not strict:
                # Best-effort: include raw data with warning flag
                if isinstance(item, dict):
                    item["_schema_warning"] = str(e)
                    validated.append(item)
            else:
                raise SchemaValidationError("M1", [msg], json_path)
    
    if warnings:
        logging.warning(f"[SCHEMA] M1 validation: {len(warnings)} warning(s) for {json_path}")
    else:
        logging.info(f"[SCHEMA] M1 validation: {len(validated)} assets validated successfully")
    
    return validated, warnings


def validate_m2_output(json_path: str, strict: bool = False) -> tuple[list[dict], list[str]]:
    """
    Validate m2_vuln.json against the M2 attack plan schema.
    
    Args:
        json_path: Path to m2_vuln.json
        strict: If True, raise SchemaValidationError on any validation failure.
                If False, log warnings and return best-effort parsed data.
    
    Returns:
        (validated_data, warnings): Tuple of validated dicts and warning messages.
    """
    warnings = []
    
    if not os.path.exists(json_path):
        if strict:
            raise SchemaValidationError("M2", ["File not found"], json_path)
        return [], [f"M2 output file not found: {json_path}"]
    
    try:
        with open(json_path, 'r') as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as e:
        msg = f"M2 output is not valid JSON: {e}"
        if strict:
            raise SchemaValidationError("M2", [msg], json_path)
        return [], [msg]
    
    # M2 output can be either:
    #   - A list of attack plan entries (direct)
    #   - A dict with "attack_plan" key (wrapped by main.py)
    if isinstance(raw_data, dict):
        raw_data = raw_data.get("attack_plan", [])
        if not isinstance(raw_data, list):
            msg = f"M2 'attack_plan' field must be a list, got {type(raw_data).__name__}"
            if strict:
                raise SchemaValidationError("M2", [msg], json_path)
            return [], [msg]
    
    if not isinstance(raw_data, list):
        msg = f"M2 output must be a JSON array, got {type(raw_data).__name__}"
        if strict:
            raise SchemaValidationError("M2", [msg], json_path)
        return [], [msg]
    
    validated = []
    for i, item in enumerate(raw_data):
        try:
            entry = AttackPlanEntry.model_validate(item)
            validated.append(entry.model_dump())
        except Exception as e:
            msg = f"M2 entry[{i}] validation error: {e}"
            warnings.append(msg)
            logging.warning(f"[SCHEMA] {msg}")
            if not strict:
                if isinstance(item, dict):
                    item["_schema_warning"] = str(e)
                    validated.append(item)
            else:
                raise SchemaValidationError("M2", [msg], json_path)
    
    if warnings:
        logging.warning(f"[SCHEMA] M2 validation: {len(warnings)} warning(s) for {json_path}")
    else:
        logging.info(f"[SCHEMA] M2 validation: {len(validated)} entries validated successfully")
    
    return validated, warnings


def validate_and_write(data: list[dict], schema_type: str, output_path: str) -> None:
    """
    Validate data against schema and write to file.
    Used by M1 and M2 output writers to ensure schema compliance before persisting.
    
    Args:
        data: List of dicts to validate
        schema_type: "m1" or "m2"
        output_path: Path to write validated JSON
    """
    model_cls = M1Asset if schema_type == "m1" else AttackPlanEntry
    validated = []
    errors = []
    
    for i, item in enumerate(data):
        try:
            obj = model_cls.model_validate(item)
            validated.append(obj.model_dump())
        except Exception as e:
            errors.append(f"[{i}] {e}")
            # Best-effort: include raw
            validated.append(item)
    
    if errors:
        logging.warning(
            f"[SCHEMA] {schema_type.upper()} write validation: "
            f"{len(errors)} error(s) in {len(data)} entries"
        )
        for err in errors[:5]:  # Log first 5
            logging.warning(f"  → {err}")
    
    with open(output_path, 'w') as f:
        json.dump(validated, f, indent=4, default=str)
    
    logging.info(
        f"[SCHEMA] {schema_type.upper()} output written: {output_path} "
        f"({len(validated)} entries, {len(errors)} warnings)"
    )
