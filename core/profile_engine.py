#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs V1.0 — Profile Engine (YAML Scan Orchestration)
=========================================================
Replaces hardcoded mode logic with declarative YAML profiles.

Each profile defines:
  - pipeline: ordered list of scan steps (tool, config, enabled)
  - rate_limit: per-profile rate limiting knobs
  - flags: behavioral toggles (stealth, WAF bypass, interactsh, etc.)
  - requirements: tool dependency matrix (critical/important/optional)

Usage:
    from core.profile_engine import ProfileEngine, ScanProfile

    engine = ProfileEngine()
    profile = engine.load("api-bounty")
    profile.dry_run()   # Preview pipeline without executing
    
    # Or load custom YAML
    profile = engine.load_file("/path/to/custom.yaml")
"""

import os
import copy
import shutil
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import yaml

logger = logging.getLogger(__name__)

# Default profiles directory (relative to project root)
_PROFILES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "profiles")

# ═══════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════

@dataclass
class PipelineStep:
    """A single step in the scan pipeline."""
    step: str              # e.g., "subdomain_enum", "port_scan", "vuln_scan"
    tool: str              # e.g., "subfinder", "nmap", "nuclei"
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self):
        status = "✅" if self.enabled else "⏭️ "
        return f"{status} {self.step}/{self.tool}"


@dataclass
class RateLimitConfig:
    """Rate limiting configuration extracted from profile."""
    nuclei_rate: int = 100
    nuclei_concurrency: int = 15
    nmap_timing: str = "T3"
    requests_per_second: int = 80
    delay_between_requests: str = "0"
    katana_max_urls: int = 15

    @classmethod
    def from_dict(cls, d: dict) -> "RateLimitConfig":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class ToolRequirements:
    """Tool dependency matrix."""
    critical: List[str] = field(default_factory=list)
    important: List[str] = field(default_factory=list)
    optional: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "ToolRequirements":
        return cls(
            critical=d.get("critical", []) or [],
            important=d.get("important", []) or [],
            optional=d.get("optional", []) or [],
        )


# ═══════════════════════════════════════════════════════════════
# SCAN PROFILE — Parsed representation of a YAML profile
# ═══════════════════════════════════════════════════════════════

class ScanProfile:
    """
    Parsed, validated scan profile ready for execution.
    
    Provides accessors for pipeline steps, rate limits, flags,
    and generates Config-compatible dicts for backward compatibility
    with existing mode-based logic.
    """

    def __init__(self, raw: dict):
        self._raw = raw
        meta = raw.get("profile", {})
        self.name: str = meta.get("name", "unknown")
        self.description: str = meta.get("description", "")
        self.version: str = meta.get("version", "7.0")

        # Parse pipeline steps
        self.pipeline: List[PipelineStep] = []
        for step_data in raw.get("pipeline", []):
            self.pipeline.append(PipelineStep(
                step=step_data.get("step", ""),
                tool=step_data.get("tool", ""),
                enabled=step_data.get("enabled", True),
                config=step_data.get("config", {}),
            ))

        # Parse rate limits
        self.rate_limit = RateLimitConfig.from_dict(raw.get("rate_limit", {}))

        # Parse flags
        self.flags: Dict[str, Any] = raw.get("flags", {})

        # Parse requirements
        self.requirements = ToolRequirements.from_dict(raw.get("requirements", {}))

    # ─── Pipeline Accessors ───────────────────────────────────

    @property
    def enabled_steps(self) -> List[PipelineStep]:
        """Return steps that are enabled."""
        return [s for s in self.pipeline if s.enabled]

    @property
    def disabled_steps(self) -> List[PipelineStep]:
        """Return steps that are disabled."""
        return [s for s in self.pipeline if not s.enabled]

    def get_steps_by_phase(self, step_name: str) -> List[PipelineStep]:
        """Get all enabled steps for a pipeline phase (e.g., 'subdomain_enum')."""
        return [s for s in self.enabled_steps if s.step == step_name]

    def get_step_by_tool(self, tool_name: str) -> Optional[PipelineStep]:
        """Get the step for a specific tool (e.g., 'nuclei')."""
        for s in self.pipeline:
            if s.tool == tool_name:
                return s
        return None

    def is_tool_enabled(self, tool_name: str) -> bool:
        """Check if a tool is enabled in this profile."""
        step = self.get_step_by_tool(tool_name)
        return step.enabled if step else False

    def get_tool_config(self, tool_name: str) -> dict:
        """Get config dict for a specific tool."""
        step = self.get_step_by_tool(tool_name)
        return step.config if step else {}

    # ─── Flag Accessors ───────────────────────────────────────

    def get_flag(self, flag_name: str, default=False) -> Any:
        """Get a behavioral flag value."""
        return self.flags.get(flag_name, default)

    @property
    def stealth_mode(self) -> bool:
        return self.get_flag("stealth_recon", False)

    @property
    def interactsh_enabled(self) -> bool:
        return self.get_flag("interactsh", False)

    @property
    def visual_recon(self) -> bool:
        return self.get_flag("visual_recon", False)

    @property
    def waf_bypass(self) -> bool:
        return self.get_flag("waf_bypass", False)

    @property
    def auto_exploit(self) -> bool:
        return self.get_flag("auto_exploit", False)

    # ─── V1.0: Unified Tactical Orchestration ─────────────────

    @property
    def tactical_mode(self) -> str:
        """Tactical mode from profile YAML (e.g., 'api-breach', 'asset-discovery').
        Falls back to the profile name if not specified."""
        return self._raw.get("profile", {}).get("tactical_mode") or self.name

    @property
    def origin_finder_enabled(self) -> bool:
        """Whether to run OriginDiscoveryEngine before Module 1."""
        return self.get_flag("origin_finder", False)

    @property
    def smart_cpe_filter(self) -> bool:
        return self.get_flag("smart_cpe_filter", True)

    # ─── Backward Compatibility ───────────────────────────────

    def to_rate_limit_dict(self) -> dict:
        """
        Generate a dict compatible with Config.RATE_LIMITS[mode].
        Allows existing code to work without refactoring.
        """
        return {
            "nuclei_rate": self.rate_limit.nuclei_rate,
            "nuclei_conc": self.rate_limit.nuclei_concurrency,
            "nmap_timing": self.rate_limit.nmap_timing,
        }

    def to_tool_matrix(self) -> dict:
        """
        Generate a dict compatible with preflight_check TOOL_MATRIX.
        """
        return {
            "critical": self.requirements.critical,
            "important": self.requirements.important,
            "optional": self.requirements.optional,
        }

    def to_katana_max(self) -> int:
        """Get Katana URL limit for this profile."""
        return self.rate_limit.katana_max_urls

    # ─── Dry Run ──────────────────────────────────────────────

    def dry_run(self) -> str:
        """
        Generate a human-readable preview of what this profile will do.
        No actual scanning — just show the plan.
        """
        lines = []
        lines.append(f"╔{'═'*62}╗")
        lines.append(f"║  🔍 DRY RUN — Profile: {self.name.upper():<36} ║")
        lines.append(f"║  {self.description[:58]:<58}  ║")
        lines.append(f"╠{'═'*62}╣")

        # Pipeline steps
        lines.append(f"║  📋 Pipeline ({len(self.enabled_steps)}/{len(self.pipeline)} steps enabled):")
        for i, step in enumerate(self.pipeline, 1):
            status = "✅" if step.enabled else "⏭️ "
            tool_name = f"{step.tool}"
            config_preview = ""
            if step.config:
                key_items = []
                for k, v in list(step.config.items())[:3]:
                    if isinstance(v, list):
                        key_items.append(f"{k}=[{len(v)} items]")
                    else:
                        key_items.append(f"{k}={v}")
                config_preview = f" ({', '.join(key_items)})"
            lines.append(f"║   {status} {i:2d}. [{step.step}] {tool_name}{config_preview}")

        # Rate limits
        lines.append(f"╠{'═'*62}╣")
        lines.append(f"║  ⚡ Rate Limits:")
        lines.append(f"║    Nuclei: {self.rate_limit.nuclei_rate} req/s, {self.rate_limit.nuclei_concurrency} concurrent")
        lines.append(f"║    Nmap timing: {self.rate_limit.nmap_timing}")
        lines.append(f"║    Katana max URLs: {self.rate_limit.katana_max_urls}")

        # Tactical Mode
        lines.append(f"╠{'═'*62}╣")
        lines.append(f"║  ⚔️  Tactical Mode: {self.tactical_mode.upper()}")
        lines.append(f"║  🔍 Origin Finder: {'ENABLED' if self.origin_finder_enabled else 'disabled'}")

        # Flags
        lines.append(f"╠{'═'*62}╣")
        lines.append(f"║  🚩 Flags:")
        flag_items = [
            f"stealth={self.stealth_mode}",
            f"waf_bypass={self.waf_bypass}",
            f"interactsh={self.interactsh_enabled}",
            f"visual={self.visual_recon}",
            f"cpe_filter={self.smart_cpe_filter}",
        ]
        lines.append(f"║    {', '.join(flag_items)}")

        # Tool requirements
        lines.append(f"╠{'═'*62}╣")
        lines.append(f"║  🔧 Requirements:")
        if self.requirements.critical:
            lines.append(f"║    CRITICAL: {', '.join(self.requirements.critical)}")
        if self.requirements.important:
            lines.append(f"║    IMPORTANT: {', '.join(self.requirements.important)}")
        if self.requirements.optional:
            lines.append(f"║    OPTIONAL: {', '.join(self.requirements.optional)}")

        # Tool availability check
        lines.append(f"╠{'═'*62}╣")
        lines.append(f"║  🩺 Tool Availability:")
        go_bin = os.path.expanduser("~/go/bin")
        all_tools = (self.requirements.critical +
                     self.requirements.important +
                     self.requirements.optional)
        for tool in all_tools:
            found = shutil.which(tool) is not None
            if not found:
                potential = os.path.join(go_bin, tool)
                found = os.path.isfile(potential) and os.access(potential, os.X_OK)
            if not found and tool == "kiterunner":
                kr_path = os.path.join(go_bin, "kr")
                found = shutil.which("kr") is not None or (os.path.isfile(kr_path) and os.access(kr_path, os.X_OK))
            status = "✅" if found else "❌"
            lines.append(f"║    {status} {tool}")

        lines.append(f"╚{'═'*62}╝")
        return "\n".join(lines)

    def __repr__(self):
        return f"<ScanProfile(name='{self.name}', steps={len(self.pipeline)}, enabled={len(self.enabled_steps)})>"


# ═══════════════════════════════════════════════════════════════
# PROFILE ENGINE — Loader, Validator, Merger
# ═══════════════════════════════════════════════════════════════

class ProfileEngine:
    """
    Central engine for loading, validating, and managing YAML profiles.
    
    Features:
      - Load built-in profiles by name (e.g., "stealth", "api-bounty")
      - Load custom profiles from arbitrary YAML files
      - Merge/override profiles for custom configurations
      - Validate profiles against schema
      - List available profiles
    """

    def __init__(self, profiles_dir: str = ""):
        self.profiles_dir = profiles_dir or _PROFILES_DIR
        self._cache: Dict[str, ScanProfile] = {}

    # ─── Profile Discovery ────────────────────────────────────

    def list_profiles(self) -> List[dict]:
        """
        List all available built-in profiles.
        
        Returns:
            List of {"name": ..., "description": ..., "path": ...}
        """
        profiles = []
        if not os.path.isdir(self.profiles_dir):
            return profiles

        for fname in sorted(os.listdir(self.profiles_dir)):
            if fname.endswith((".yaml", ".yml")):
                fpath = os.path.join(self.profiles_dir, fname)
                try:
                    with open(fpath, "r") as f:
                        raw = yaml.safe_load(f)
                    meta = raw.get("profile", {})
                    profiles.append({
                        "name": meta.get("name", fname.replace(".yaml", "")),
                        "description": meta.get("description", ""),
                        "path": fpath,
                        "steps": len(raw.get("pipeline", [])),
                    })
                except Exception as e:
                    logger.warning(f"[ProfileEngine] Failed to parse {fname}: {e}")
        return profiles

    # ─── Loading ──────────────────────────────────────────────

    def load(self, name: str) -> ScanProfile:
        """
        Load a built-in profile by name.
        
        Args:
            name: Profile name (e.g., "stealth", "api-bounty", "fast")
            
        Returns:
            ScanProfile instance
            
        Raises:
            FileNotFoundError if profile doesn't exist
        """
        if name in self._cache:
            return self._cache[name]

        # Search for the YAML file
        candidates = [
            os.path.join(self.profiles_dir, f"{name}.yaml"),
            os.path.join(self.profiles_dir, f"{name}.yml"),
        ]
        for path in candidates:
            if os.path.isfile(path):
                return self.load_file(path)

        # Fallback: try legacy mode name mapping
        legacy_map = {
            "sniper": "fast",
        }
        if name in legacy_map:
            return self.load(legacy_map[name])

        raise FileNotFoundError(
            f"Profile '{name}' not found in {self.profiles_dir}. "
            f"Available: {[p['name'] for p in self.list_profiles()]}"
        )

    def load_file(self, path: str) -> ScanProfile:
        """
        Load a profile from a specific YAML file path.
        
        Args:
            path: Absolute or relative path to the YAML file
            
        Returns:
            ScanProfile instance
        """
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Profile file not found: {path}")

        with open(path, "r") as f:
            raw = yaml.safe_load(f)

        if not raw or not isinstance(raw, dict):
            raise ValueError(f"Invalid YAML profile: {path}")

        # Validate structure
        self._validate(raw, path)

        profile = ScanProfile(raw)
        self._cache[profile.name] = profile
        logger.info(f"[ProfileEngine] Loaded profile: {profile.name} "
                     f"({len(profile.enabled_steps)}/{len(profile.pipeline)} steps)")
        return profile

    # ─── Merging (Profile Inheritance) ────────────────────────

    def merge(self, base_name: str, overrides: dict) -> ScanProfile:
        """
        Create a new profile by merging overrides into a base profile.
        
        Useful for CLI flag overrides:
            engine.merge("stealth", {"flags": {"interactsh": True}})
        
        Args:
            base_name: Name of the base profile
            overrides: Dict of values to override
            
        Returns:
            New ScanProfile with merged values
        """
        base = self.load(base_name)
        merged = copy.deepcopy(base._raw)

        # Deep merge
        for key, value in overrides.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key].update(value)
            elif key in merged and isinstance(merged[key], list) and isinstance(value, list):
                merged[key] = value  # Replace lists entirely
            else:
                merged[key] = value

        return ScanProfile(merged)

    # ─── Validation ───────────────────────────────────────────

    def _validate(self, raw: dict, path: str = ""):
        """
        Validate profile structure against expected schema.
        
        Raises ValueError with descriptive message on failure.
        """
        errors = []

        # Must have 'profile' section
        if "profile" not in raw:
            errors.append("Missing 'profile' section (name, description)")
        else:
            meta = raw["profile"]
            if "name" not in meta:
                errors.append("profile.name is required")

        # Must have 'pipeline' section
        if "pipeline" not in raw:
            errors.append("Missing 'pipeline' section (list of steps)")
        else:
            pipeline = raw["pipeline"]
            if not isinstance(pipeline, list):
                errors.append("pipeline must be a list of step objects")
            else:
                for i, step in enumerate(pipeline):
                    if not isinstance(step, dict):
                        errors.append(f"pipeline[{i}] must be a dict")
                        continue
                    if "step" not in step:
                        errors.append(f"pipeline[{i}] missing 'step' field")
                    if "tool" not in step:
                        errors.append(f"pipeline[{i}] missing 'tool' field")

        if errors:
            raise ValueError(
                f"Profile validation failed ({path}):\n" +
                "\n".join(f"  • {e}" for e in errors)
            )

    # ─── Compatibility Bridge ─────────────────────────────────

    def get_legacy_mode_config(self, name: str) -> dict:
        """
        Generate backward-compatible config dicts for existing code.
        
        Returns dict with keys matching Config.RATE_LIMITS, TOOL_MATRIX, etc.
        """
        try:
            profile = self.load(name)
        except FileNotFoundError:
            # If no YAML profile exists, return empty (use hardcoded defaults)
            return {}

        return {
            "rate_limit": profile.to_rate_limit_dict(),
            "tool_matrix": profile.to_tool_matrix(),
            "katana_max": profile.to_katana_max(),
            "flags": profile.flags,
        }
