#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Central wordlist registry for scanner modes and plugins."""

from __future__ import annotations

import os
from typing import Any


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORDLIST_DIR = os.path.join(PROJECT_ROOT, "wordlists")


GENERATED_SENSITIVE_PATHS = [
    ".env", ".env.backup", ".env.dev", ".env.staging", ".env.localhost",
    ".git/config", ".git/HEAD", ".aws/credentials", ".aws/config",
    ".ssh/id_rsa", ".ssh/id_ed25519", "robots.txt", "sitemap.xml",
    ".well-known/security.txt", "swagger.json", "swagger.yaml",
    "swagger-ui.html", "api-docs", "openapi.json", "graphql", "graphiql",
    "server-status", "server-info", "phpinfo.php", "info.php",
    "wp-login.php", "wp-admin", "administrator", "admin", "login",
    "backup.zip", "backup.tar.gz", "backup.sql", "database.sql", "db.sql",
    "docker-compose.yml", "docker-compose.yaml", ".dockerenv", "Dockerfile",
    "config.json", "config.yml", "config.php", "config.bak",
    ".DS_Store", "web.config", "elmah.axd", "trace.axd",
    "actuator", "actuator/health", "actuator/env", "actuator/configprops",
    "debug", "console", "_debug", "status", "health", "metrics",
]


GENERATED_CICD_PATHS = [
    ".github/workflows", ".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml",
    "azure-pipelines.yml", "bitbucket-pipelines.yml", ".travis.yml",
    "buildkite.yml", ".drone.yml", "deploy.yml", "deployment.yaml",
    "helm/values.yaml", "kustomization.yaml", "terraform.tfstate",
    ".terraform.lock.hcl", "ansible.cfg", "inventory.ini",
]


WORDLIST_CATALOG: dict[str, dict[str, Any]] = {
    "web_content_stealth": {
        "env": ["PENLABS_WEB_STEALTH_WORDLIST", "PENLABS_WEB_WORDLIST"],
        "paths": [
            os.path.join(WORDLIST_DIR, "sensitive_paths_2026.txt"),
            os.path.join(WORDLIST_DIR, "common.txt"),
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ],
        "generated": ("sensitive_paths.txt", GENERATED_SENSITIVE_PATHS),
    },
    "web_content": {
        "env": ["PENLABS_WEB_WORDLIST"],
        "paths": [
            os.path.join(WORDLIST_DIR, "common.txt"),
            os.path.join(WORDLIST_DIR, "sensitive_paths_2026.txt"),
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ],
        "generated": ("sensitive_paths.txt", GENERATED_SENSITIVE_PATHS),
    },
    "web_content_deep": {
        "env": ["PENLABS_WEB_DEEP_WORDLIST", "PENLABS_WEB_WORDLIST"],
        "paths": [
            os.path.join(WORDLIST_DIR, "raft-large-directories.txt"),
            "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
            os.path.join(WORDLIST_DIR, "common.txt"),
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
        ],
        "generated": ("sensitive_paths.txt", GENERATED_SENSITIVE_PATHS),
    },
    "sensitive_paths": {
        "env": ["PENLABS_SENSITIVE_PATHS_WORDLIST"],
        "paths": [
            os.path.join(WORDLIST_DIR, "sensitive_paths_2026.txt"),
            os.path.join(WORDLIST_DIR, "common.txt"),
        ],
        "generated": ("sensitive_paths.txt", GENERATED_SENSITIVE_PATHS),
    },
    "cicd_paths": {
        "env": ["PENLABS_CICD_WORDLIST"],
        "paths": [
            os.path.join(WORDLIST_DIR, "cicd_paths.txt"),
            os.path.join(WORDLIST_DIR, "sensitive_paths_2026.txt"),
        ],
        "generated": ("cicd_paths.txt", GENERATED_CICD_PATHS),
    },
    "api_routes": {
        "env": ["KITERUNNER_WORDLIST", "PENLABS_API_ROUTES_WORDLIST"],
        "paths": [os.path.join(WORDLIST_DIR, "routes-small.kite")],
        "generated": None,
    },
    "api_params": {
        "env": ["PENLABS_PARAM_WORDLIST"],
        "paths": [os.path.join(WORDLIST_DIR, "params.txt")],
        "generated": None,
    },
    "s3_buckets": {
        "env": ["PENLABS_S3_WORDLIST"],
        "paths": [os.path.join(WORDLIST_DIR, "s3_buckets.txt")],
        "generated": None,
    },
    "passwords": {
        "env": ["PENLABS_PASSWORD_WORDLIST"],
        "paths": [
            os.path.join(WORDLIST_DIR, "top-10000-passwords.txt"),
            os.path.join(WORDLIST_DIR, "pass.txt"),
            os.path.join(WORDLIST_DIR, "top-1000.txt"),
        ],
        "generated": None,
        "auto_enabled": False,
    },
}


MODE_PURPOSE_ALIASES = {
    ("web_content", "stealth"): "web_content_stealth",
    ("web_content", "sniper"): "web_content_stealth",
    ("web_content", "full-audit"): "web_content_deep",
    ("web_content", "infra-smash"): "web_content_deep",
}


def _usable_file(path: str) -> bool:
    try:
        return bool(path and os.path.isfile(path) and os.path.getsize(path) > 0)
    except OSError:
        return False


def _materialize_generated(filename: str, lines: list[str], out_dir: str | None) -> str:
    directory = out_dir or os.path.join(PROJECT_ROOT, "output", "generated_wordlists")
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, filename)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
        handle.write("\n")
    return path


def _catalog_key(purpose: str, mode: str = "") -> str:
    normalized_purpose = str(purpose or "web_content").strip().lower().replace("-", "_")
    normalized_mode = str(mode or "").strip().lower()
    return MODE_PURPOSE_ALIASES.get((normalized_purpose, normalized_mode), normalized_purpose)


def resolve_wordlist(
    purpose: str,
    *,
    mode: str = "",
    out_dir: str | None = None,
    explicit_path: str = "",
) -> dict[str, Any]:
    """Resolve the best wordlist for a purpose/mode pair."""
    key = _catalog_key(purpose, mode)
    catalog = WORDLIST_CATALOG.get(key, WORDLIST_CATALOG["web_content"])

    if explicit_path and _usable_file(explicit_path):
        return {
            "purpose": purpose,
            "resolved_purpose": key,
            "mode": mode,
            "path": explicit_path,
            "source": "explicit",
            "exists": _usable_file(explicit_path),
            "generated": False,
            "auto_enabled": bool(catalog.get("auto_enabled", True)),
        }

    for env_name in catalog.get("env", []):
        env_path = os.getenv(env_name, "").strip()
        if _usable_file(env_path):
            return {
                "purpose": purpose,
                "resolved_purpose": key,
                "mode": mode,
                "path": env_path,
                "source": f"env:{env_name}",
                "exists": True,
                "generated": False,
                "auto_enabled": bool(catalog.get("auto_enabled", True)),
            }

    for path in catalog.get("paths", []):
        if _usable_file(path):
            return {
                "purpose": purpose,
                "resolved_purpose": key,
                "mode": mode,
                "path": path,
                "source": "repo" if path.startswith(PROJECT_ROOT) else "system",
                "exists": True,
                "generated": False,
                "auto_enabled": bool(catalog.get("auto_enabled", True)),
            }

    generated = catalog.get("generated")
    if generated:
        filename, lines = generated
        path = _materialize_generated(filename, lines, out_dir)
        return {
            "purpose": purpose,
            "resolved_purpose": key,
            "mode": mode,
            "path": path,
            "source": "generated",
            "exists": True,
            "generated": True,
            "auto_enabled": bool(catalog.get("auto_enabled", True)),
        }

    return {
        "purpose": purpose,
        "resolved_purpose": key,
        "mode": mode,
        "path": "",
        "source": "missing",
        "exists": False,
        "generated": False,
        "auto_enabled": bool(catalog.get("auto_enabled", True)),
    }


def build_wordlist_profile(mode: str = "") -> dict[str, Any]:
    """Expose wordlist selections in scan output/report without running tools."""
    purposes = ["web_content", "sensitive_paths", "api_routes", "api_params", "s3_buckets", "passwords"]
    profile = {
        purpose: resolve_wordlist(purpose, mode=mode)
        for purpose in purposes
    }
    profile["mode"] = mode
    profile["wordlist_dir"] = WORDLIST_DIR
    return profile
