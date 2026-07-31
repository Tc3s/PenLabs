"""Kubernetes kube-hunter plugin wrapper."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from typing import Dict, List, Optional

from core.base_plugin import BasePlugin


class KubeHunterPlugin(BasePlugin):
    """Run kube-hunter in remote/internal mode and normalize JSON reports."""

    def name(self) -> str:
        return "KubeHunter"

    def description(self) -> str:
        return "Kubernetes cluster discovery and vulnerability hunting."

    def _executable(self) -> Optional[str]:
        import sys
        import os
        venv_bin = os.path.dirname(sys.executable)
        return shutil.which("kube-hunter") or shutil.which(os.path.join(venv_bin, "kube-hunter"))

    def check_installed(self) -> bool:
        return self._executable() is not None

    def run(self, target: Optional[str] = None, mode: str = "remote", timeout: int = 600):
        if mode not in {"remote", "internal"}:
            raise ValueError("mode must be 'remote' or 'internal'")
        if mode == "remote" and not target:
            raise ValueError("target required for remote mode")
        exe = self._executable()
        if not exe:
            return {"findings": [], "nodes": [], "summary": {}, "error": "kube-hunter not installed"}

        cmd = self._build_command(target=target, mode=mode)
        cmd[0] = exe
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            logging.warning("[KubeHunter] scan timeout")
            return {"findings": [], "nodes": [], "summary": {}, "error": "timeout"}
        except OSError as exc:
            logging.warning("[KubeHunter] failed: %s", exc)
            return {"findings": [], "nodes": [], "summary": {}, "error": str(exc)}

        output = proc.stdout or proc.stderr or ""
        parsed = self._parse_report(output)
        if proc.returncode not in (0, None) and not parsed.get("findings"):
            parsed["error"] = parsed.get("error") or f"kube-hunter exited {proc.returncode}"
        return parsed

    @staticmethod
    def _build_command(target: Optional[str] = None, mode: str = "remote") -> List[str]:
        cmd = ["kube-hunter"]
        if mode == "remote":
            cmd.extend(["--remote", target or ""])
        else:
            cmd.append("--internal")
        cmd.extend(["--report", "json", "--log", "level=ERROR"])
        return cmd

    def _parse_report(self, output: str) -> Dict:
        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return {"findings": [], "nodes": [], "summary": {}, "error": "parse_failed"}

        vulnerabilities = data.get("vulnerabilities") or data.get("findings") or []
        nodes = data.get("nodes") or []
        summary = self._summarize(vulnerabilities)
        return {"findings": vulnerabilities, "nodes": nodes, "summary": summary}

    @staticmethod
    def _summarize(vulnerabilities: List[Dict]) -> Dict[str, int]:
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "total": len(vulnerabilities)}
        for vuln in vulnerabilities:
            severity = str(vuln.get("severity") or vuln.get("level") or "info").lower()
            if severity not in summary:
                severity = "info"
            summary[severity] += 1
        return summary
