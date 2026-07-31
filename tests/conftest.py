"""Pytest-only compatibility stubs for optional external packages."""

from __future__ import annotations

import sys
import types


if "pymetasploit3.msfrpc" not in sys.modules:
    pkg = types.ModuleType("pymetasploit3")
    msfrpc = types.ModuleType("pymetasploit3.msfrpc")

    class MsfRpcClient:  # pragma: no cover - tests patch this symbol.
        def __init__(self, *args, **kwargs):
            raise RuntimeError("pymetasploit3 test stub should be patched")

    msfrpc.MsfRpcClient = MsfRpcClient
    pkg.msfrpc = msfrpc
    sys.modules.setdefault("pymetasploit3", pkg)
    sys.modules.setdefault("pymetasploit3.msfrpc", msfrpc)
