#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Base Route Handler
=============================
Abstract base class for all tactical scanner routes.
Proxies attribute lookups to the central ScannerRouter instance.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


class BaseRoute:
    """
    Base class for tactical route handlers.
    Delegates all helper method and configuration accesses to the ScannerRouter.
    """

    def __init__(self, router: Any):
        self.router = router

    def __getattr__(self, name: str) -> Any:
        """Forward attribute & method lookups to the router instance."""
        return getattr(self.router, name)

    async def execute(self, ip: str, target: str, index: int, osint_ports: list) -> dict:
        """Route entry point — to be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement execute()")
