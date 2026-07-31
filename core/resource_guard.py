#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Resource Guard & Memory Pressure Monitor
===================================================
Monitors system RAM and CPU usage to prevent OOM kills
when running resource-heavy tasks like Playwright, Gowitness, or large Ffuf scans.
"""

from __future__ import annotations

import asyncio
import logging
import psutil

logger = logging.getLogger(__name__)


class ResourceGuard:
    """System resource pressure guard."""

    def __init__(self, max_memory_pct: float = 85.0, log=None):
        self.max_memory_pct = max_memory_pct
        self.log = log or logger

    def check_memory(self) -> tuple[bool, float]:
        """Check if memory usage is within acceptable limits."""
        mem = psutil.virtual_memory()
        return mem.percent < self.max_memory_pct, mem.percent

    async def acquire(self, task_name: str = "Heavy Task", timeout_seconds: int = 300) -> bool:
        """
        Wait until memory usage drops below threshold before starting task_name.
        Returns True if acquired, False if timed out.
        """
        mem = psutil.virtual_memory()
        if mem.percent < self.max_memory_pct:
            return True

        self.log.warning(
            f"[ResourceGuard] HIGH MEMORY PRESSURE ({mem.percent:.1f}% >= {self.max_memory_pct}%). "
            f"Throttling '{task_name}'..."
        )

        elapsed = 0
        poll_interval = 5
        while elapsed < timeout_seconds:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval
            mem = psutil.virtual_memory()
            if mem.percent < self.max_memory_pct:
                self.log.info(
                    f"[ResourceGuard] Memory recovered ({mem.percent:.1f}%). Proceeding with '{task_name}'."
                )
                return True

        self.log.error(
            f"[ResourceGuard] TIMEOUT waiting for memory recovery ({mem.percent:.1f}%). Skipping '{task_name}'."
        )
        return False
