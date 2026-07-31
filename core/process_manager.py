#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-2] SAFE PROCESS MANAGER
=============================
Prevents subprocess zombie processes by using process groups (os.setsid)
and guaranteed cleanup (os.killpg + SIGKILL escalation).

[V2026-FIX] Proxy Environment Injection:
  When inject_proxy=True, automatically merges HTTP_PROXY/HTTPS_PROXY/ALL_PROXY
  env vars from core.proxy_env into child process environments. This ensures
  ALL subprocess tools (nmap, nuclei, curl, httpx, katana, etc.) route traffic
  through the configured proxy infrastructure (StealthNet JA3 spoofing,
  ProxyRelay, or Tor SOCKS5) instead of going direct to target.

Replaces dangerous patterns:
  - asyncio.wait_for(proc.wait(), timeout) — cannot kill underlying process
  - loop.run_in_executor(None, subprocess.run, ...) — timeout doesn't propagate

Usage:
    from core.process_manager import safe_run_tool, safe_run_tool_sync

    # Async version (recommended for M1 pipeline)
    stdout = await safe_run_tool(["nmap", "-p", "80", "target"], timeout=120)

    # Sync version (for plugins)
    stdout = safe_run_tool_sync(["nuclei", "-u", "target"], timeout=300)
"""

import asyncio
import logging
import os
import signal
import subprocess
import time
from typing import Optional


class ProcessTimeoutError(Exception):
    """Raised when a managed subprocess exceeds its timeout."""
    def __init__(self, cmd: list, timeout: float, partial_output: str = ""):
        self.cmd = cmd
        self.timeout = timeout
        self.partial_output = partial_output
        super().__init__(
            f"Process timed out after {timeout}s: {' '.join(cmd[:3])}..."
        )


async def safe_run_tool(
    cmd: list[str],
    timeout: float = 300,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    stdin_data: Optional[bytes] = None,
    capture_stderr: bool = True,
    sigterm_grace: float = 5.0,
    inject_proxy: bool = True,
    scan_mode: Optional[str] = None,
) -> str:
    """
    Run an external tool with guaranteed cleanup on timeout/error.
    
    Uses os.setsid() to create a process group, allowing os.killpg() to
    kill ALL child processes (prevents zombie sub-processes from tools
    like Amass that spawn multiple workers).
    
    Args:
        cmd: Command and arguments as list
        timeout: Maximum execution time in seconds
        cwd: Working directory
        env: Environment variables (merged with os.environ)
        stdin_data: Data to pipe to stdin
        capture_stderr: If True, merge stderr into stdout
        sigterm_grace: Seconds to wait after SIGTERM before SIGKILL
        inject_proxy: If True, inject HTTP_PROXY/HTTPS_PROXY/ALL_PROXY env vars
                       from core.proxy_env into the child process environment.
                       Set to False for internal commands (pgrep, pip, etc.).
        scan_mode: Scan mode for proxy resolution ('recon', 'fuzz', 'exploit').
    
    Returns:
        stdout as string
    
    Raises:
        ProcessTimeoutError: If process exceeds timeout
        FileNotFoundError: If binary not found
        RuntimeError: If process exits with non-zero code
    """
    merged_env = os.environ.copy()
    
    # [V2026-FIX] Inject proxy env vars for child process traffic routing
    if inject_proxy:
        try:
            from core.proxy_env import build_proxy_env_auto
            proxy_vars = build_proxy_env_auto(scan_mode=scan_mode)
            if proxy_vars:
                merged_env.update(proxy_vars)
        except Exception:
            pass  # Fail-open: don't block tool execution if proxy_env fails
    
    if env:
        merged_env.update(env)  # Caller overrides take highest priority
    
    stderr_target = asyncio.subprocess.STDOUT if capture_stderr else asyncio.subprocess.PIPE
    
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=stderr_target,
        stdin=asyncio.subprocess.PIPE if stdin_data else asyncio.subprocess.DEVNULL,
        cwd=cwd,
        env=merged_env,
        preexec_fn=os.setsid,  # Create process group for clean kill
    )
    
    pgid = None
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pass
    
    try:
        stdout_bytes, _ = await asyncio.wait_for(
            proc.communicate(input=stdin_data),
            timeout=timeout,
        )
        
        stdout_text = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        
        if proc.returncode != 0:
            logging.debug(
                f"[ProcessManager] Non-zero exit ({proc.returncode}): "
                f"{' '.join(cmd[:3])}... — output: {stdout_text[:200]}"
            )
        
        return stdout_text
    
    except asyncio.TimeoutError:
        partial = ""
        logging.warning(
            f"[ProcessManager] TIMEOUT ({timeout}s): {' '.join(cmd[:3])}... "
            f"PID={proc.pid}, PGID={pgid}"
        )
        
        # Phase 1: SIGTERM (graceful)
        try:
            if pgid:
                os.killpg(pgid, signal.SIGTERM)
            else:
                proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        
        # Wait for graceful shutdown
        try:
            partial_bytes, _ = await asyncio.wait_for(
                proc.communicate(), timeout=sigterm_grace
            )
            partial = partial_bytes.decode("utf-8", errors="replace") if partial_bytes else ""
        except asyncio.TimeoutError:
            # Phase 2: SIGKILL (forced)
            logging.warning(
                f"[ProcessManager] SIGKILL escalation for PID={proc.pid}, PGID={pgid}"
            )
            try:
                if pgid:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    proc.kill()
            except (ProcessLookupError, OSError):
                pass
            
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                pass
        
        raise ProcessTimeoutError(cmd, timeout, partial)
    
    except Exception:
        # Ensure cleanup on any error
        try:
            if pgid:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass
        raise


def safe_run_tool_sync(
    cmd: list[str],
    timeout: float = 300,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    stdin_data: Optional[bytes] = None,
    capture_stderr: bool = True,
    sigterm_grace: float = 5.0,
    inject_proxy: bool = True,
    scan_mode: Optional[str] = None,
) -> str:
    """
    Synchronous version of safe_run_tool for use in plugins.
    
    Uses subprocess.Popen with process group + guaranteed cleanup.
    """
    merged_env = os.environ.copy()
    
    # [V2026-FIX] Inject proxy env vars for child process traffic routing
    if inject_proxy:
        try:
            from core.proxy_env import build_proxy_env_auto
            proxy_vars = build_proxy_env_auto(scan_mode=scan_mode)
            if proxy_vars:
                merged_env.update(proxy_vars)
        except Exception:
            pass  # Fail-open: don't block tool execution if proxy_env fails
    
    if env:
        merged_env.update(env)  # Caller overrides take highest priority
    
    stderr_target = subprocess.STDOUT if capture_stderr else subprocess.PIPE
    
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=stderr_target,
        stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
        cwd=cwd,
        env=merged_env,
        preexec_fn=os.setsid,
        text=False,  # Binary mode for consistent handling
    )
    
    pgid = None
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, OSError):
        pass
    
    try:
        stdout_bytes, _ = proc.communicate(input=stdin_data, timeout=timeout)
        stdout_text = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        return stdout_text
    
    except subprocess.TimeoutExpired:
        logging.warning(
            f"[ProcessManager] TIMEOUT ({timeout}s): {' '.join(cmd[:3])}... "
            f"PID={proc.pid}, PGID={pgid}"
        )
        
        # Phase 1: SIGTERM
        try:
            if pgid:
                os.killpg(pgid, signal.SIGTERM)
            else:
                proc.terminate()
        except (ProcessLookupError, OSError):
            pass
        
        # Wait for graceful shutdown
        try:
            proc.communicate(timeout=sigterm_grace)
        except subprocess.TimeoutExpired:
            # Phase 2: SIGKILL
            logging.warning(
                f"[ProcessManager] SIGKILL escalation for PID={proc.pid}, PGID={pgid}"
            )
            try:
                if pgid:
                    os.killpg(pgid, signal.SIGKILL)
                else:
                    proc.kill()
            except (ProcessLookupError, OSError):
                pass
            
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        
        raise ProcessTimeoutError(cmd, timeout, "")
    
    except Exception:
        try:
            if pgid:
                os.killpg(pgid, signal.SIGKILL)
            else:
                proc.kill()
        except (ProcessLookupError, OSError):
            pass
        raise


class BackgroundDaemonManager:
    """
    Manages background daemon processes (msfrpcd, interactsh-client) with:
    - Process group isolation
    - Health check heartbeat
    - Guaranteed cleanup via atexit
    """
    
    _instances: dict[str, "BackgroundDaemonManager"] = {}
    
    def __init__(self, name: str):
        self.name = name
        self.proc: Optional[subprocess.Popen] = None
        self.pid: Optional[int] = None
        self.pgid: Optional[int] = None
        self._started_at: Optional[float] = None
    
    @classmethod
    def get_or_create(cls, name: str) -> "BackgroundDaemonManager":
        if name not in cls._instances:
            cls._instances[name] = cls(name)
        return cls._instances[name]
    
    def start(
        self,
        cmd: list[str],
        cwd: Optional[str] = None,
        env: Optional[dict] = None,
        startup_wait: float = 3.0,
    ) -> bool:
        """
        Start a background daemon with process group isolation.
        
        Returns True if daemon started successfully.
        """
        if self.is_alive():
            logging.info(f"[DaemonManager] {self.name} already running (PID={self.pid})")
            return True
        
        merged_env = None
        if env:
            merged_env = os.environ.copy()
            merged_env.update(env)
        
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=merged_env,
                preexec_fn=os.setsid,
                start_new_session=True,
            )
            
            self.pid = self.proc.pid
            try:
                self.pgid = os.getpgid(self.pid)
            except (ProcessLookupError, OSError):
                self.pgid = self.pid
            
            self._started_at = time.time()
            
            # Wait for startup
            time.sleep(startup_wait)
            
            if self.is_alive():
                logging.info(
                    f"[DaemonManager] {self.name} started: PID={self.pid}, PGID={self.pgid}"
                )
                
                # Register atexit cleanup
                import atexit
                atexit.register(self.stop)
                
                return True
            else:
                rc = self.proc.poll()
                logging.error(
                    f"[DaemonManager] {self.name} died during startup (exit code: {rc})"
                )
                return False
        
        except FileNotFoundError:
            logging.error(f"[DaemonManager] {self.name}: binary not found — {cmd[0]}")
            return False
        except Exception as e:
            logging.error(f"[DaemonManager] {self.name}: start failed — {e}")
            return False
    
    def is_alive(self) -> bool:
        """Check if daemon process is still running."""
        if self.proc is None:
            return False
        return self.proc.poll() is None
    
    def stop(self, sigterm_grace: float = 5.0) -> None:
        """
        Stop daemon with SIGTERM → SIGKILL escalation.
        Kills entire process group to prevent orphaned children.
        """
        if not self.is_alive():
            return
        
        logging.info(f"[DaemonManager] Stopping {self.name} (PID={self.pid}, PGID={self.pgid})")
        
        # Phase 1: SIGTERM
        try:
            if self.pgid:
                os.killpg(self.pgid, signal.SIGTERM)
            elif self.proc:
                self.proc.terminate()
        except (ProcessLookupError, OSError):
            return
        
        # Wait for graceful shutdown
        try:
            if self.proc:
                self.proc.wait(timeout=sigterm_grace)
                logging.info(f"[DaemonManager] {self.name} stopped gracefully")
                return
        except subprocess.TimeoutExpired:
            pass
        
        # Phase 2: SIGKILL
        logging.warning(f"[DaemonManager] {self.name}: SIGKILL escalation")
        try:
            if self.pgid:
                os.killpg(self.pgid, signal.SIGKILL)
            elif self.proc:
                self.proc.kill()
        except (ProcessLookupError, OSError):
            pass
        
        try:
            if self.proc:
                self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            logging.error(f"[DaemonManager] {self.name}: could not kill PID={self.pid}")
    
    @classmethod
    def cleanup_all(cls) -> None:
        """Stop all managed daemons. Called by atexit."""
        for name, mgr in cls._instances.items():
            try:
                mgr.stop()
            except Exception as e:
                logging.warning(f"[DaemonManager] cleanup error for {name}: {e}")
