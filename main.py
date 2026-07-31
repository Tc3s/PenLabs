#!/usr/bin/env python3
# FILE: main.py
# CHỨC NĂNG: Điều phối luồng chạy tự động M1 -> M2 -> M3 (An toàn, OPSEC)
# V1.0: Database Core + Circuit Breaker + Checkpoint/Resume System

import os
import sys
import uuid
import json
import subprocess
import re
import argparse
import asyncio
import atexit
import logging
import unicodedata
from datetime import datetime
import readline  # Handle special terminal keys and prevent ^M on Enter

# Import PluginRegistry từ kiến trúc V1.0
from core.registry import PluginRegistry
from core.terminal_ui import (
    border as terminal_border,
    display_width as terminal_display_width,
    frame_line as terminal_frame_line,
    strip_ansi as terminal_strip_ansi,
    truncate_display as terminal_truncate_display,
)
from config import Config

# V1.0 — Circuit Breaker & Checkpoint
from core.circuit_breaker import CircuitBreaker
from core.checkpoint import CheckpointManager

# V1.0 — SQLAlchemy Database Core & Diff Engine
# Lazy import: not needed for --help/--list-profiles/--dry-run startup paths.
init_db = get_session = get_or_create_project = None
Project = ScanSession = ScanStatus = Asset = DiffEngine = None
_HAS_DB = True

# [P0-1] Schema Validation Layer — Pydantic models for inter-module contracts
validate_m1_output = validate_m2_output = SchemaValidationError = None
_HAS_SCHEMA = True

# [P0-2] Process Manager — Safe subprocess with process group kill
try:
    from core.process_manager import BackgroundDaemonManager
    _HAS_PROCMGR = True
except ImportError as _pm_err:
    _HAS_PROCMGR = False
    logging.warning(f"[ProcessManager] Process manager not available: {_pm_err}")

# V1.0 — YAML Profile Engine
try:
    from core.profile_engine import ProfileEngine, ScanProfile
    _HAS_PROFILE = True
except ImportError as _prof_err:
    _HAS_PROFILE = False
    logging.warning(f"[Profile] Profile engine not available: {_prof_err}")

# V1.0 — Terminal Dashboard
# Lazy import: rich/markdown stack is only needed for interactive review/dashboard.
TerminalDashboard = render_interactive_menu = render_tactical_review = None
_HAS_AI = True

# V1.0 — Origin Discovery Engine
# Lazy import: dnspython/HTTP stack is expensive and only needed when origin finder runs.
OriginDiscoveryEngine = None
_HAS_ORIGIN = True

# Import ScopeEngine
try:
    from utils.scope_engine import ScopeEngine
    _HAS_SCOPE = True
except ImportError:
    _HAS_SCOPE = False
    ScopeEngine = None

# Import AuditLog
try:
    from utils.audit_log import AuditLog
    _HAS_AUDIT = True
except ImportError:
    _HAS_AUDIT = False
    AuditLog = None

# --- CẤU HÌNH TÊN TRỤC MODULE ---
SCRIPTS_DIR = "scripts"
MODULE_1_SCRIPT = os.path.join(SCRIPTS_DIR, "Module1_Recon.py")
MODULE_2_SCRIPT = os.path.join(SCRIPTS_DIR, "Module2_VulnAnalysis.py")
MODULE_3_SCRIPT = os.path.join(SCRIPTS_DIR, "Module3_Exploit.py")
OUTPUT_DIR = "output"

# Màu sắc
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
DIM = "\033[90m"
RESET = "\033[0m"

ANSI_RE = re.compile(r"\x1B\[[0-9;]*[mK]")


def strip_ansi(text):
    return terminal_strip_ansi(text)


def display_width(text):
    return terminal_display_width(text)


def truncate_display(text, max_width):
    return terminal_truncate_display(text, max_width)


def frame_line(content, width=86):
    return terminal_frame_line(content, width, CYAN, RESET)

def print_banner():
    print(f"""{CYAN}
    ██████╗ ███████╗███╗   ██╗████████╗███████╗███████╗████████╗
    ██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
    ██████╔╝█████╗  ██╔██╗ ██║   ██║   █████╗  ███████╗   ██║   
    ██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══╝  ╚════██║   ██║   
    ██║     ███████╗██║ ╚████║   ██║   ███████╗███████║   ██║   
    ╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚══════╝   ╚═╝   
             AUTOMATED KILL-CHAIN FRAMEWORK (V1.0 CPE-ASYNC-RPC ARCH)
    {RESET}""")

class TeeLogger:
    """Sao chép output từ terminal sang file. Dùng atexit để đảm bảo cleanup."""
    def __init__(self, stream, filepath):
        self.stream = stream
        self.log = open(filepath, "a", encoding="utf-8")
        # [SECURITY-FIX] Dùng atexit thay vì __del__ để đảm bảo file handle được close
        atexit.register(self.close)

    def write(self, data):
        self.stream.write(data)
        if not self.log.closed:
            self.log.write(data)
    
    def flush(self):
        self.stream.flush()
        if not self.log.closed:
            self.log.flush()

    def close(self):
        """Đóng file handle một cách an toàn."""
        try:
            if hasattr(self, 'log') and not self.log.closed:
                self.log.flush()
                self.log.close()
        except Exception:
            pass

# ──  Preflight Tool Check ─────────────────────────────────────────────
def preflight_check(mode: str) -> bool:
    """
     Pre-scan tool inventory per mode.
    Phân loại: CRITICAL (abort nếu thiếu) / IMPORTANT (warning) / OPTIONAL (info).
    Returns True nếu đủ critical tools, False nếu thiếu.
    """
    import shutil

    # Tool requirements per mode
    TOOL_MATRIX = {
        # V1.0 — Tactical Doctrine 2026
        "asset-discovery": {"critical": ["httpx-toolkit"], "important": ["subfinder", "nuclei", "katana"], "optional": ["dnsx", "amass", "gowitness"]},
        "api-breach":      {"critical": ["nuclei", "httpx-toolkit"], "important": ["arjun", "katana"], "optional": ["dalfox", "sqlmap", "kiterunner", "ffuf"]},
        "cloud-native":    {"critical": ["nuclei"], "important": ["subfinder", "httpx-toolkit"], "optional": ["dnsx", "ffuf"]},
        "infra-smash":     {"critical": ["nmap"], "important": ["naabu", "nuclei"], "optional": ["rustscan", "metasploit-framework"]},
        # Legacy modes (backward compat)
        "stealth":      {"critical": ["nmap"], "important": ["nuclei", "subfinder"], "optional": ["dnsx", "amass"]},
        "sniper":       {"critical": ["nmap"], "important": ["nuclei", "httpx-toolkit", "naabu"], "optional": ["dnsx"]},
        "web-vuln":     {"critical": ["nuclei", "httpx-toolkit"], "important": ["katana", "ffuf"], "optional": ["dalfox", "gowitness"]},
        "cloud-devops": {"critical": [], "important": ["subfinder", "nuclei", "httpx-toolkit"], "optional": ["dnsx", "ffuf"]},
        "full-audit":   {"critical": ["nmap"], "important": ["nuclei", "httpx-toolkit", "naabu"], "optional": ["rustscan", "katana", "ffuf", "gowitness"]},
        "api-bounty":   {"critical": ["nuclei", "httpx-toolkit"], "important": ["katana", "ffuf"], "optional": ["dalfox", "sqlmap", "arjun", "kiterunner", "gowitness"]},
        "continuous":   {"critical": ["nuclei", "httpx-toolkit"], "important": ["subfinder", "katana"], "optional": ["dalfox", "sqlmap", "arjun"]},
    }

    tools = TOOL_MATRIX.get(mode, TOOL_MATRIX["sniper"])
    all_tools = []
    go_bin_path = os.path.expanduser("~/go/bin")
    
    for category in ["critical", "important", "optional"]:
        for tool in tools.get(category, []):
            # Check system PATH
            installed = shutil.which(tool) is not None
            # Fallback for Go binaries in ~/go/bin
            if not installed:
                potential_path = os.path.join(go_bin_path, tool)
                if os.path.isfile(potential_path) and os.access(potential_path, os.X_OK):
                    installed = True
                # Special case for kiterunner (binary name might be 'kr')
                elif tool == "kiterunner":
                    kr_path = os.path.join(go_bin_path, "kr")
                    if os.path.isfile(kr_path) and os.access(kr_path, os.X_OK):
                        installed = True
            
            all_tools.append((tool, category, installed))

    # Print report
    print(f"\n{CYAN}╔{'═'*62}╗{RESET}")
    print(f"{CYAN}║  🔍 PREFLIGHT CHECK — Tool Inventory ({mode.upper()})         {RESET}")
    print(f"{CYAN}╠{'═'*62}╣{RESET}")

    missing_critical = []
    missing_important = []
    total = len(all_tools)
    available = sum(1 for _, _, ok in all_tools if ok)

    for tool, category, installed in all_tools:
        status = f"{GREEN}✅ installed{RESET}" if installed else f"{RED}❌ missing{RESET}"
        cat_color = RED if category == "critical" else (YELLOW if category == "important" else BLUE)
        cat_label = f"{cat_color}[{category.upper()}]{RESET}"
        print(f"{CYAN}║{RESET}  {cat_label} {tool:<16} {status}")
        if not installed:
            if category == "critical":
                missing_critical.append(tool)
            elif category == "important":
                missing_important.append(tool)

    # Coverage estimate
    coverage_pct = int((available / total) * 100) if total > 0 else 0
    coverage_color = GREEN if coverage_pct >= 80 else (YELLOW if coverage_pct >= 50 else RED)
    print(f"{CYAN}╠{'═'*62}╣{RESET}")
    print(f"{CYAN}║{RESET}  📊 Tool Coverage: {coverage_color}{available}/{total} ({coverage_pct}%){RESET}")
    print(f"{CYAN}╚{'═'*62}╝{RESET}")

    if missing_critical:
        print(f"\n{RED}[!] CRITICAL TOOLS MISSING: {', '.join(missing_critical)}{RESET}")
        print(f"{RED}[!] Cannot proceed with {mode.upper()} mode. Install missing tools first.{RESET}")
        return False

    if missing_important:
        print(f"\n{YELLOW}[!] Important tools missing: {', '.join(missing_important)}")
        print(f"    Scan will proceed with reduced coverage.{RESET}")

    return True


def sanitize_target(target):
    """Sanitize target input to prevent command injection."""
    # Cho phép domain/IPv4/IPv6. KHÔNG có ký tự đặc biệt shell.
    # IPv4: 192.168.1.1
    # IPv6: 2001:db8::1, fe80::1, ::1
    # Domain: example.com, sub.example.co.uk
    ipv4_domain = re.match(r'^[a-zA-Z0-9][a-zA-Z0-9\.\-]+[a-zA-Z0-9]$', target)
    ipv6 = re.match(r'^[0-9a-fA-F:]+$', target) and ':' in target
    if not ipv4_domain and not ipv6:
        print(f"{RED}[!] Target chứa ký tự không hợp lệ. Vui lòng nhập Domain, IPv4 hoặc IPv6 sạch.{RESET}")
        sys.exit(1)
    return target

def run_command(step_name, command_args):
    """Chạy command dạng mảng an toàn (shell=False) và in realtime (để TeeLogger bắt)"""
    print(f"\n{GREEN}[+] ĐANG CHẠY: {step_name}...{RESET}")
    print(f"    CMD: {' '.join(command_args)}")
    try:
        process = subprocess.Popen(command_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        for line in process.stdout:
            sys.stdout.write(line)
            sys.stdout.flush()
        process.wait()

        if process.returncode == 0:
            print(f"{GREEN}[✔] Hoàn thành: {step_name}{RESET}")
            return True
        else:
            print(f"{RED}[✘] Lỗi khi chạy {step_name}: Ký hiệu Exit Code {process.returncode}{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[✘] Ngoại lệ khi chạy {step_name}: {e}{RESET}")
        return False

def check_modules():
    """Kiểm tra sự tồn tại của các file module"""
    missing = []
    for m in [MODULE_1_SCRIPT, MODULE_2_SCRIPT, MODULE_3_SCRIPT]:
        if not os.path.exists(m):
            missing.append(m)
    if missing:
        print(f"{RED}[!] Thiếu các file lõi: {', '.join(missing)}{RESET}")
        sys.exit(1)


def get_origin_discovery_engine():
    """Import OriginDiscoveryEngine only when origin finder is actually used."""
    global OriginDiscoveryEngine, _HAS_ORIGIN
    if not _HAS_ORIGIN:
        return None
    if OriginDiscoveryEngine is None:
        try:
            from core.origin_discovery_engine import OriginDiscoveryEngine as _OriginDiscoveryEngine
            OriginDiscoveryEngine = _OriginDiscoveryEngine
        except ImportError as exc:
            _HAS_ORIGIN = False
            logging.warning(f"[OriginFinder] Origin discovery unavailable: {exc}")
            return None
    return OriginDiscoveryEngine


def ensure_db_loaded() -> bool:
    """Load DB/Diff modules on demand."""
    global init_db, get_session, get_or_create_project
    global Project, ScanSession, ScanStatus, Asset, DiffEngine, _HAS_DB
    if not _HAS_DB:
        return False
    if init_db is not None:
        return True
    try:
        from core.db import (
            init_db as _init_db,
            get_session as _get_session,
            get_or_create_project as _get_or_create_project,
            Project as _Project,
            ScanSession as _ScanSession,
            ScanStatus as _ScanStatus,
            Asset as _Asset,
        )
        from core.diff_engine import DiffEngine as _DiffEngine
    except ImportError as exc:
        _HAS_DB = False
        logging.warning(f"[DB] Database module not available: {exc}")
        return False
    init_db = _init_db
    get_session = _get_session
    get_or_create_project = _get_or_create_project
    Project = _Project
    ScanSession = _ScanSession
    ScanStatus = _ScanStatus
    Asset = _Asset
    DiffEngine = _DiffEngine
    return True


def ensure_schema_loaded() -> bool:
    """Load Pydantic schemas only when validating module output."""
    global validate_m1_output, validate_m2_output, SchemaValidationError, _HAS_SCHEMA
    if not _HAS_SCHEMA:
        return False
    if validate_m1_output is not None:
        return True
    try:
        from core.schemas import (
            validate_m1_output as _validate_m1_output,
            validate_m2_output as _validate_m2_output,
            SchemaValidationError as _SchemaValidationError,
        )
    except ImportError as exc:
        _HAS_SCHEMA = False
        logging.warning(f"[Schema] Schema validation not available: {exc}")
        return False
    validate_m1_output = _validate_m1_output
    validate_m2_output = _validate_m2_output
    SchemaValidationError = _SchemaValidationError
    return True


def ensure_dashboard_loaded() -> bool:
    """Load Rich dashboard components only when UI rendering is requested."""
    global TerminalDashboard, render_interactive_menu, render_tactical_review, _HAS_AI
    if not _HAS_AI:
        return False
    if TerminalDashboard is not None:
        return True
    try:
        from core.dashboard import (
            TerminalDashboard as _TerminalDashboard,
            render_interactive_menu as _render_interactive_menu,
            render_tactical_review as _render_tactical_review,
        )
    except ImportError as exc:
        _HAS_AI = False
        logging.warning(f"[Dashboard] Terminal Dashboard unavailable: {exc}")
        return False
    TerminalDashboard = _TerminalDashboard
    render_interactive_menu = _render_interactive_menu
    render_tactical_review = _render_tactical_review
    return True


async def _scan_subdomain_async(sub_target, idx, total, recursive_results_dir, mode, args, _HAS_ORIGIN, semaphore):
    async with semaphore:
        print(f"\n{CYAN}[RECURSIVE-ASYNC {idx}/{total}] ══ {sub_target} ══{RESET}")
        
        sub_session = os.path.join(recursive_results_dir, sub_target.replace(".", "_"))
        os.makedirs(sub_session, exist_ok=True)
        sub_result = {"subdomain": sub_target, "origin_ip": None, "m2_findings": 0}
        
        # ── Step 1: Origin Finder (nếu bật) ──
        if getattr(args, 'origin_finder', False) and _HAS_ORIGIN:
            try:
                origin_cls = get_origin_discovery_engine()
                if not origin_cls:
                    raise RuntimeError("OriginDiscoveryEngine unavailable")
                origin_eng = origin_cls()
                loop = asyncio.get_running_loop()
                o_result = await loop.run_in_executor(None, origin_eng.discover, sub_target)
                if o_result.get("origin_ip"):
                    sub_result["origin_ip"] = o_result["origin_ip"]
                    print(f"{GREEN}  [ORIGIN] {sub_target} → {o_result['origin_ip']} (Confidence: {o_result['confidence']}%){RESET}")
                    origin_file = os.path.join(sub_session, "origin.json")
                    with open(origin_file, "w") as _of:
                        json.dump(o_result, _of, indent=2, default=str)
                else:
                    print(f"{YELLOW}  [ORIGIN] {sub_target}: Không tìm thấy Origin IP.{RESET}")
            except Exception as _oe:
                print(f"{YELLOW}  [ORIGIN] {sub_target}: Lỗi - {_oe}{RESET}")

        # ── Step 2: Module 1 (Lightweight Recon) cho subdomain ──
        sub_m1_json = os.path.join(sub_session, "m1_recon.json")
        cmd_sub_m1 = [
            sys.executable, MODULE_1_SCRIPT,
            sub_target,
            "--outdir", sub_session,
            "--output", sub_m1_json,
            "--mode", mode,
            "--rate-limit", str(args.rate_limit),
        ]
        if args.proxy:
            cmd_sub_m1.extend(["--proxy", args.proxy])
        if args.debug:
            cmd_sub_m1.append("--debug")
        if getattr(args, 'cookie', ''):
            cmd_sub_m1.extend(["--cookie", args.cookie])
        if getattr(args, 'permissive', False):
            cmd_sub_m1.append("--permissive")
            if getattr(args, 'confirm_permissive', False):
                cmd_sub_m1.append("--confirm-permissive")

        print(f"{BLUE}  [M1] Chạy Recon cho {sub_target}...{RESET}")
        loop = asyncio.get_running_loop()
        m1_success = await loop.run_in_executor(None, run_command, f"RECURSIVE M1 ({sub_target})", cmd_sub_m1)
        
        if m1_success:
            # ── Step 3: Module 2 (VulnAnalysis) cho subdomain ──
            if os.path.exists(sub_m1_json):
                sub_m2_json = os.path.join(sub_session, "m2_vuln.json")
                cmd_sub_m2 = [
                    sys.executable, MODULE_2_SCRIPT,
                    "--m1-json", sub_m1_json,
                    "--output", sub_m2_json
                ]
                if args.debug:
                    cmd_sub_m2.append("--debug")

                print(f"{BLUE}  [M2] Chạy VulnAnalysis cho {sub_target}...{RESET}")
                m2_success = await loop.run_in_executor(None, run_command, f"RECURSIVE M2 ({sub_target})", cmd_sub_m2)
                if m2_success:
                    try:
                        with open(sub_m2_json, "r") as _sm2:
                            sm2_data = json.load(_sm2)
                            sub_result["m2_findings"] = len(sm2_data.get("attack_plan", []))
                            if sub_result["m2_findings"]:
                                print(f"{GREEN}  [M2] {sub_target}: {sub_result['m2_findings']} findings!{RESET}")
                    except Exception:
                        pass
        else:
            print(f"{YELLOW}  [M1] {sub_target}: Recon thất bại, bỏ qua.{RESET}")

        return sub_result


async def _scan_all_subdomains_async(live_subdomains, recursive_results_dir, mode, args, _HAS_ORIGIN):
    semaphore = asyncio.Semaphore(10)  # max 10 concurrent subdomain scans
    tasks = [
        _scan_subdomain_async(sub_target, idx, len(live_subdomains), recursive_results_dir, mode, args, _HAS_ORIGIN, semaphore)
        for idx, sub_target in enumerate(live_subdomains, 1)
    ]
    return await asyncio.gather(*tasks, return_exceptions=True)

def main():
    global _HAS_DB
    parser = argparse.ArgumentParser(description="Automated Kill-Chain Framework (V1.0 — Stealth & Precision)")
    parser.add_argument("target", nargs='?', help="Mục tiêu (Domain/IPv4)")
    parser.add_argument("--mode", choices=[
        # V1.0 Tactical Doctrine
        'asset-discovery', 'api-breach', 'cloud-native', 'infra-smash',
        # Legacy (backward compat)
        'sniper', 'fast', 'stealth', 'web-vuln', 'cloud-devops', 'full-audit', 'api-bounty', 'continuous'
    ], help="Chế độ quét")
    parser.add_argument("--vt-key", default=os.getenv('VT_API_KEY', ''), help="VirusTotal API Key (có thể truyền qua biến môi trường VT_API_KEY)")
    parser.add_argument("--interactive", action="store_true", default=True, help="Bật Menu Review Khai thác (Mặc định: Bật)")
    parser.add_argument("--no-msf", action="store_true", help="Vô hiệu hoá Module 3 (Không gọi Metasploit)")
    
    # Cờ mới được thêm vào từ V1.0
    parser.add_argument("--blacklist", help="Đường dẫn đến file chứa danh sách IP/Domain cần đưa vào Blacklist")
    parser.add_argument("--no-interactive", action="store_true", help="Chạy hoàn toàn tự động, không hỏi input")
    parser.add_argument("--auto-exploit", action="store_true", help="Tự động pick CVE cao nhất và khai thác")
    
    # Cờ Stealth / Evasion (V1.0 - Tier 1 Evasion)
    parser.add_argument("--stealth", action="store_true", help="Bật chế độ AV/EDR & WAF Evasion (Tunnel/Crypter)")
    parser.add_argument("--stealth-recon", action="store_true", help="Bật tính năng săn subdomain & bypass WAF")
    parser.add_argument("--subdomain-scan", dest="subdomain_scan", action="store_true", default=True, help="Bật quét đệ quy tất cả subdomains tìm thấy")
    parser.add_argument("--no-subdomain-scan", dest="subdomain_scan", action="store_false", help="Tắt quét đệ quy subdomain tự động")
    parser.add_argument("--no-stealth-discovery", dest="stealth_discovery", action="store_false", default=True, help="Tắt WAF/subdomain passive discovery mặc định")
    parser.add_argument("--no-osint", dest="osint_enabled", action="store_false", default=True, help="Tắt OSINT passive phase (benchmark/active-only)")
    parser.add_argument("--proxy", default="", help="Sử dụng proxy URL (vd: socks5://127.0.0.1:9050) hoặc file proxies.txt cho HTTP")
    parser.add_argument("--tor-route", action="store_true", help="Ép HTTP tooling hỗ trợ proxy đi qua Tor SOCKS5 local 127.0.0.1:9050")
    parser.add_argument("--rate-limit", type=int, default=5, help="Giới hạn requests/giây (WAF bypass, mặc định: 5)")
    parser.add_argument("--delay", default="", help="Delay giữa các web requests (vd: 500ms, 2s)")
    parser.add_argument("--recursive-sub", action="store_true", default=False, help="Quét sâu M2 trên tất cả live subdomains (max 50)")
    
    # Cờ Debug Mode V1.0
    parser.add_argument("--debug", action="store_true", help="In ra toàn bộ log của các công cụ đang chạy & lưu vào file")
    
    # Scope Enforcement
    parser.add_argument("--scope", help="Đường dẫn file scope (mỗi dòng 1 IP/CIDR/domain được phép)")
    parser.add_argument("--permissive", action="store_true", help="Cho phép mọi target (bỏ qua scope check) — chỉ dùng cho lab/CTF")
    parser.add_argument("--confirm-permissive", action="store_true", help="[HIGH-05 FIX] Bắt buộc bật để xác nhận nguy hiểm khi dùng --permissive")
    
    # [V1.0] Visual Recon & Auto-Persistence
    parser.add_argument("--visual-recon", action="store_true", help="Chụp ảnh bằng chứng (gowitness screenshots) cho tất cả live URL")
    parser.add_argument("--persist", action="store_true", help="Kích hoạt cây cửa hậu sinh tồn (SSH key/SystemD/LD_PRELOAD backdoor)")
    
    # [V1.0] Stealth & Precision
    parser.add_argument("--no-edr-check", action="store_true", help="Tắt EDR Dry-Run check trước exploit")
    parser.add_argument("--no-interactsh", action="store_true", help="Tắt Interactsh OOB daemon")
    parser.add_argument("--no-smart-cpe", action="store_true", help="Tắt Smart CPE Filter (Nểu HttpX data gây false negative)")
    
    # [V1.0] Bug Bounty Extended
    parser.add_argument("--auth-userA", default="", help="Auth token cho User A (VD: 'Bearer xxx') — dùng cho BOLA Engine")
    parser.add_argument("--auth-userB", default="", help="Auth token cho User B (VD: 'Bearer yyy') — dùng cho BOLA Engine")
    
    # [FIX-REVIEW-1] Authenticated Scan — Cờ bị thiếu so với Module 1
    parser.add_argument("--cookie", default="", help="HTTP Cookie cho authenticated scan (VD: 'PHPSESSID=abc123; token=xyz')")
    parser.add_argument("--header", action="append", help="Custom HTTP Header, có thể dùng nhiều lần (VD: --header 'Authorization: Bearer xxx' --header 'X-Custom: val')")
    
    # [V1.0] Checkpoint/Resume System
    parser.add_argument("--resume", default=None, help="Resume scan từ session bị gián đoạn (VD: --resume SESSION_example.com_20260419_120000_abc123)")
    
    # [V1.0] Database Core
    parser.add_argument("--db-url", default="", help="Database URL (mặc định: SQLite tại output/penlabs.db, VD PostgreSQL: postgresql://user:pass@host:5432/penlabs)")
    parser.add_argument("--project", default="", help="Tên project/campaign (VD: 'HackerOne-Yahoo'). Tự động sinh slug.")
    
    # [V1.0] YAML Profile Orchestration
    parser.add_argument("--profile", default="", help="YAML profile name hoặc path (VD: 'stealth', 'api-bounty', '/path/to/custom.yaml')")
    parser.add_argument("--dry-run", action="store_true", help="Xem trước pipeline sẽ chạy (không thực thi scan)")
    parser.add_argument("--list-profiles", action="store_true", help="Liệt kê tất cả YAML profiles có sẵn")
    
    # [V1.0] New Core Options
    parser.add_argument("--proxy-file", help="Đường dẫn đến file danh sách proxies (để xoay IP)")
    parser.add_argument("--auth-config", help="Đường dẫn đến file JSON cấu hình tự động xác thực (Login flow)")
    parser.add_argument("--use-playwright", action="store_true", help="Kích hoạt SPA Discovery Engine qua trình duyệt Chromium")
    parser.add_argument("--sqlmap-relay", action="store_true", help="Tàng hình hóa SQLMap qua StealthNet Proxy Relay")
    parser.add_argument("--bola-engine", action="store_true", help="Kích hoạt BOLA/IDOR Engine kiểm tra phân quyền")
    parser.add_argument("--seed-subs", help="File chứa danh sách subdomain mồi (từ Origin-Finder)")
    parser.add_argument("--chunk-size", type=int, default=20, help="Kích thước đơn vị Resume (Chunks) để hỗ trợ Resume (mặc định: 20)")
    
    cli_argv = sys.argv[1:]
    cli_rate_limit_explicit = "--rate-limit" in cli_argv
    cli_no_subdomain_scan_explicit = "--no-subdomain-scan" in cli_argv
    args = parser.parse_args()
    args._cli_rate_limit_explicit = cli_rate_limit_explicit
    args._cli_no_subdomain_scan_explicit = cli_no_subdomain_scan_explicit
    
    # ── Đồng bộ scope_enforce ↔ permissive ──
    if hasattr(args, 'scope_enforce'):
        args.permissive = not args.scope_enforce
    
    #  Normalize header_input from interactive menu to header list
    if getattr(args, 'header_input', None) and not args.header:
        args.header = [args.header_input]

    print_banner()
    check_modules()

    # ══════════════════════════════════════════════════════════════
    # V1.0: PROFILE ENGINE — List / Dry-Run / Load
    # ══════════════════════════════════════════════════════════════
    _profile_engine = ProfileEngine() if _HAS_PROFILE else None
    _active_profile = None  # Will be set if --profile or --mode maps to a YAML

    # --list-profiles: Show available profiles and exit
    if args.list_profiles:
        if not _profile_engine:
            print(f"{RED}[!] Profile Engine not available.{RESET}")
            sys.exit(1)
        profiles = _profile_engine.list_profiles()
        print(f"\n{CYAN}╔{'═'*62}╗{RESET}")
        print(f"{CYAN}║  📋 Available Scan Profiles                                  ║{RESET}")
        print(f"{CYAN}╠{'═'*62}╣{RESET}")
        for p in profiles:
            print(f"{CYAN}║{RESET}  {GREEN}{p['name']:<16}{RESET} {p['description'][:42]}")
            print(f"{CYAN}║{RESET}    Steps: {p['steps']}  |  {p['path']}")
        print(f"{CYAN}╚{'═'*62}╝{RESET}")
        sys.exit(0)

    # Try to load profile (from --profile flag or --mode fallback)
    if _profile_engine:
        profile_name = args.profile or args.mode
        if profile_name:
            try:
                # Support direct YAML file paths
                if profile_name.endswith(('.yaml', '.yml')) and os.path.isfile(profile_name):
                    _active_profile = _profile_engine.load_file(profile_name)
                else:
                    _active_profile = _profile_engine.load(profile_name)
                print(f"{GREEN}[Profile] ✅ Loaded: {_active_profile.name} — {_active_profile.description}{RESET}")
            except FileNotFoundError:
                # No YAML profile for this mode — use legacy hardcoded logic
                print(f"{YELLOW}[Profile] No YAML profile for '{profile_name}', using legacy mode.{RESET}")
            except Exception as e:
                print(f"{YELLOW}[Profile] ⚠️  Profile load error: {e}. Using legacy mode.{RESET}")

    # --dry-run: Show pipeline preview and exit
    if args.dry_run:
        if _active_profile:
            print(_active_profile.dry_run())
        else:
            print(f"{YELLOW}[!] Dry-run requires a profile. Use --profile <name> or ensure --mode has a YAML profile.{RESET}")
            if _profile_engine:
                print(f"    Available: {[p['name'] for p in _profile_engine.list_profiles()]}")
        sys.exit(0)

    # ══════════════════════════════════════════════════════════════
    # V1.0: CORE SERVICE INITIALIZATION (Proxy & Auth)
    # ══════════════════════════════════════════════════════════════
    if getattr(args, 'proxy_file', None):
        from utils.proxy_manager import ProxyManager
        ProxyManager(proxy_file=args.proxy_file)
        print(f"{GREEN}[Proxy] ✅ Proxy Manager initialized with {args.proxy_file}{RESET}")

    # Initialize AuthManager from CLI or Auth Config file
    auth_mgr = None
    try:
        from core.auth_manager import AuthManager
        cookie_val = getattr(args, 'cookie', '') or ''
        userA_val = getattr(args, 'auth_userA', '') or ''
        header_val = args.header[0] if getattr(args, 'header', None) and isinstance(args.header, list) and args.header else ''
        auth_mgr = AuthManager(auth_token=userA_val, cookie_str=cookie_val, auth_header=header_val)
        if auth_mgr.is_authenticated():
            print(f"{GREEN}[Auth] ✅ AuthManager initialized for authenticated scan context.{RESET}")
    except Exception as e:
        print(f"{YELLOW}[Auth] AuthManager initialization warning: {e}{RESET}")

    # --- [NEW-AUDIT] Khởi tạo Audit Log cho CLI ---
    audit_logger = None
    if _HAS_AUDIT and AuditLog:
        # Đảm bảo thư mục output tồn tại cho audit.log
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        audit_logger = AuditLog(log_path=os.path.join(OUTPUT_DIR, "audit.log"))
        audit_logger.log("CLI", "CLI_START", args.target or "UNKNOWN", f"mode={args.mode or 'INTERACTIVE'}")
    
    target_input = args.target
    if not target_input:
        if args.no_interactive:
            print(f"{RED}[!] Chế độ --no-interactive yêu cầu truyền target là argument.{RESET}")
            sys.exit(1)
        target_input = input(f"\n{CYAN}🎯 Nhập Mục tiêu (Domain/IPv4): {RESET}").strip()

    target = sanitize_target(target_input)
    if not target:
        print(f"\n{RED}[✘] Lỗi: Mục tiêu không hợp lệ! Vui lòng nhập Domain hoặc IPv4 đúng chuẩn.{RESET}")
        sys.exit(1)

    # [SCOPE-FIX-V1.0] Scope và Blacklist là 2 cơ chế TÁCH BIỆT:
    #   - Scope = danh sách CHO PHÉP (whitelist)
    #   - Blacklist = danh sách CẤM (blacklist)
    # KHÔNG được dùng BLACKLIST_FILE làm scope_file!
    if _HAS_SCOPE and ScopeEngine:
        scope = ScopeEngine(
            scope_file=args.scope or None,
            permissive=args.permissive,
            confirm_permissive=getattr(args, 'confirm_permissive', False)
        )
        print(f"{YELLOW}[*] Scope: {scope.summary()}{RESET}")
        if not scope.is_in_scope(target):
            print(f"{RED}[!] TARGET '{target}' NẰM NGOÀI SCOPE! Dừng lại.{RESET}")
            print(f"{YELLOW}    Thêm target vào scope file hoặc dùng --permissive (lab only).{RESET}")
            sys.exit(1)
    
    # BƯỚC 2: CHỌN CHẾ ĐỘ CHIẾN THUẬT (2026 Tactical Doctrine)
    mode = args.mode
    if not mode:
        MAGENTA = "\033[95m"
        tactical_modes = [
            ("1", "ASSET-DISCOVERY", "asset-discovery", "[Recon]", "Subdomains, JS, API, tokens", "LOW", "LOW"),
            ("2", "WEB-VULN", "web-vuln", "[Auth Web]", "Nuclei + Dalfox + CORS + BXSS", "MED", "MED"),
            ("3", "API-BOUNTY", "api-bounty", "[Bounty]", "Full web/API logic flaw pipeline", "MED", "MED"),
            ("4", "API-BREACH", "api-breach", "[Origin/API]", "Origin finder + Arjun + exposure", "MED", "HIGH"),
            ("5", "CLOUD-NATIVE", "cloud-native", "[Cloud]", "S3/GCP/Azure/takeover/K8s", "MED", "MED"),
            ("6", "INFRA-SMASH", "infra-smash", "[Red Team]", "Ports -> NSE -> exploit chain", "HIGH", "HIGH"),
            ("7", "SNIPER", "sniper", "[Balanced]", "Nhanh, gon, mot target chinh", "LOW", "LOW"),
            ("8", "STEALTH", "stealth", "[Low Noise]", "WAF-aware / external quiet scan", "LOW", "LOW"),
            ("9", "FULL-AUDIT", "full-audit", "[Deep]", "Coverage sau, noise cao", "HIGH", "HIGH"),
        ]
        mode_colors = {
            "1": GREEN,
            "2": YELLOW,
            "3": MAGENTA,
            "4": BLUE,
            "5": BLUE,
            "6": RED,
            "7": CYAN,
            "8": CYAN,
            "9": CYAN,
        }
        direct_map = {
            "1": "asset-discovery",
            "2": "web-vuln",
            "3": "api-bounty",
            "4": "api-breach",
            "5": "cloud-native",
            "6": "infra-smash",
            "7": "sniper",
            "8": "stealth",
            "9": "full-audit",
            "recon": "asset-discovery",
            "asset": "asset-discovery",
            "asset-discovery": "asset-discovery",
            "web": "web-vuln",
            "web-vuln": "web-vuln",
            "auth-web": "web-vuln",
            "bounty": "api-bounty",
            "api-bounty": "api-bounty",
            "origin": "api-breach",
            "api": "api-breach",
            "api-breach": "api-breach",
            "cloud": "cloud-native",
            "cloud-native": "cloud-native",
            "redteam": "infra-smash",
            "infra": "infra-smash",
            "infra-smash": "infra-smash",
            "sniper": "sniper",
            "stealth": "stealth",
            "quiet": "stealth",
            "audit": "full-audit",
            "full": "full-audit",
            "full-audit": "full-audit",
        }
        advanced_map = {
            "a": "cloud-devops",
            "b": "continuous",
            "cloud-devops": "cloud-devops",
            "cloud": "cloud-devops",
            "continuous": "continuous",
            "cont": "continuous",
        }
        danger_modes = {"infra-smash", "full-audit", "continuous"}
        width = 86
        print("\n" + terminal_border("top", width, CYAN, RESET))
        print(frame_line(f"  {CYAN}TACTICAL DOCTRINE V1.0 - CHON CHE DO CHIEN THUAT{RESET}", width))
        print(terminal_border("mid", width, CYAN, RESET))
        print(frame_line(f"  {DIM}{'No':<4} {'Mode':<18} {'Profile':<13} {'Use case':<30} {'N':<7} {'R':<7}{RESET}", width))
        print(terminal_border("sep", width, CYAN, RESET))
        for key, label, _, profile, focus, noise, risk in tactical_modes:
            color = mode_colors[key]
            noise_color = GREEN if noise == "LOW" else (YELLOW if noise == "MED" else RED)
            risk_color = GREEN if risk == "LOW" else (YELLOW if risk == "MED" else RED)
            line = (
                f"  {color}{key:<4}{RESET} {label:<18} {profile:<13} "
                f"{truncate_display(focus, 30):<30} {noise_color}{noise:<7}{RESET} {risk_color}{risk:<7}{RESET}"
            )
            print(frame_line(line, width))
        print(terminal_border("mid", width, CYAN, RESET))
        print(frame_line(f"  {MAGENTA}A{RESET}    ADVANCED           cloud-devops | continuous", width))
        print(frame_line(f"  {YELLOW}Quick map:{RESET} recon=1 | bounty=3 | redteam=6 | stealth=8 | audit=9", width))
        print(frame_line(f"  {DIM}Nhap 1 so, A, hoac alias mode. Vi du: recon | bounty | stealth{RESET}", width))
        print(terminal_border("bottom", width, CYAN, RESET))
        choice = input(f"\n{YELLOW}👉 Lựa chọn của bạn (1-9/A hoặc alias) [Mặc định: 1]: {RESET}").strip().lower()
        choice = re.split(r"[\s,]+", choice)[0] if choice else ""

        if choice == 'a':
            print(f"\n{YELLOW}  Advanced Modes:{RESET}")
            print(f"    {CYAN}[a]{RESET} cloud-devops   {CYAN}[b]{RESET} continuous")
            print(f"    {DIM}Alias: cloud | cloud-devops | cont | continuous{RESET}")
            sub = input(f"  {YELLOW}Chọn (a-b hoặc alias) [Mặc định: a]: {RESET}").strip().lower()
            sub = re.split(r"[\s,]+", sub)[0] if sub else ""
            mode = advanced_map.get(sub, 'cloud-devops')
        else:
            mode = direct_map.get(choice, 'asset-discovery')

        if mode in danger_modes:
            confirm = input(
                f"{RED}[CONFIRM] Mode {mode.upper()} co noise/risk cao. Gõ YES để tiếp tục: {RESET}"
            ).strip()
            if confirm != "YES":
                print(f"{YELLOW}[i] Hủy mode nguy cơ cao, quay về ASSET-DISCOVERY.{RESET}")
                mode = "asset-discovery"
        
        # [V1.0-FIX] Cập nhật lại args.mode để các module sau (như Dashboard) nhận diện được
        args.mode = mode

    # Dynamically load YAML profile matching the mode if none was specified on the CLI
    if not _active_profile and _profile_engine and mode:
        try:
            profile_name_to_load = "fast" if mode == "sniper" else mode
            _active_profile = _profile_engine.load(profile_name_to_load)
            print(f"{GREEN}[Profile] ✅ Loaded Profile dynamically for Mode: {_active_profile.name} — {_active_profile.description}{RESET}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"{YELLOW}[Profile] ⚠️  Dynamic profile load error: {e}{RESET}")

    print(f"\n\U0001f3af Mục tiêu: {target}")
    print(f"\U0001f575\ufe0f Chế độ chiến thuật: {mode.upper()}")

    # V1.0: Mode-specific auto-configuration (Profile-first, fallback to hardcoded)
    if _active_profile:
        # Profile drives origin_finder and flags
        args.origin_finder = _active_profile.origin_finder_enabled
        if _active_profile.get_flag("no_msf", False):
            args.no_msf = True
        if _active_profile.tactical_mode != 'fallback':
            mode = _active_profile.tactical_mode
            print(f"{CYAN}[V1.0] Profile tactical_mode override: {mode.upper()}{RESET}")

        # Bridge profile values into args & Config. Explicit CLI RoE controls
        # must win over profile defaults on production scans.
        profile_rate_cfg = _active_profile.to_rate_limit_dict()
        if getattr(args, "_cli_rate_limit_explicit", False):
            cli_rate = max(1, int(args.rate_limit))
            profile_rate_cfg["nuclei_rate"] = min(int(profile_rate_cfg.get("nuclei_rate", cli_rate)), cli_rate)
            if cli_rate <= 5:
                profile_rate_cfg["nuclei_conc"] = min(int(profile_rate_cfg.get("nuclei_conc", 2)), 2)
        Config.RATE_LIMITS[mode] = profile_rate_cfg
        Config.KATANA_MAX_URLS[mode] = _active_profile.to_katana_max()
        if not getattr(args, "_cli_rate_limit_explicit", False):
            args.rate_limit = _active_profile.rate_limit.requests_per_second
        if _active_profile.rate_limit.delay_between_requests != "0":
            args.delay = _active_profile.rate_limit.delay_between_requests

        if _active_profile.stealth_mode:
            args.stealth = True
            args.stealth_recon = True
        if _active_profile.waf_bypass:
            args.stealth_recon = True
        if not _active_profile.interactsh_enabled:
            args.no_interactsh = True
        if _active_profile.visual_recon:
            args.visual_recon = True
        if _active_profile.auto_exploit:
            args.auto_exploit = True
        if not _active_profile.smart_cpe_filter:
            args.no_smart_cpe = True
        if _active_profile.get_flag("recursive_sub", False) and not getattr(args, "_cli_no_subdomain_scan_explicit", False):
            args.recursive_sub = True
    else:
        # Legacy hardcoded fallback
        if mode == 'api-breach':
            args.origin_finder = True
            args.no_msf = True
            if not hasattr(args, 'recursive_sub'):
                args.recursive_sub = True
            print(f"{CYAN}[API-BREACH] Auto-enabled Origin Finder + Recursive Sub + disabled M3.{RESET}")
        elif mode == 'asset-discovery':
            if not hasattr(args, 'recursive_sub'):
                args.recursive_sub = True
            print(f"{GREEN}[ASSET-DISCOVERY] Auto-enabled Recursive Subdomain Scan.{RESET}")
        elif mode == 'api-bounty':
            args.no_msf = True
            print(f"{YELLOW}[*] API-BOUNTY mode: Auto-disabled M3/M4.{RESET}")
        elif mode == 'infra-smash':
            print(f"{RED}[INFRA-SMASH] \u2620\ufe0f  Red Team mode \u2014 InternetDB passive port map + full kill-chain.{RESET}")

    # BƯỚC 3: Tactical Options Menu V5 (chỉ hiển thị trong interactive mode)
    if not args.no_interactive:
        if ensure_dashboard_loaded():
            render_interactive_menu(args)
            render_tactical_review(args)
        else:
            print(f"{YELLOW}[*] Dashboard/Menu module is not available. Skipping interactive options menu.{RESET}")

    # --- Đồng bộ Visual Recon & Persistence vào Config ---
    Config.VISUAL_RECON = getattr(args, 'visual_recon', False)
    os.environ["VISUAL_RECON"] = str(Config.VISUAL_RECON).lower()
    Config.PERSISTENCE = getattr(args, 'persist', False)
    os.environ["PERSISTENCE"] = str(Config.PERSISTENCE).lower()

    # --- [FIX] Đồng bộ JA3-SPOOF toggle từ TUI vào Config + env var ---
    # Cho phép user thực sự bật/tắt JA3 spoofing qua menu thay vì dead flag.
    Config.JA3_SPOOF_ENABLED = getattr(args, 'ja3_spoof', True)
    os.environ["JA3_SPOOF_ENABLED"] = str(Config.JA3_SPOOF_ENABLED).lower()
    
    # ---  --stealth → Auto-enable --stealth-recon + cap rate-limit ---
    # Khi Red Teamer bật --stealth, toàn bộ pipeline phải im lặng end-to-end:
    #   M1: stealth-recon ON, rate-limit ≤ 50, User-Agent rotation ON
    #   M3: Tunnel + Crypter ON (đã có sẵn)
    if getattr(args, 'stealth', False):
        if not args.stealth_recon:
            args.stealth_recon = True
            print(f"{YELLOW}🥷 [STEALTH] Auto-enabled --stealth-recon cho Module 1 (WAF bypass + UA rotation).{RESET}")
        if args.rate_limit > 50:
            args.rate_limit = 50
            print(f"{YELLOW}🥷 [STEALTH] Rate-limit capped tại 50 req/s để giảm noise.{RESET}")
        if not args.delay:
            args.delay = "500ms"
            print(f"{YELLOW}🥷 [STEALTH] Auto-set delay=500ms giữa các requests.{RESET}")
    
    # --- [V1.0] Đồng bộ Stealth & Precision flags ---
    if getattr(args, 'no_edr_check', False):
        Config.EDR_DRYRUN_ENABLED = False
        os.environ["EDR_DRYRUN_ENABLED"] = "false"
    if getattr(args, 'no_interactsh', False):
        Config.INTERACTSH_ENABLED = False
        os.environ["INTERACTSH_ENABLED"] = "false"
        #  Warn about disabled OOB detection
        print(f"{YELLOW}⚠️  [WARNING] Interactsh disabled — Blind SSRF/XSS detection will NOT work.{RESET}")
    if getattr(args, 'no_smart_cpe', False):
        Config.SMART_CPE_FILTER = False
        os.environ["SMART_CPE_FILTER"] = "false"
        #  Warn about disabled CPE matching
        print(f"{YELLOW}⚠️  [WARNING] Smart CPE filter disabled — Expect significantly higher false positive rate in M2.{RESET}")

    # --- Tóm tắt cuối cùng sau khi user chọn xong ---
    print(f"\n{CYAN}\u2554{'\u2550'*62}\u2557{RESET}")
    print(f"{CYAN}\u2551  ✅ CẤU HÌNH PHIÊN LÀM VIỆC{' ' * 38}\u2551{RESET}")
    print(f"{CYAN}\u2560{'\u2550'*62}\u2563{RESET}")
    print(f"{CYAN}\u2551{RESET}  🎯 Target       : {GREEN}{target}{RESET}")
    print(f"{CYAN}\u2551{RESET}  \U0001f6e1\ufe0f  Mode         : {YELLOW}{mode.upper()}{RESET}")
    print(f"{CYAN}\u2551{RESET}  \U0001f4cc Auto-Exploit : {'%s[ON]%s' % (GREEN, RESET) if args.auto_exploit else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  🥷 Stealth      : {'%s[ON]%s' % (GREEN, RESET) if getattr(args, 'stealth', False) else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f4cc Stealth-Recon: {'%s[ON]%s' % (GREEN, RESET) if args.stealth_recon else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f4cc Proxy        : {'%s[ON]%s' % (GREEN, RESET) if args.proxy else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f4cc Debug        : {'%s[ON]%s' % (GREEN, RESET) if args.debug else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f4cc No-MSF       : {'%s[ON]%s' % (GREEN, RESET) if args.no_msf else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f4f8 Visual-Recon : {'%s[ON]%s' % (GREEN, RESET) if getattr(args, 'visual_recon', False) else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f512 Persistence  : {'%s[ON]%s' % (GREEN, RESET) if getattr(args, 'persist', False) else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f6e1 EDR-DryRun   : {'%s[ON]%s' % (GREEN, RESET) if Config.EDR_DRYRUN_ENABLED else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f9ec Interactsh   : {'%s[ON]%s' % (GREEN, RESET) if Config.INTERACTSH_ENABLED else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  \U0001f9f0 SmartCPE     : {'%s[ON]%s' % (GREEN, RESET) if Config.SMART_CPE_FILTER else '%s[OFF]%s' % (RED, RESET)}")
    print(f"{CYAN}\u2551{RESET}  ⚡ Rate-Limit   : {YELLOW}{args.rate_limit} req/s{RESET}")
    if getattr(args, 'cookie', ''):
        print(f"{CYAN}\u2551{RESET}  🍪 Cookie       : {GREEN}[SET]{RESET}")
    if getattr(args, 'header', None):
        print(f"{CYAN}\u2551{RESET}  📋 Headers      : {GREEN}{len(args.header)} custom header(s){RESET}")
    if args.scope:
        print(f"{CYAN}\u2551{RESET}  \U0001f4cc Scope File   : {GREEN}{args.scope}{RESET}")
    if args.blacklist:
        print(f"{CYAN}\u2551{RESET}  \U0001f4cc Blacklist    : {GREEN}{args.blacklist}{RESET}")
    print(f"{CYAN}\u255a{'\u2550'*62}\u255d{RESET}")

    # Preflight tool check — warn before long scan (final resolved mode)
    if not preflight_check(mode):
        print(f"{RED}[!] Preflight check failed. Aborting.{RESET}")
        sys.exit(1)

    if audit_logger:
        audit_logger.log("CLI", "SCAN_STARTED", target, f"mode={mode}")

    # [PI-2 FIX] Dry-Run gate
    if getattr(args, 'dry_run', False):
        print(f"\n{YELLOW}[DRY-RUN] Pipeline preview completed. Exiting without execution.{RESET}")
        sys.exit(0)

    # ==============================================================
    # KHỞI TẠO SESSION
    # ==============================================================
    # V1.0: Hỗ trợ --resume để resume session trước đó
    resume_session = getattr(args, 'resume', None)
    if resume_session:
        # Resume từ session cũ
        if os.path.isdir(resume_session):
            session_dir = resume_session
            session_id = os.path.basename(session_dir)
        else:
            # Tìm trong output/
            candidate = os.path.join(os.getcwd(), OUTPUT_DIR, resume_session)
            if os.path.isdir(candidate):
                session_dir = candidate
                session_id = resume_session
            else:
                print(f"{RED}[!] Không tìm thấy session '{resume_session}' để resume.{RESET}")
                sys.exit(1)
        print(f"{GREEN}[*] RESUMING session: {session_id}{RESET}")
    else:
        # Khởi tạo Session ID an toàn và thư mục độc lập để tránh Race Condition
        session_id = f"SESSION_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        session_dir = os.path.join(os.getcwd(), OUTPUT_DIR, session_id)
    os.makedirs(session_dir, exist_ok=True)
    raw_dir = os.path.join(session_dir, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    raw_manifest = os.path.join(raw_dir, "README.md")
    if not os.path.exists(raw_manifest):
        with open(raw_manifest, "w", encoding="utf-8") as f:
            f.write(
                "# PenLabs Raw Tool Output\n\n"
                "This directory stores raw artifacts from external tools for manual analysis.\n\n"
                "- Crawler output is stored under tool-specific folders such as `katana_*`.\n"
                "- Scanner output is stored under folders such as `nuclei_*`, `httpx_*`, `ffuf_*`.\n"
                "- Files are intentionally kept after scans; do not treat raw output as deduplicated findings.\n"
            )

    if getattr(args, "tor_route", False):
        tor_proxy_file = os.path.join(session_dir, "tor_proxy.txt")
        with open(tor_proxy_file, "w", encoding="utf-8") as f:
            f.write("socks5h://127.0.0.1:9050\n")
        args.proxy_file = tor_proxy_file
        args.proxy = ""
        os.environ["TOR_ROUTE"] = "true"
        print(f"{YELLOW}[TOR] TOR-ROUTE enabled — proxy file: {tor_proxy_file}{RESET}")
    else:
        os.environ["TOR_ROUTE"] = "false"
    
    # V1.0: Khởi tạo Checkpoint Manager
    ckpt = CheckpointManager(session_dir=session_dir, session_id=session_id, target=target)
    if ckpt.is_resuming:
        print(f"\n{CYAN}[Checkpoint] Detected previous progress:{RESET}")
        print(ckpt.get_summary())
        resume_point = ckpt.get_resume_point()
        if resume_point:
            print(f"{GREEN}[Checkpoint] Will resume from: {resume_point}{RESET}")
        else:
            print(f"{GREEN}[Checkpoint] Pipeline already completed!{RESET}")
            sys.exit(0)

    # V1.0: Khởi tạo Circuit Breaker
    cb = CircuitBreaker(max_failures=3, reset_timeout=300)

    # ══════════════════════════════════════════════════════════════
    # V1.0: DATABASE INITIALIZATION
    # ══════════════════════════════════════════════════════════════
    db_session_id = None   # DB ScanSession.id (for DiffEngine)
    db_project_id = None   # DB Project.id
    db_url = getattr(args, 'db_url', '') or ''
    if ensure_db_loaded():
        try:
            init_db(db_url)
            with get_session(db_url) as db_sess:
                # Get or create project
                project_name = getattr(args, 'project', '') or f"PenLabs-{target}"
                project_slug = re.sub(r'[^a-z0-9]+', '-', project_name.lower()).strip('-')
                db_project = get_or_create_project(
                    db_sess, name=project_name, slug=project_slug,
                    in_scope=[target],
                )
                db_project_id = db_project.id

                # Create ScanSession record
                db_scan = ScanSession(
                    project_id=db_project_id,
                    session_uid=session_id,
                    target=target,
                    profile=mode,
                    status=ScanStatus.RUNNING.value,
                    session_dir=session_dir,
                )
                db_sess.add(db_scan)
                db_sess.flush()
                db_session_id = db_scan.id

            print(f"{GREEN}[DB] ✅ Database initialized — Project: {project_slug} | Session #{db_session_id}{RESET}")
        except Exception as _db_init_err:
            print(f"{YELLOW}[DB] ⚠️  Database init failed (falling back to JSON-only): {_db_init_err}{RESET}")
            _HAS_DB = False

    # Bật tính năng Debug Logging nếu có cờ --debug
    if args.debug:
        debug_log_path = os.path.join(session_dir, "debug.log")
        sys.stdout = TeeLogger(sys.stdout, debug_log_path)
        sys.stderr = TeeLogger(sys.stderr, debug_log_path)
        print(f"{GREEN}[*] Debug Mode Enabled: Lưu log ngầm tại {debug_log_path}{RESET}")

    print(f"{YELLOW}[*] Không gian làm việc (Session Dir): {session_dir}{RESET}")

    # ==============================================================
    # BƯỚC 1: MODULE 1 - RECONNAISSANCE
    # ==============================================================
    # ══════════════════════════════════════════════════════════════
    # V1.0: ORIGIN FINDER — Chạy trước Module 1 nếu được bật
    # ══════════════════════════════════════════════════════════════
    if getattr(args, 'origin_finder', False) and _HAS_ORIGIN:
        print(f"\n{CYAN}{'='*60}{RESET}")
        print(f"{CYAN}[ORIGIN-FINDER] Đang tìm kiếm Origin IP cho {target}...{RESET}")
        print(f"{CYAN}{'='*60}{RESET}")
        try:
            origin_cls = get_origin_discovery_engine()
            if not origin_cls:
                raise RuntimeError("OriginDiscoveryEngine unavailable")
            origin_engine = origin_cls()
            origin_result = origin_engine.discover(target)
            if origin_result.get("origin_ip"):
                print(f"{GREEN}[ORIGIN-FINDER] ⚠️  ORIGIN IP: {origin_result['origin_ip']}{RESET}")
                print(f"{GREEN}[ORIGIN-FINDER] Method: {origin_result['method']} | Confidence: {origin_result['confidence']}%{RESET}")
                # Lưu kết quả vào session
                origin_out = os.path.join(session_dir, "origin_discovery.json")
                with open(origin_out, 'w') as f:
                    json.dump(origin_result, f, indent=2, default=str)
                print(f"{YELLOW}[ORIGIN-FINDER] Kết quả lưu tại: {origin_out}{RESET}")

                #  Trích xuất subdomain để làm seed cho Module 1
                origin_subs = origin_result.get("subdomains", [])
                if origin_subs:
                    seed_file = os.path.join(session_dir, "origin_subdomains.txt")
                    with open(seed_file, 'w') as f:
                        f.write("\n".join(origin_subs))
                    # Lưu vào args để Module 1 sử dụng
                    args.seed_subs = seed_file
                    print(f"{GREEN}[ORIGIN-FINDER] ✅ Seeded {len(origin_subs)} subdomains for Module 1.{RESET}")

                # V1.0: API-BREACH mode → auto-switch target to Origin IP
                if mode == 'api-breach' and origin_result.get("confidence", 0) >= 85:
                    original_target = target
                    target = origin_result["origin_ip"]
                    print(f"{RED}[API-BREACH] ⚡ TARGET SWITCHED: {original_target} → {target} (Direct Origin){RESET}")
                    print(f"{YELLOW}[API-BREACH] Pipeline sẽ bypass CDN/WAF, đánh thẳng Origin.{RESET}")
            else:
                print(f"{YELLOW}[ORIGIN-FINDER] Không xác nhận được Origin IP.{RESET}")
                if origin_result.get("favicon_hash"):
                    print(f"{YELLOW}[ORIGIN-FINDER] Thử Shodan: http.favicon.hash:{origin_result['favicon_hash']}{RESET}")
        except Exception as e:
            print(f"{RED}[ORIGIN-FINDER] Lỗi: {e}{RESET}")

    # V1.0: INFRA-SMASH mode → InternetDB passive port map
    if mode == 'infra-smash' and _HAS_ORIGIN:
        try:
            from plugins.shodan_internetdb_plugin import InternetDBPlugin
            idb = InternetDBPlugin()
            import socket as _sock
            try:
                target_ip = _sock.gethostbyname(target)
            except _sock.gaierror:
                target_ip = target
            idb_result = idb.lookup(target_ip)
            if idb_result.get("ports"):
                print(f"{CYAN}[INFRA-SMASH] InternetDB Passive Ports: {idb_result['ports']}{RESET}")
                if idb_result.get("vulns"):
                    print(f"{RED}[INFRA-SMASH] Known Vulns: {', '.join(idb_result['vulns'][:10])}{RESET}")
                idb_out = os.path.join(session_dir, "internetdb_passive.json")
                with open(idb_out, 'w') as f:
                    json.dump(idb_result, f, indent=2, default=str)
            else:
                print(f"{YELLOW}[INFRA-SMASH] InternetDB: Không có dữ liệu passive cho {target_ip}.{RESET}")
        except Exception as e:
            print(f"{YELLOW}[INFRA-SMASH] InternetDB lookup error: {e}{RESET}")

    m1_json = os.path.join(session_dir, "m1_recon.json")

    if ckpt.should_skip("MODULE_1_RECON"):
        print(f"{GREEN}[Checkpoint] ⏭️  MODULE 1 already completed, using cached m1_recon.json{RESET}")
    else:
        cmd_m1 = [
            sys.executable, MODULE_1_SCRIPT,
            target,
            "--outdir", session_dir,
            "--output", m1_json,
            "--mode", mode
        ]
        
        # [V1.0] Forward new core options
        if getattr(args, 'proxy_file', None):
            cmd_m1.extend(["--proxy-file", args.proxy_file])
        if getattr(args, 'tor_route', False):
            cmd_m1.append("--tor-route")
        if getattr(args, 'auth_config', None):
            cmd_m1.extend(["--auth-config", args.auth_config])
        if getattr(args, 'use_playwright', False):
            cmd_m1.append("--use-playwright")
        if getattr(args, 'sqlmap_relay', False):
            cmd_m1.append("--sqlmap-relay")
        if getattr(args, 'bola_engine', False):
            cmd_m1.append("--bola-engine")
        if getattr(args, 'chunk_size', 20) != 20:
            cmd_m1.extend(["--chunk-size", str(args.chunk_size)])
        if getattr(args, 'seed_subs', None):
            cmd_m1.extend(["--seed-subs", args.seed_subs])
            
        if args.vt_key:
            cmd_m1.extend(["--vt-key", args.vt_key])
        elif Config.VT_API_KEY:
            cmd_m1.extend(["--vt-key", Config.VT_API_KEY])
            
        # [V1.0] Hunter.how API removed — replaced by OWASP Amass + theHarvester (free, no API key needed)
        if Config.CHAOS_KEY:
            cmd_m1.extend(["--chaos-key", Config.CHAOS_KEY])
        
        # Truyền blacklist vào Module 1
        if args.blacklist:
            cmd_m1.extend(["--blacklist", args.blacklist])
        if args.proxy:
            cmd_m1.extend(["--proxy", args.proxy])
        if args.stealth_recon or getattr(Config, "STEALTH_RECON_ENABLED", False):
            cmd_m1.append("--stealth-recon")
        if getattr(args, 'subdomain_scan', True):
            cmd_m1.append("--subdomain-scan")
        else:
            cmd_m1.append("--no-subdomain-scan")
        if not getattr(args, 'stealth_discovery', True):
            cmd_m1.append("--no-stealth-discovery")
        if not getattr(args, 'osint_enabled', True):
            cmd_m1.append("--no-osint")
        cmd_m1.extend(["--rate-limit", str(args.rate_limit)])
        if args.delay:
            cmd_m1.extend(["--delay", str(args.delay)])
        if args.debug:
            cmd_m1.append("--debug")
            
        if getattr(args, 'visual_recon', False):
            cmd_m1.append("--visual-recon")
        
        # [FIX-REVIEW-2] Forward --cookie and --header to Module 1 (authenticated scan)
        if getattr(args, 'cookie', ''):
            cmd_m1.extend(["--cookie", args.cookie])
        if getattr(args, 'header', None):
            for h in args.header:
                cmd_m1.extend(["--header", h])
        
        # [V1.0] Forward BOLA args to Module 1
        if getattr(args, 'auth_userA', ''):
            cmd_m1.extend(["--auth-userA", args.auth_userA])
        if getattr(args, 'auth_userB', ''):
            cmd_m1.extend(["--auth-userB", args.auth_userB])

        # V1.0: Forward unified mode (from profile or legacy) to Module 1
        cmd_m1.extend(["--mode", mode])
        if mode == 'infra-smash':
            cmd_m1.append("--use-internetdb")
            
        if args.permissive:
            cmd_m1.append("--permissive")
            if getattr(args, 'confirm_permissive', False):
                cmd_m1.append("--confirm-permissive")

        if not run_command("MODULE 1 (RECON)", cmd_m1):
            ckpt.mark_failed("MODULE_1_RECON", "Module 1 returned non-zero exit code")
            cb.record_failure("MODULE_1_RECON", "exit code != 0")
            sys.exit(1)

        if not os.path.exists(m1_json):
            ckpt.mark_failed("MODULE_1_RECON", "m1_recon.json not found")
            print(f"{RED}[!] Không tìm thấy cấu trúc JSON đầu ra của Module 1. Huỷ chuỗi.{RESET}")
            sys.exit(1)

        # V1.0: Mark M1 completed
        cb.record_success("MODULE_1_RECON")
        ckpt.mark_completed("MODULE_1_RECON", metadata={"output": m1_json})

    # ── [P0-1] SCHEMA VALIDATION GATE: M1 Output ──────────────────────────
    if ensure_schema_loaded():
        try:
            _m1_validated, _m1_warnings = validate_m1_output(m1_json, strict=False)
            if _m1_warnings:
                print(f"{YELLOW}[SCHEMA] M1 output: {len(_m1_warnings)} validation warning(s){RESET}")
                for _w in _m1_warnings[:3]:
                    print(f"  {YELLOW}⚠ {_w[:120]}{RESET}")
            else:
                print(f"{GREEN}[SCHEMA] ✓ M1 output validated: {len(_m1_validated)} assets{RESET}")
        except SchemaValidationError as _se:
            print(f"{RED}[SCHEMA] ✗ M1 output validation FAILED: {_se}{RESET}")
            logging.error(f"[SCHEMA] M1 validation failure: {_se.errors}")

    # ══════════════════════════════════════════════════════════════
    # V1.0: INGEST M1 RESULTS INTO DATABASE (Diff Engine)
    # ══════════════════════════════════════════════════════════════
    diff_report = None
    if ensure_db_loaded() and db_project_id and db_session_id:
        try:
            with open(m1_json, "r") as _m1f:
                m1_raw_data = json.load(_m1f)

            diff_engine = DiffEngine(project_id=db_project_id, scan_session_id=db_session_id)
            with get_session(db_url) as db_sess:
                diff_report = diff_engine.ingest_recon_results(db_sess, m1_raw_data)

            if diff_report.has_changes:
                print(f"{GREEN}[DB] 🔍 Diff Engine: {diff_report.summary}{RESET}")
            else:
                print(f"{YELLOW}[DB] Diff Engine: No new discoveries (all assets already known).{RESET}")
        except Exception as _db_ingest_err:
            print(f"{YELLOW}[DB] ⚠️  Data ingestion warning: {_db_ingest_err}{RESET}")

    # ==============================================================
    # V1.0 — DUAL-CHANNEL DATA PIPELINE
    # ==============================================================
    # Tách dữ liệu từ M1 thành 2 luồng:
    #   Channel 1 (Infrastructure): Ports, versions, banners → M2 CPE Filter
    #   Channel 2 (Web Logic Flaws): XSS, SSRF, CORS, Secrets, Error Endpoints
    #                                → Bypass M2, ghi thẳng vào report
    # ==============================================================
    web_logic_findings = []
    try:
        with open(m1_json, "r") as _mf:
            m1_data_raw = json.load(_mf)
            m1_data = m1_data_raw[0] if isinstance(m1_data_raw, list) and len(m1_data_raw) > 0 else (m1_data_raw if isinstance(m1_data_raw, dict) else {})

        # --- Extract Web Logic Flaws từ M1 output ---
        # Dalfox XSS findings
        xss_findings = m1_data.get("xss_findings", [])
        for xss in xss_findings:
            web_logic_findings.append({
                "type": "XSS",
                "severity": xss.get("severity", "medium").upper(),
                "url": xss.get("url", ""),
                "param": xss.get("param", ""),
                "payload": xss.get("payload", ""),
                "source": "Dalfox",
            })

        # SSRF findings (đã được precision-filter ở V1.0)
        ssrf_findings = m1_data.get("ssrf_findings", [])
        for ssrf in ssrf_findings:
            web_logic_findings.append({
                "type": "SSRF",
                "severity": ssrf.get("severity", "HIGH"),
                "url": ssrf.get("url", ""),
                "param": ssrf.get("param", ""),
                "evidence": ssrf.get("evidence", ""),
                "source": "SSRFProbe",
            })

        # CORS misconfigurations
        cors_findings = m1_data.get("cors_findings", [])
        for cors in cors_findings:
            web_logic_findings.append({
                "type": "CORS_Misconfiguration",
                "severity": cors.get("severity", "medium").upper(),
                "url": cors.get("url", ""),
                "details": cors.get("details", ""),
                "source": "Corsy",
            })

        # Secrets from LinkFinder
        secrets = m1_data.get("secrets", [])
        for sec in secrets:
            web_logic_findings.append({
                "type": "Hardcoded_Secret",
                "severity": "HIGH",
                "url": sec.get("source", ""),
                "details": f"{sec.get('type', 'unknown')}: {sec.get('value', '')[:40]}...",
                "source": "LinkFinder",
            })

        # Katana vulnerable endpoints (HTTP 500/403/401)
        vuln_eps = m1_data.get("vulnerable_endpoints", [])
        for ep in vuln_eps:
            web_logic_findings.append({
                "type": "Error_Endpoint",
                "severity": "MEDIUM" if ep.get("status_code") in (403, 401) else "HIGH",
                "url": ep.get("url", ""),
                "details": f"HTTP {ep.get('status_code', '?')} — {ep.get('method', 'GET')}",
                "source": "Katana",
            })

        # Open Redirect findings
        open_redir = m1_data.get("open_redirect_findings", [])
        for redir in open_redir:
            web_logic_findings.append({
                "type": "Open_Redirect",
                "severity": redir.get("severity", "MEDIUM"),
                "url": redir.get("url", ""),
                "details": redir.get("evidence", ""),
                "source": "OpenRedirect",
            })

        # BOLA/IDOR findings
        bola_findings = m1_data.get("bola_findings", [])
        for bola in bola_findings:
            web_logic_findings.append({
                "type": "BOLA_IDOR",
                "severity": "HIGH",
                "url": bola.get("url", ""),
                "details": bola.get("evidence", ""),
                "source": "BOLAEngine",
            })

        # GraphQL findings
        graphql_findings = m1_data.get("graphql_findings", [])
        for gql in graphql_findings:
            web_logic_findings.append({
                "type": "GraphQL_Exposure",
                "severity": gql.get("severity", "high").upper(),
                "url": gql.get("url", ""),
                "details": gql.get("details", ""),
                "source": "GraphQLProbe",
            })

        # CRLF findings
        crlf_findings = m1_data.get("crlf_findings", [])
        for crlf in crlf_findings:
            web_logic_findings.append({
                "type": "CRLF_Injection",
                "severity": crlf.get("severity", "MEDIUM"),
                "url": crlf.get("url", ""),
                "details": crlf.get("evidence", ""),
                "source": "CRLF",
            })

        if web_logic_findings:
            print(f"\n{GREEN}[+] V1.0 DUAL-CHANNEL: {len(web_logic_findings)} Web Logic Flaws extracted → Bypass M2 CPE Filter{RESET}")
            # Lưu Web Logic Flaws vào file riêng
            web_logic_path = os.path.join(session_dir, "web_logic_findings.json")
            with open(web_logic_path, "w") as _wf:
                json.dump(web_logic_findings, _wf, indent=2, default=str)
            print(f"    📋 Saved: {web_logic_path}")
        else:
            print(f"{YELLOW}[*] V1.0 DUAL-CHANNEL: No Web Logic Flaws extracted from M1 output.{RESET}")

    except Exception as _e:
        print(f"{YELLOW}[!] V1.0 Pipeline split warning: {_e}{RESET}")

    # ══════════════════════════════════════════════════════════════
    # V1.0: RECURSIVE SUBDOMAIN DEEP SCAN
    # Quét sâu M2 + Origin Finder + JS-Exposure trên mỗi live subdomain
    # ══════════════════════════════════════════════════════════════
    def _get_recursive_max(m: str) -> int:
        """Dynamic cap theo mode — full-audit cho phép scan rộng hơn."""
        caps = {
            "stealth": 20,
            "sniper": 50,
            "web-vuln": 50,
            "cloud-devops": 30,
            "full-audit": 200,
            "api-bounty": 100,
            "api-breach": 100,
            "cloud-native": 50,
            "infra-smash": 30,
            "asset-discovery": 100,
        }
        return caps.get(m, 50)

    RECURSIVE_MAX = _get_recursive_max(mode)

    recursive_sub_enabled = getattr(args, 'recursive_sub', False)
    if recursive_sub_enabled:
        live_subdomains = []
        try:
            with open(m1_json, "r") as _rsf:
                _rs_data = json.load(_rsf)
                _rs_data = _rs_data[0] if isinstance(_rs_data, list) and _rs_data else (_rs_data if isinstance(_rs_data, dict) else {})

            # Trích xuất live subdomains từ httpx results
            httpx_results = _rs_data.get("httpx_results", [])
            if httpx_results:
                for entry in httpx_results:
                    host = ""
                    if isinstance(entry, dict):
                        host = entry.get("host", entry.get("url", entry.get("input", "")))
                    elif isinstance(entry, str):
                        host = entry
                    # Clean URL → domain
                    host = host.strip()
                    if "://" in host:
                        host = host.split("://", 1)[1]
                    host = host.split("/")[0].split(":")[0].strip()
                    if host and host != target and "." in host:
                        live_subdomains.append(host)

            # Fallback: subdomains list
            if not live_subdomains:
                subs = _rs_data.get("subdomains", [])
                for s in subs:
                    s = s.strip().lstrip("*.")
                    if s and s != target and "." in s:
                        live_subdomains.append(s)

            # Deduplicate + cap
            live_subdomains = list(dict.fromkeys(live_subdomains))[:RECURSIVE_MAX]

        except Exception as _rse:
            print(f"{YELLOW}[RECURSIVE] Lỗi đọc M1 data: {_rse}{RESET}")

        if live_subdomains:
            print(f"\n{CYAN}╔{'═'*62}╗{RESET}")
            print(f"{CYAN}║  🔄 RECURSIVE SUBDOMAIN DEEP SCAN — {len(live_subdomains)} targets{' '*(22 - len(str(len(live_subdomains))))}║{RESET}")
            print(f"{CYAN}╚{'═'*62}╝{RESET}")

            recursive_results_dir = os.path.join(session_dir, "recursive_scans")
            os.makedirs(recursive_results_dir, exist_ok=True)
            # Run parallel subdomain scans using the async driver
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

            if loop.is_running():
                import nest_asyncio
                nest_asyncio.apply()
                results = loop.run_until_complete(
                    _scan_all_subdomains_async(live_subdomains, recursive_results_dir, mode, args, _HAS_ORIGIN)
                )
            else:
                results = asyncio.run(
                    _scan_all_subdomains_async(live_subdomains, recursive_results_dir, mode, args, _HAS_ORIGIN)
                )

            recursive_summary = [r for r in results if isinstance(r, dict)]

            # ── Summary Report ──
            print(f"\n{CYAN}╔{'═'*62}╗{RESET}")
            print(f"{CYAN}║  📊 RECURSIVE SCAN SUMMARY{' '*36}║{RESET}")
            print(f"{CYAN}╠{'═'*62}╣{RESET}")
            total_findings = 0
            origins_found = 0
            for rs in recursive_summary:
                origin_tag = f"{GREEN}→ {rs['origin_ip']}{RESET}" if rs['origin_ip'] else f"{YELLOW}N/A{RESET}"
                findings_tag = f"{GREEN}{rs['m2_findings']}{RESET}" if rs['m2_findings'] else f"{YELLOW}0{RESET}"
                print(f"{CYAN}║{RESET}  {rs['subdomain']:<35} Origin: {origin_tag} Findings: {findings_tag}")
                total_findings += rs['m2_findings']
                if rs['origin_ip']:
                    origins_found += 1
            print(f"{CYAN}╠{'═'*62}╣{RESET}")
            print(f"{CYAN}║{RESET}  Subdomains: {len(recursive_summary)} | Origins: {origins_found} | Total Findings: {total_findings}")
            print(f"{CYAN}╚{'═'*62}╝{RESET}")

            # Lưu summary
            summary_path = os.path.join(recursive_results_dir, "recursive_summary.json")
            with open(summary_path, "w") as _sf:
                json.dump(recursive_summary, _sf, indent=2, default=str)
            print(f"{YELLOW}[RECURSIVE] Summary lưu tại: {summary_path}{RESET}")

            # ══════════════════════════════════════════════════════════════
            # V1.0-FIX: INGEST RECURSIVE SCAN RESULTS INTO DATABASE
            # Walks all recursive_scans/*/m1_recon.json + m2_vuln.json
            # and feeds them through DiffEngine → penlabs.db
            # ══════════════════════════════════════════════════════════════
            if ensure_db_loaded() and db_project_id and db_session_id:
                try:
                    recursive_db_assets = 0
                    recursive_db_vulns = 0
                    recursive_diff = DiffEngine(project_id=db_project_id, scan_session_id=db_session_id)

                    with get_session(db_url) as db_sess:
                        for rs in recursive_summary:
                            sub_dir = os.path.join(
                                recursive_results_dir,
                                rs['subdomain'].replace('.', '_')
                            )

                            # Ingest M1 recon data (subdomains, IPs, endpoints)
                            sub_m1 = os.path.join(sub_dir, "m1_recon.json")
                            if os.path.exists(sub_m1):
                                try:
                                    with open(sub_m1, "r") as _rm1f:
                                        sub_m1_data = json.load(_rm1f)
                                    sub_diff = recursive_diff.ingest_recon_results(db_sess, sub_m1_data)
                                    if sub_diff and sub_diff.has_changes:
                                        recursive_db_assets += len(getattr(sub_diff, 'new_assets', []))
                                except Exception as _rm1e:
                                    logging.debug(f"[DB-RECURSIVE] M1 ingest error for {rs['subdomain']}: {_rm1e}")

                            # Ingest M2 vuln data (CVEs, findings)
                            sub_m2 = os.path.join(sub_dir, "m2_vuln.json")
                            if os.path.exists(sub_m2):
                                try:
                                    with open(sub_m2, "r") as _rm2f:
                                        sub_m2_data = json.load(_rm2f)
                                    attack_entries = sub_m2_data if isinstance(sub_m2_data, list) else sub_m2_data.get("attack_plan", [])
                                    for entry in attack_entries:
                                        from core.db import upsert_vulnerability
                                        _, is_new = upsert_vulnerability(
                                            db_sess,
                                            project_id=db_project_id,
                                            vuln_type=entry.get("cve", "UNKNOWN"),
                                            evidence_url=entry.get("matched_at", entry.get("target", "")),
                                            name=entry.get("cve", ""),
                                            severity=entry.get("severity", "medium"),
                                            confidence=entry.get("confidence", 0.5),
                                            matched_at=entry.get("matched_at", ""),
                                            reporter_tool=entry.get("match_source", "M2-VulnAnalysis"),
                                            reporter_source="Recursive-Scan",
                                        )
                                        if is_new:
                                            recursive_db_vulns += 1
                                except Exception as _rm2e:
                                    logging.debug(f"[DB-RECURSIVE] M2 ingest error for {rs['subdomain']}: {_rm2e}")

                    if recursive_db_assets or recursive_db_vulns:
                        print(f"{GREEN}[DB] ✅ Recursive scans ingested: {recursive_db_assets} new assets, {recursive_db_vulns} new vulns.{RESET}")
                    else:
                        print(f"{YELLOW}[DB] Recursive scans: no new data to ingest.{RESET}")
                except Exception as _db_rec_err:
                    print(f"{YELLOW}[DB] ⚠️  Recursive DB ingestion warning: {_db_rec_err}{RESET}")

        else:
            print(f"{YELLOW}[RECURSIVE] Không tìm thấy live subdomains để quét sâu.{RESET}")

    # ==============================================================
    # BƯỚC 2: MODULE 2 - VULNERABILITY ANALYSIS (Infrastructure Channel Only)
    # ==============================================================
    m2_json = os.path.join(session_dir, "m2_vuln.json")

    if ckpt.should_skip("MODULE_2_VULN_ANALYSIS"):
        print(f"{GREEN}[Checkpoint] ⏭️  MODULE 2 already completed, using cached m2_vuln.json{RESET}")
    else:
        cmd_m2 = [
            sys.executable, MODULE_2_SCRIPT, 
            "--m1-json", m1_json, 
            "--output", m2_json
        ]
        if args.debug:
            cmd_m2.append("--debug")

        if not run_command("MODULE 2 (VULN ANALYSIS)", cmd_m2):
            ckpt.mark_failed("MODULE_2_VULN_ANALYSIS", "Module 2 returned non-zero exit code")
            cb.record_failure("MODULE_2_VULN_ANALYSIS", "exit code != 0")
            sys.exit(1)

        # === V1.0: Inject Web Logic Flaws vào M2 output ===
        # Cho dù M2 CPE Filter lọc hết, logic flaws vẫn được giữ nguyên
        if os.path.exists(m2_json) and web_logic_findings:
            try:
                with open(m2_json, "r") as _m2f:
                    m2_data = json.load(_m2f)

                # Inject web logic findings vào attack_plan
                attack_plan = m2_data.get("attack_plan", [])
                for wlf in web_logic_findings:
                    attack_plan.append({
                        "cve": f"WEB-LOGIC-{wlf['type']}",
                        "target": wlf.get("url", ""),
                        "severity": wlf.get("severity", "MEDIUM"),
                        "description": f"[{wlf['source']}] {wlf['type']}: {wlf.get('details', wlf.get('payload', ''))}",
                        "source": wlf.get("source", "M1-Direct"),
                        "bypass_m2": True,  # Đánh dấu bypass
                    })

                m2_data["attack_plan"] = attack_plan
                m2_data["web_logic_findings_count"] = len(web_logic_findings)

                with open(m2_json, "w") as _m2f:
                    json.dump(m2_data, _m2f, indent=2, default=str)

                print(f"{GREEN}[+] V1.0: Injected {len(web_logic_findings)} logic flaws vào M2 attack_plan.{RESET}")
            except Exception as _ie:
                print(f"{YELLOW}[!] V1.0 injection warning: {_ie}{RESET}")

        if not os.path.exists(m2_json):
            ckpt.mark_failed("MODULE_2_VULN_ANALYSIS", "m2_vuln.json not found")
            print(f"{RED}[!] Không tìm thấy Kế Hoạch Tấn Công (Attack Plan) từ Module 2.{RESET}")
            sys.exit(1)

        # V1.0: Mark M2 completed
        cb.record_success("MODULE_2_VULN_ANALYSIS")
        ckpt.mark_completed("MODULE_2_VULN_ANALYSIS", metadata={"output": m2_json})

    # ── [P0-1] SCHEMA VALIDATION GATE: M2 Output ──────────────────────────
    if ensure_schema_loaded():
        try:
            _m2_validated, _m2_warnings = validate_m2_output(m2_json, strict=False)
            if _m2_warnings:
                print(f"{YELLOW}[SCHEMA] M2 attack plan: {len(_m2_warnings)} validation warning(s){RESET}")
                for _w in _m2_warnings[:3]:
                    print(f"  {YELLOW}⚠ {_w[:120]}{RESET}")
            else:
                _vuln_count = len(_m2_validated)
                print(f"{GREEN}[SCHEMA] ✓ M2 attack plan validated: {_vuln_count} entries{RESET}")
                if _vuln_count == 0:
                    print(f"{YELLOW}[SCHEMA] ⚠ M2 produced 0 valid attack plan entries — check tool output formats{RESET}")
        except SchemaValidationError as _se:
            print(f"{RED}[SCHEMA] ✗ M2 attack plan validation FAILED: {_se}{RESET}")
            logging.error(f"[SCHEMA] M2 validation failure: {_se.errors}")

    if args.no_msf:
        print(f"\n{YELLOW}[!] Đã bỏ qua MODULE 3 theo tuỳ chọn --no-msf.{RESET}")

        print(f"🏁 QUY TRÌNH KIỂM THỬ HOÀN TẤT DƯỚI SESSION UID: {session_id}!")
        sys.exit(0)

    # Hỏi user trước khi gọi M3 nếu chế độ interactive
    if args.interactive and not args.no_interactive:
        print(f"\n{YELLOW}=================================================================={RESET}")
        print(f"{YELLOW}🗲 Module 1 & 2 đã hoàn tất! Mục tiêu đã được dựng rạp tấn công.{RESET}")
        ans = input(f"{YELLOW}👉 Bạn có muốn mở INTERACTIVE MSF MENU (Module 3) không? (Y/n): {RESET}").strip().lower()
        if ans == 'n':
            print(f"\n{BLUE}[*] Thoát an toàn. Kế hoạch M2 lưu tại: {m2_json}{RESET}")
            sys.exit(0)

    # ==============================================================
    # 4. CHẠY MODULE 3 (EXECUTIONER)
    # ==============================================================
    print(f"\n{CYAN}[+] ĐANG CHẠY: MODULE 3 (EXECUTIONER INTERACTIVE MENU)...{RESET}")
    cmd_m3 = [
        sys.executable, MODULE_3_SCRIPT,
        "--plan", m2_json,
        "--session-dir", session_dir
    ]
    if getattr(args, 'stealth', False):
        cmd_m3.append("--stealth")
    
    if args.auto_exploit:
        cmd_m3.append("--auto-exploit")
        
    if args.debug:
        cmd_m3.append("--debug")
    
    # Đối với Interactive Menu, ta chạy trực tiếp thay vì ghi log ẩn
    # Nhưng nếu đang ở Debug + Interactive thì Popen có thể mất input() stream
    print(f"    CMD: {' '.join(cmd_m3)}")
    try:
        if args.debug and not args.interactive:
            # Nếu chạy debug + non-interactive thì dùng run_command để ghi log
            run_command("MODULE 3 (EXECUTIONER)", cmd_m3)
        else:
            subprocess.run(cmd_m3)
    except Exception as e:
        print(f"{RED}[✘] Lỗi khi chạy MODULE 3: {e}{RESET}")

    # ==============================================================
    # [V1.0] MODULE 4 — POST-EXPLOITATION (tự động khi có sessions)
    # ==============================================================
    # [FIX] Đọc lại session password mà M3 đã sinh (random) để M4 có thể auth
    msfrpc_pass_file = os.path.join(session_dir, ".msfrpc_session_pass")
    if os.path.exists(msfrpc_pass_file):
        try:
            with open(msfrpc_pass_file, 'r') as pf:
                session_rpc_pass = pf.read().strip()
            if session_rpc_pass:
                Config.MSF_RPC_PASS = session_rpc_pass
                os.environ["MSF_RPC_PASS"] = session_rpc_pass
                if args.debug:
                    print(f"{YELLOW}[*] Đã load MSFRPC session password từ M3 cho M4.{RESET}")
        except Exception:
            pass

    try:
        from scripts.Module4_PostExploit import PostExploitEngine
        post_dir = os.path.join(session_dir, "post_exploit")
        # [V1.0] Session Isolation: truyền target IP để M4 chỉ tương tác session khớp mục tiêu
        # Resolve domain → IP nếu cần
        import socket
        try:
            target_ip_resolved = socket.gethostbyname(target)
        except socket.gaierror:
            target_ip_resolved = target  # Fallback: dùng nguyên string nếu resolve fail
        post_engine = PostExploitEngine(post_dir, target_ip=target_ip_resolved)
        if post_engine.connect():
            sessions = post_engine.list_sessions()
            if sessions:
                print(f"\n{CYAN}[+] MODULE 4: Post-Exploitation — {len(sessions)} sessions available.{RESET}")
                if args.interactive:
                    post_engine.interactive_menu()
                else:
                    # Auto mode: enumerate all sessions
                    for sid in sessions:
                        post_engine.enumerate_system(int(sid))
                        post_engine.check_privesc(int(sid))
                
                # [V1.0] Auto-Persistence khi cờ --persist được bật
                if getattr(args, 'persist', False):
                    print(f"\n{YELLOW}[*] PERSISTENCE FLAG ENABLED — Auto-deploying backdoors...{RESET}")
                    for sid in sessions:
                        try:
                            post_engine.establish_persistence(int(sid), force_auto=True)
                        except Exception as pe:
                            print(f"{RED}[!] Persistence failed for session #{sid}: {pe}{RESET}")
    except ImportError:
        pass
    except Exception as e:
        print(f"{YELLOW}[!] Module 4 skipped: {e}{RESET}")
    finally:
        # [F-09 FIX] Cleanup .msfrpc_session_pass — plaintext credential should not persist
        if os.path.exists(msfrpc_pass_file):
            try:
                os.remove(msfrpc_pass_file)
                if args.debug:
                    print(f"{YELLOW}[*] Cleaned up MSFRPC session password file.{RESET}")
            except OSError:
                pass

    # ==============================================================
    # [V1.0] REPORT GENERATION — Auto-generate HTML report
    # ==============================================================
    try:
        from core.registry import PluginRegistry as _PR
        report_plugin = _PR.get("ReportGenerator")
        if report_plugin and os.path.exists(m2_json):
            print(f"\n{CYAN}[+] Generating pentest report...{RESET}")
            # [V1.0] Truyền screenshots_dir cho report nếu Visual Recon đã bật
            screenshots_dir = ""
            if getattr(args, 'visual_recon', False):
                screenshots_dir = os.path.join(session_dir, "screenshots")
                if not os.path.exists(screenshots_dir):
                    # Tìm trong raw/gowitness/screenshots
                    raw_ss = os.path.join(session_dir, "raw", "gowitness", "screenshots")
                    if os.path.exists(raw_ss):
                        screenshots_dir = raw_ss
                    else:
                        raw_ss2 = os.path.join(session_dir, "raw", "gowitness_full", "screenshots")
                        if os.path.exists(raw_ss2):
                            screenshots_dir = raw_ss2
            report_path = report_plugin.run(
                m2_json_path=m2_json,
                out_dir=session_dir,
                target=target,
                mode=args.mode,
                screenshots_dir=screenshots_dir,
            )
            print(f"{GREEN}[+] ✓ Report saved: {report_path}{RESET}")
    except Exception as e:
        print(f"{YELLOW}[!] Report generation skipped: {e}{RESET}")

    # V1.0: Mark report generation completed
    ckpt.mark_completed("REPORT_GENERATION")
    ckpt.mark_pipeline_complete()

    # V1.0: Print Circuit Breaker summary
    print(f"\n{CYAN}{cb.summary()}{RESET}")
    print(f"\n{CYAN}{ckpt.get_summary()}{RESET}")

    # ══════════════════════════════════════════════════════════════
    # V1.0: FINALIZE DATABASE SESSION
    # ══════════════════════════════════════════════════════════════
    if ensure_db_loaded() and db_session_id:
        try:
            with get_session(db_url) as db_sess:
                db_scan = db_sess.query(ScanSession).filter_by(id=db_session_id).first()
                if db_scan:
                    db_scan.status = ScanStatus.COMPLETED.value
                    db_scan.ended_at = datetime.now()
                    # Count totals
                    db_scan.total_assets = db_sess.query(Asset).filter_by(project_id=db_project_id).count()
                    from core.db import Vulnerability as VulnModel
                    db_scan.total_vulns = db_sess.query(VulnModel).filter_by(project_id=db_project_id).count()

            print(f"{GREEN}[DB] ✅ Session #{db_session_id} finalized — "
                  f"{db_scan.total_assets} assets, {db_scan.total_vulns} vulns in DB.{RESET}")

            # Print Diff summary if available
            if diff_report and diff_report.has_changes:
                print(f"{GREEN}[DB] 📊 Discovery Summary: {diff_report.summary}{RESET}")
        except Exception as _db_final_err:
            print(f"{YELLOW}[DB] ⚠️  DB finalization warning: {_db_final_err}{RESET}")

    # ══════════════════════════════════════════════════════════════
    # V1.0: TERMINAL DASHBOARD
    # ══════════════════════════════════════════════════════════════
    if getattr(args, 'dashboard', False):
        if not ensure_dashboard_loaded():
            print(f"{YELLOW}[Dashboard] Terminal Dashboard module not loaded.{RESET}")
        else:
            dashboard = TerminalDashboard()
            
            # Khởi tạo Default Metrics phòng khi không dùng DB
            db_stats = {
                "target": target,
                "subdomains": len(discovered_subdomains) if 'discovered_subdomains' in locals() else 0,
                "endpoints": len(live_ips) if 'live_ips' in locals() else 0,
                "js_files": 0,
            }
            vulns_list = []

            if ensure_db_loaded() and db_session_id:
                try:
                    with get_session(db_url) as sess:
                        # Extract metrics
                        db_stats["subdomains"] = sess.query(Asset).filter_by(project_id=db_project_id, asset_type='subdomain').count()
                        db_stats["endpoints"] = sess.query(Asset).filter_by(project_id=db_project_id, asset_type='ip').count()
                        db_stats["js_files"] = sess.query(Asset).filter_by(project_id=db_project_id, asset_type='javascript').count()
                        
                        # Extract Vulns (Limit 30)
                        from core.db import Vulnerability as VulnModel
                        recent_vulns = sess.query(VulnModel).filter_by(project_id=db_project_id).order_by(VulnModel.id.desc()).limit(30)
                        for v in recent_vulns:
                            vulns_list.append({
                                "name": v.name,
                                "severity": v.severity,
                                "matched_at": v.matched_at
                            })
                except Exception as e:
                    print(f"{YELLOW}[Dashboard] Error fetching DB stats: {e}{RESET}")

            dashboard.print_scan_summary(target, session_id, db_stats, vulns_list)

    if audit_logger:
        audit_logger.log("CLI", "SCAN_COMPLETED", target, f"session={session_id}")

    print(f"\n{GREEN}🏁 QUY TRÌNH KIỂM THỬ HOÀN TẤT DƯỚI SESSION UID: {session_id}!{RESET}")

if __name__ == "__main__":
    main()
