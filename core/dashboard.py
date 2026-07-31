import os
import json
import re
import unicodedata
from typing import Dict, List, Any
from core.terminal_ui import (
    border as _terminal_border,
    display_width as _terminal_display_width,
    frame_line as _terminal_frame_line,
    strip_ansi as _terminal_strip_ansi,
    truncate_display as _terminal_truncate_display,
)
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich.markdown import Markdown
from rich.align import Align
from rich import box

class TerminalDashboard:
    """
    PenLabs V1.0 — Terminal Dashboard
    Renders live scan statistics and final AI reports in a beautiful
    terminal UI using 'rich', mimicking reNgine's dashboard.
    """

    def __init__(self):
        self.console = Console()

    def print_scan_summary(self, target: str, session_id: str, db_stats: Dict[str, Any], vulnerabilities: List[Dict[str, Any]]):
        """Displays the high-level metrics of the scan."""
        
        # Breakdown vulnerabilities by severity
        severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for v in vulnerabilities:
            sev = str(v.get("severity", "info")).lower()
            if sev in severities:
                severities[sev] += 1
            else:
                severities["info"] += 1

        # Create Stats Table
        stats_table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=False, expand=True)
        stats_table.add_column("Metric", style="cyan", ratio=1)
        stats_table.add_column("Value", style="bold white", ratio=1)
        
        stats_table.add_row("🎯 Target", target)
        stats_table.add_row("🆔 Session", session_id)
        stats_table.add_row("🌐 Subdomains", str(db_stats.get('subdomains', 0)))
        stats_table.add_row("🔌 Live Endpoints", str(db_stats.get('endpoints', 0)))
        stats_table.add_row("📜 JS Files Analyzed", str(db_stats.get('js_files', 0)))
        
        # Create Vulnerability Breakdown Table
        vuln_table = Table(box=box.MINIMAL_DOUBLE_HEAD, show_header=True, expand=True)
        vuln_table.add_column("Severity", style="bold")
        vuln_table.add_column("Count", justify="right")
        
        vuln_table.add_row("[bold red]CRITICAL[/]", str(severities["critical"]))
        vuln_table.add_row("[bold orange3]HIGH[/]", str(severities["high"]))
        vuln_table.add_row("[bold yellow]MEDIUM[/]", str(severities["medium"]))
        vuln_table.add_row("[bold blue]LOW[/]", str(severities["low"]))
        vuln_table.add_row("[bold grey74]INFO[/]", str(severities["info"]))

        # Build Layout panels
        from rich.columns import Columns
        grid = Columns([
            Panel(stats_table, title="[bold cyan]Scan Execution Metrics[/]", border_style="cyan"),
            Panel(vuln_table, title="[bold red]Vulnerability Breakdown[/]", border_style="red")
        ], expand=True)

        self.console.print("\n")
        self.console.print(Panel(grid, title="[bold white]PenLabs V1.0 — Scan Complete[/]", border_style="green", padding=(1, 2)))


    def print_new_discovery(self, asset_type: str, value: str, source: str):
        """Print a live discovery in a nice formatted line."""
        color = "green"
        icon = "🎯"
        if asset_type == "vulnerability":
            color = "red"
            icon = "🔥"
        elif asset_type == "subdomain":
            color = "cyan"
            icon = "🌐"
        
        self.console.print(f"[{color}][{icon} New {asset_type.upper()}][/] {value} (via {source})")


# ══════════════════════════════════════════════════════════════
# TACTICAL OPTIONS MENU V5 — Standalone renderer (ANSI only)
# Không phụ thuộc vào rich, chạy trên bất kỳ terminal nào.
# ══════════════════════════════════════════════════════════════

_GREEN  = "\033[92m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_YELLOW = "\033[93m"
_BLUE   = "\033[94m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_RST    = "\033[0m"

_ANSI_RE = re.compile(r"\x1B\[[0-9;]*[mK]")


def _strip_ansi(text: str) -> str:
    return _terminal_strip_ansi(text)


def _display_width(text: str) -> int:
    return _terminal_display_width(text)


def _truncate_display(text: str, max_width: int) -> str:
    return _terminal_truncate_display(text, max_width)


def _frame_line(content: str, width: int = 86) -> str:
    return _terminal_frame_line(content, width, _CYAN, _RST)


def _border(kind: str, width: int = 86) -> str:
    return _terminal_border(kind, width, _CYAN, _RST)

# Định nghĩa 4 Khối Chiến Thuật
# Mỗi entry: (label, attr_name, description, kind, block_id)
#   kind: None=bool toggle, "value"=prompt, "path"=prompt file
#   block_id: 1=Stealth, 2=Exploit, 3=Compliance, 4=RedTeam
TACTICAL_OPTIONS = [
    # ── BLOCK 1: STEALTH & EVASION ──
    ("ORIGIN-FINDER", "origin_finder", "Tìm IP gốc (Origin) đứng sau CDN/WAF",            None,    1, ["api-breach", "web-vuln", "api-bounty"]),
    ("JA3-SPOOF",     "ja3_spoof",     "Giả mạo TLS Fingerprint qua curl_cffi",            None,    1, ["asset-discovery", "api-breach", "stealth", "web-vuln", "api-bounty", "continuous"]),
    ("TOR-ROUTE",     "tor_route",     "Ép HTTP tooling hỗ trợ proxy qua Tor SOCKS5 local", None,   1, None),
    ("PROXY-POOL",    "proxy_file",    "📂 Tải danh sách proxy (proxies.txt)",              "path",  1, None),
    ("RATE-LIMIT",    "rate_limit",    "⏳ HTTP Requests/giây (khuyến nghị ≤ 10)",          "value", 1, None),
    ("DELAY",         "delay",         "⏸️  Delay tĩnh giữa gói tin (500ms, 2s...)",       "value", 1, None),
    ("STEALTH",       "stealth",       "🥷 Full Stealth: Evasion + Recon im lặng",          None,    1, None),
    ("STEALTH-RECON", "stealth_recon", "WAF bypass + subdomain hunting (Subfinder/Chaos)",  None,    1, ["asset-discovery", "cloud-native", "api-bounty", "web-vuln", "stealth"]),

    # ── BLOCK 2: EXPLOIT & AUDIT ──
    ("SPA-ENGINE", "use_playwright", "🎭 Quét ứng dụng SPA (Playwright Chromium)",        None,    2, ["sniper", "infra-smash", "full-audit", "api-bounty"]),
    ("SMART-SQLI",  "sqlmap_relay",   "🔗 Ép SQLMap đi qua StealthNet Proxy Relay",       None,    2, ["api-bounty"]),
    ("RESUME-CHUNKS",    "chunk_size",    "📦 Chia nhỏ mục tiêu để Resume (VD: 20)",           "value", 2, ["infra-smash", "sniper", "web-vuln", "full-audit", "api-bounty"]),
    ("BOLA-ENGINE",   "bola_engine",   "Kiểm tra IDOR/Broken Access Control",              None,    2, ["api-bounty", "api-breach"]),
    ("VISUAL-RECON",  "visual_recon",  "📸 Chụp screenshot bằng chứng (gowitness)",         None,    2, ["web-vuln", "api-bounty", "full-audit"]),
    ("RECURSIVE-SUB", "recursive_sub", "🔄 Quét sâu M2 trên TẤT CẢ live subdomains (max 50)",  None,    2, ["asset-discovery", "full-audit", "continuous"]),

    # ── BLOCK 3: COMPLIANCE & SETUP ──
    ("SCOPE-ENFORCE", "scope_enforce", "Cấm quét ngoài scope file (Tắt = Permissive)",     None,    3, None),
    ("SCOPE",         "scope",         "📂 Tải file scope (giới hạn target)",               "path",  3, None),
    ("AUTH-VAULT",   "auth_config",   "🔑 File cấu hình Login (auto-refresh token)",       "path",  3, None),
    ("COOKIE",        "cookie",        "HTTP Cookie (VD: 'PHPSESSID=abc')",                 "value", 3, ["asset-discovery", "api-breach", "web-vuln", "api-bounty", "continuous", "sniper", "infra-smash", "full-audit"]),
    ("HEADER",        "header_input",  "📋 Custom Header (VD: 'Authorization: Bearer x')",   "value", 3, ["asset-discovery", "api-breach", "web-vuln", "api-bounty", "continuous", "sniper", "infra-smash", "full-audit"]),
    ("AUTH-USER-A",   "auth_userA",    "Token User A (BOLA Engine)",                        "value", 3, ["api-bounty", "api-breach"]),
    ("AUTH-USER-B",   "auth_userB",    "Token User B (BOLA Engine)",                        "value", 3, ["api-bounty", "api-breach"]),
    ("PROJECT",       "project",       "Tên chiến dịch (VD: HackerOne-Yahoo)",              "value", 3, None),
    ("BLACKLIST",     "blacklist",     "Tải file blacklist IP/Domain",                     "path",  3, None),
    ("DASHBOARD",     "dashboard",     "📊 Rich Terminal UI Metrics cuối buổi",             None,    3, None),
    ("DEBUG",         "debug",         "In full log & lưu debug.log",                       None,    3, None),
    ("DRY-RUN",       "dry_run",       "Xem Trước Pipeline (Không bắn gói tin)",            None,    3, None),
    ("NO-MSF",        "no_msf",        "Bỏ qua Module 3 (không gọi Metasploit)",            None,    3, None),

    # ── BLOCK 4: RED TEAM — DANGER ZONE ──
    ("AUTO-EXPLOIT",  "auto_exploit",  "Tự pick CVE & khai thác tự động sau M2",            None,    4, ["infra-smash", "full-audit", "api-bounty"]),
    ("PERSISTENCE",   "persist",       "Cấy backdoor SSH/Cron/Registry sau shell",           None,    4, ["infra-smash", "full-audit"]),
    ("NO-EDR-CHECK",  "no_edr_check",  "Tắt EDR Dry-Run check trước exploit",               None,    4, ["infra-smash", "full-audit"]),
]


BLOCK_HEADERS = {
    1: ("🛡️  STEALTH & EVASION (Tàng hình & Vượt tường)", _CYAN),
    2: ("🎯 EXPLOIT & AUDIT (Khai thác & Kiểm toán)",     _BLUE),
    3: ("⚙️  COMPLIANCE & SETUP (Pháp lý & Cấu hình)",    _YELLOW),
    4: ("☠️  RED TEAM — DANGER ZONE",                      _RED),
}


MENU_DEFAULTS = {
    "origin_finder": False,
    "ja3_spoof": True,
    "tor_route": False,
    "proxy_file": None,
    "rate_limit": 150,
    "delay": "",
    "stealth": False,
    "stealth_recon": False,
    "use_playwright": False,
    "sqlmap_relay": False,
    "chunk_size": 20,
    "bola_engine": False,
    "visual_recon": False,
    "recursive_sub": False,
    "scope_enforce": True,
    "scope": None,
    "auth_config": None,
    "cookie": "",
    "header_input": None,
    "auth_userA": "",
    "auth_userB": "",
    "project": "",
    "blacklist": None,
    "dashboard": False,
    "debug": False,
    "dry_run": False,
    "no_msf": False,
    "auto_exploit": False,
    "persist": False,
    "no_edr_check": False,
}


MODE_PRESETS = {
    "asset-discovery": {
        "ja3_spoof": True,
        "stealth_recon": True,
        "recursive_sub": True,
        "chunk_size": 20,
    },
    "web-vuln": {
        "ja3_spoof": True,
        "visual_recon": True,
        "chunk_size": 20,
    },
    "api-bounty": {
        "ja3_spoof": True,
        "sqlmap_relay": True,
        "bola_engine": True,
        "visual_recon": True,
        "chunk_size": 20,
        "no_msf": True,
    },
    "api-breach": {
        "origin_finder": True,
        "ja3_spoof": True,
        "recursive_sub": True,
        "bola_engine": True,
        "no_msf": True,
    },
    "cloud-native": {
        "stealth_recon": True,
        "chunk_size": 20,
    },
    "infra-smash": {
        "use_playwright": True,
        "chunk_size": 20,
        "visual_recon": True,
    },
    "sniper": {
        "chunk_size": 20,
    },
    "stealth": {
        "stealth": True,
        "stealth_recon": True,
        "ja3_spoof": True,
        "rate_limit": 50,
        "delay": "500ms",
    },
    "full-audit": {
        "use_playwright": True,
        "visual_recon": True,
        "chunk_size": 20,
    },
    "continuous": {
        "ja3_spoof": True,
        "recursive_sub": True,
    },
}


GOAL_PRESETS = {
    "bounty": {
        "label": "Bug Bounty",
        "description": "Web/API bounty, logic flaws, low-risk exploit path",
        "dangerous": False,
        "settings": {
            "ja3_spoof": True,
            "visual_recon": True,
            "sqlmap_relay": True,
            "bola_engine": True,
            "chunk_size": 20,
            "no_msf": True,
        },
    },
    "auth-web": {
        "label": "Authenticated Web App",
        "description": "Session-aware web testing with browser coverage",
        "dangerous": False,
        "settings": {
            "ja3_spoof": True,
            "use_playwright": True,
            "visual_recon": True,
            "chunk_size": 20,
            "scope_enforce": True,
        },
    },
    "stealth-ext": {
        "label": "Stealth External",
        "description": "Low-noise external recon against WAF/CDN targets",
        "dangerous": False,
        "settings": {
            "stealth": True,
            "stealth_recon": True,
            "ja3_spoof": True,
            "rate_limit": 25,
            "delay": "750ms",
            "no_msf": True,
        },
    },
    "internal-rt": {
        "label": "Internal Red Team",
        "description": "Aggressive internal chain with exploit/persistence path",
        "dangerous": True,
        "settings": {
            "use_playwright": True,
            "visual_recon": True,
            "chunk_size": 20,
            "auto_exploit": True,
            "persist": True,
            "no_edr_check": False,
        },
    },
    "recon-only": {
        "label": "Recon Only",
        "description": "Enumerate assets safely without exploit handoff",
        "dangerous": False,
        "settings": {
            "ja3_spoof": True,
            "recursive_sub": True,
            "visual_recon": True,
            "no_msf": True,
            "auto_exploit": False,
            "persist": False,
        },
    },
}


MODE_METADATA = {
    "asset-discovery": {"engagement": "Recon", "noise": "LOW", "runtime": "MED"},
    "web-vuln": {"engagement": "Auth Web", "noise": "MED", "runtime": "MED"},
    "api-bounty": {"engagement": "Bounty", "noise": "MED", "runtime": "HIGH"},
    "api-breach": {"engagement": "Origin/API", "noise": "MED", "runtime": "MED"},
    "cloud-native": {"engagement": "Cloud", "noise": "MED", "runtime": "MED"},
    "infra-smash": {"engagement": "Red Team", "noise": "HIGH", "runtime": "HIGH"},
    "sniper": {"engagement": "Balanced", "noise": "LOW", "runtime": "LOW"},
    "stealth": {"engagement": "Low Noise", "noise": "LOW", "runtime": "MED"},
    "full-audit": {"engagement": "Deep", "noise": "HIGH", "runtime": "HIGH"},
    "continuous": {"engagement": "Continuous", "noise": "HIGH", "runtime": "HIGH"},
    "cloud-devops": {"engagement": "Cloud DevOps", "noise": "MED", "runtime": "HIGH"},
}

GOAL_PRESET_SHORTCUTS = {
    "b": "bounty",
    "w": "auth-web",
    "s": "stealth-ext",
    "i": "internal-rt",
    "r": "recon-only",
}

TACTICAL_PRESET_DIR = os.path.join("output", "tactical_presets")


def _recommended_attrs_for_mode(mode: str) -> set[str]:
    return set(MODE_PRESETS.get(str(mode or "").lower(), {}).keys())


def _colorize_level(level: str) -> str:
    normalized = str(level or "").upper()
    color = _GREEN if normalized == "LOW" else (_YELLOW if normalized == "MED" else _RED)
    return f"{color}{normalized}{_RST}"


def _level_to_score(level: str) -> int:
    normalized = str(level or "").upper()
    return {"LOW": 1, "MED": 2, "HIGH": 3}.get(normalized, 2)


def _score_to_level(score: int) -> str:
    if score <= 1:
        return "LOW"
    if score == 2:
        return "MED"
    return "HIGH"


def _estimate_menu_posture(args) -> dict:
    mode = str(getattr(args, "mode", "") or "").lower()
    meta = MODE_METADATA.get(mode, {"engagement": "Custom", "noise": "MED", "runtime": "MED"})
    noise_score = _level_to_score(meta["noise"])
    runtime_score = _level_to_score(meta["runtime"])

    if getattr(args, "stealth", False):
        noise_score -= 1
        runtime_score += 1
    if getattr(args, "tor_route", False):
        noise_score -= 1
        runtime_score += 1
    if getattr(args, "delay", ""):
        runtime_score += 1
        noise_score -= 1
    if int(getattr(args, "rate_limit", 150) or 150) <= 25:
        noise_score -= 1
        runtime_score += 1
    if getattr(args, "recursive_sub", False):
        noise_score += 1
        runtime_score += 1
    if getattr(args, "visual_recon", False) or getattr(args, "use_playwright", False):
        runtime_score += 1
    if getattr(args, "debug", False):
        runtime_score += 1
    if getattr(args, "auto_exploit", False):
        noise_score += 1
        runtime_score += 1
    if getattr(args, "persist", False):
        noise_score += 1
        runtime_score += 1
    if getattr(args, "dry_run", False):
        noise_score = 1

    noise_score = max(1, min(3, noise_score))
    runtime_score = max(1, min(3, runtime_score))
    return {
        "engagement": meta["engagement"],
        "noise": _score_to_level(noise_score),
        "runtime": _score_to_level(runtime_score),
    }


def _estimate_menu_coverage(args, active_options=None) -> dict:
    mode = str(getattr(args, "mode", "") or "").lower()
    base_score = {
        "asset-discovery": 58,
        "web-vuln": 64,
        "api-bounty": 70,
        "api-breach": 66,
        "cloud-native": 60,
        "infra-smash": 72,
        "sniper": 50,
        "stealth": 48,
        "full-audit": 82,
        "continuous": 74,
        "cloud-devops": 68,
    }.get(mode, 60)

    if active_options is None:
        active_options = []
        for opt in TACTICAL_OPTIONS:
            label, attr, desc, kind, block_id, allowed_modes = opt
            if allowed_modes is None or (mode and mode in allowed_modes):
                active_options.append(opt)

    active_count = 0
    for _, attr, _, kind, _, _ in active_options:
        value = getattr(args, attr, None)
        if kind in ("path", "value"):
            if value not in (None, "", False):
                active_count += 1
        elif bool(value):
            active_count += 1

    score = base_score
    score += min(active_count * 2, 12)
    if getattr(args, "auth_config", None) or getattr(args, "cookie", "") or getattr(args, "header_input", None):
        score += 6
    if getattr(args, "visual_recon", False):
        score += 4
    if getattr(args, "recursive_sub", False):
        score += 5
    if getattr(args, "bola_engine", False):
        score += 5
    if getattr(args, "use_playwright", False):
        score += 4
    if getattr(args, "origin_finder", False):
        score += 3
    if getattr(args, "auto_exploit", False):
        score += 4
    if getattr(args, "dry_run", False):
        score -= 18
    if getattr(args, "stealth", False) and not getattr(args, "recursive_sub", False):
        score -= 4

    score = max(25, min(95, score))
    if score < 55:
        band = "LIGHT"
    elif score < 75:
        band = "BALANCED"
    else:
        band = "DEEP"
    return {"score": score, "band": band}


def _menu_lock_reason(args, attr: str):
    mode = str(getattr(args, "mode", "") or "").lower()
    if attr == "origin_finder" and mode == "api-breach":
        return "required in API-BREACH"
    if attr == "proxy_file" and getattr(args, "tor_route", False):
        return "TOR-ROUTE overrides proxy pool"
    if attr == "no_msf" and (getattr(args, "auto_exploit", False) or getattr(args, "persist", False)):
        return "conflicts with exploit path"
    if attr == "no_edr_check" and not (getattr(args, "auto_exploit", False) or getattr(args, "persist", False)):
        return "enable exploit path first"
    return None


def _set_menu_value(args, attr: str, value):
    setattr(args, attr, value)
    if attr == "scope_enforce":
        args.permissive = not value


def _project_preset_key(args) -> str:
    project = str(getattr(args, "project", "") or "").strip()
    mode = str(getattr(args, "mode", "") or "default").strip().lower()
    raw = project or f"mode-{mode}"
    slug = re.sub(r"[^a-z0-9]+", "-", raw.lower()).strip("-")
    return slug or f"mode-{mode}"


def _tactical_preset_path(args) -> str:
    return os.path.join(TACTICAL_PRESET_DIR, f"{_project_preset_key(args)}.json")


def _collect_tactical_state(args, active_options) -> dict:
    state = {}
    for _, attr, _, kind, _, _ in active_options:
        value = getattr(args, attr, None)
        if kind in ("path", "value"):
            if value not in (None, "", False):
                state[attr] = value
        else:
            state[attr] = bool(value)
    return state


def _save_project_preset(args, active_options):
    os.makedirs(TACTICAL_PRESET_DIR, exist_ok=True)
    payload = {
        "project_key": _project_preset_key(args),
        "project": str(getattr(args, "project", "") or ""),
        "mode": str(getattr(args, "mode", "") or ""),
        "saved_options": _collect_tactical_state(args, active_options),
    }
    path = _tactical_preset_path(args)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=True, sort_keys=True)
    print(f"{_GREEN}  [+] Tactical preset đã lưu: {path}{_RST}")


def _load_project_preset(args, active_options, path: str | None = None):
    path = path or _tactical_preset_path(args)
    if not os.path.exists(path):
        print(f"{_YELLOW}  [i] Chưa có preset cho key '{_project_preset_key(args)}'.{_RST}")
        return
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    saved_options = payload.get("saved_options", {})
    active_attrs = {opt[1] for opt in active_options}
    for attr, value in saved_options.items():
        if attr in active_attrs or hasattr(args, attr):
            _set_menu_value(args, attr, value)
    _apply_menu_guardrails(args)
    print(f"{_GREEN}  [+] Tactical preset đã nạp: {path}{_RST}")


def _list_saved_presets() -> list[dict]:
    if not os.path.isdir(TACTICAL_PRESET_DIR):
        return []
    presets = []
    for name in sorted(os.listdir(TACTICAL_PRESET_DIR)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(TACTICAL_PRESET_DIR, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                payload = json.load(fh)
        except Exception:
            payload = {}
        presets.append({
            "name": name,
            "path": path,
            "project_key": payload.get("project_key", name[:-5]),
            "project": payload.get("project", ""),
            "mode": payload.get("mode", ""),
            "option_count": len(payload.get("saved_options", {}) or {}),
        })
    return presets


def _render_preset_catalog():
    presets = _list_saved_presets()
    print(f"{_CYAN}  Saved Tactical Presets:{_RST}")
    if not presets:
        print(f"{_DIM}    (empty){_RST}")
        return presets
    for idx, item in enumerate(presets, start=1):
        project = item["project"] or "-"
        mode = str(item["mode"] or "-").upper()
        print(
            f"    {_YELLOW}[{idx}]{_RST} {item['project_key']:<20} "
            f"mode={mode:<14} opts={item['option_count']:<2} project={project}"
        )
    print(f"{_DIM}    Commands: <n>=load | d <n>=delete | r <n> <new-key>=rename | Enter=back{_RST}")
    return presets


def _rename_saved_preset(path: str, new_key: str):
    safe_key = re.sub(r"[^a-z0-9]+", "-", str(new_key or "").strip().lower()).strip("-")
    if not safe_key:
        print(f"{_RED}  [!] Tên preset mới không hợp lệ.{_RST}")
        return
    new_path = os.path.join(TACTICAL_PRESET_DIR, f"{safe_key}.json")
    if os.path.exists(new_path) and os.path.abspath(new_path) != os.path.abspath(path):
        print(f"{_YELLOW}  [i] Preset '{safe_key}' đã tồn tại.{_RST}")
        return
    with open(path, "r", encoding="utf-8") as fh:
        payload = json.load(fh)
    payload["project_key"] = safe_key
    with open(new_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=True, sort_keys=True)
    if os.path.abspath(new_path) != os.path.abspath(path):
        os.remove(path)
    print(f"{_GREEN}  [+] Đã đổi tên preset thành: {safe_key}{_RST}")


def _delete_saved_preset(path: str):
    if not os.path.exists(path):
        print(f"{_YELLOW}  [i] Preset không còn tồn tại.{_RST}")
        return
    os.remove(path)
    print(f"{_GREEN}  [+] Đã xóa preset: {os.path.basename(path)}{_RST}")


def _open_preset_catalog(args, active_options):
    import re as _re

    while True:
        presets = _render_preset_catalog()
        raw = input(f"{_YELLOW}  ➢ Preset catalog: {_RST}").strip()
        if not raw:
            return
        parts = _re.split(r"[\s,]+", raw)
        cmd = parts[0].lower()
        if cmd.isdigit():
            idx = int(cmd)
            if not (1 <= idx <= len(presets)):
                print(f"{_RED}  [!] Preset index không hợp lệ.{_RST}")
                continue
            _load_project_preset(args, active_options, presets[idx - 1]["path"])
            return
        if cmd == "d" and len(parts) >= 2 and parts[1].isdigit():
            idx = int(parts[1])
            if not (1 <= idx <= len(presets)):
                print(f"{_RED}  [!] Preset index không hợp lệ.{_RST}")
                continue
            confirm = input(f"{_RED}  [CONFIRM] Xóa preset {presets[idx - 1]['project_key']}? Gõ YES: {_RST}").strip()
            if confirm == "YES":
                _delete_saved_preset(presets[idx - 1]["path"])
            else:
                print(f"{_YELLOW}  [i] Hủy xóa preset.{_RST}")
            continue
        if cmd == "r" and len(parts) >= 3 and parts[1].isdigit():
            idx = int(parts[1])
            if not (1 <= idx <= len(presets)):
                print(f"{_RED}  [!] Preset index không hợp lệ.{_RST}")
                continue
            _rename_saved_preset(presets[idx - 1]["path"], parts[2])
            continue
        print(f"{_YELLOW}  [i] Cú pháp: <n> | d <n> | r <n> <new-key>{_RST}")


def _apply_mode_preset(args, active_options, preset_name: str = "recommended"):
    mode = str(getattr(args, "mode", "") or "").lower()
    preset = MODE_PRESETS.get(mode, {})
    if not preset:
        print(f"{_YELLOW}  [i] Không có preset cho mode này.{_RST}")
        return
    active_attrs = {opt[1] for opt in active_options}
    for attr, value in preset.items():
        if attr in active_attrs or hasattr(args, attr):
            setattr(args, attr, value)
    print(f"{_GREEN}  [+] Đã áp dụng preset {preset_name} cho mode {mode}.{_RST}")


def _apply_goal_preset(args, active_options, preset_key: str):
    preset = GOAL_PRESETS.get(preset_key)
    if not preset:
        print(f"{_RED}  [!] Goal preset không hợp lệ.{_RST}")
        return
    if preset.get("dangerous"):
        confirm = input(f"{_RED}  [CONFIRM] {preset['label']} sẽ bật exploit/persistence path. Gõ YES để tiếp tục: {_RST}").strip()
        if confirm != "YES":
            print(f"{_YELLOW}  [i] Đã hủy áp dụng goal preset nguy hiểm.{_RST}")
            return
    active_attrs = {opt[1] for opt in active_options}
    for attr, value in preset["settings"].items():
        if attr in active_attrs or hasattr(args, attr):
            setattr(args, attr, value)
    print(f"{_GREEN}  [+] Đã áp dụng goal preset: {preset['label']}.{_RST}")


def _reset_menu_options(args, active_options):
    active_attrs = {opt[1] for opt in active_options}
    for attr in active_attrs:
        if attr in MENU_DEFAULTS:
            setattr(args, attr, MENU_DEFAULTS[attr])
    print(f"{_YELLOW}  [i] Đã reset các tactical options về mặc định an toàn.{_RST}")


def _apply_menu_guardrails(args):
    mode = str(getattr(args, "mode", "") or "").lower()
    if getattr(args, "persist", False) and not getattr(args, "auto_exploit", False):
        args.auto_exploit = True
        print(f"{_YELLOW}  [Guardrail] PERSISTENCE yêu cầu AUTO-EXPLOIT — đã tự bật.{_RST}")
    if getattr(args, "tor_route", False) and getattr(args, "proxy_file", None):
        args.proxy_file = None
        print(f"{_YELLOW}  [Guardrail] TOR-ROUTE override PROXY-POOL — đã xóa proxy_file trong menu.{_RST}")
    if getattr(args, "auto_exploit", False) and getattr(args, "no_msf", False):
        args.no_msf = False
        print(f"{_YELLOW}  [Guardrail] AUTO-EXPLOIT xung đột với NO-MSF — đã tắt NO-MSF.{_RST}")
    if getattr(args, "bola_engine", False) and mode in ("api-bounty", "api-breach"):
        if not getattr(args, "auth_userA", ""):
            print(f"{_YELLOW}  [Hint] BOLA-ENGINE hiệu quả hơn khi có AUTH-USER-A và AUTH-USER-B.{_RST}")
    if mode == "api-breach" and not getattr(args, "origin_finder", False):
        args.origin_finder = True
        print(f"{_YELLOW}  [Guardrail] API-BREACH tự bật ORIGIN-FINDER.{_RST}")


def _render_goal_presets():
    print(f"{_CYAN}  Goal Presets:{_RST}")
    ordered = [
        ("1/B", "bounty"),
        ("2/W", "auth-web"),
        ("3/S", "stealth-ext"),
        ("4/I", "internal-rt"),
        ("5/R", "recon-only"),
    ]
    for key, preset_id in ordered:
        preset = GOAL_PRESETS[preset_id]
        print(f"    {_YELLOW}[{key}]{_RST} {preset['label']:<20} {preset['description']}")


def render_tactical_review(args):
    mode = str(getattr(args, "mode", "") or "").lower()
    posture = _estimate_menu_posture(args)
    coverage = _estimate_menu_coverage(args)
    preset_key = _project_preset_key(args)
    width = 86
    print("\n" + _border("top", width))
    title = f"🧾 TACTICAL REVIEW ({mode.upper() if mode else 'UNKNOWN'})"
    print(_frame_line(f"  {_BOLD}{title}{_RST}", width))
    print(_border("mid", width))
    summary = (
        f"  Profile={posture['engagement']} | Noise={posture['noise']} | Runtime={posture['runtime']} | "
        f"Coverage={coverage['score']}%/{coverage['band']} | PresetKey={preset_key} | "
        f"ExploitPath={'ON' if getattr(args, 'auto_exploit', False) else 'OFF'}"
    )
    print(_frame_line(f"  {_truncate_display(summary, width - 2)}", width))
    print(_border("sep", width))

    active_options = []
    for label, attr, desc, kind, block_id, allowed_modes in TACTICAL_OPTIONS:
        if allowed_modes is None or (mode and mode in allowed_modes):
            value = getattr(args, attr, None)
            if kind in ("path", "value"):
                if value not in (None, "", False):
                    active_options.append((block_id, label, str(value)))
            else:
                if bool(value):
                    active_options.append((block_id, label, "ON"))

    if not active_options:
        print(_frame_line(f"  {_DIM}Không có tactical option nào đang bật cho mode hiện tại.{_RST}", width))
        print(_border("bottom", width))
        return

    current_block = 0
    for block_id, label, value in active_options:
        if block_id != current_block:
            current_block = block_id
            header_text, header_color = BLOCK_HEADERS[block_id]
            if block_id > 1:
                print(_border("sep", width))
            print(_frame_line(f"  {header_color}{_BOLD}{header_text}{_RST}", width))
            print(_border("sep", width))

        line = f"  {_GREEN}•{_RST} {label:<18} {value}"
        print(_frame_line(line, width))

    print(_border("bottom", width))


def _render_menu_frame(args):
    """Vẽ khung menu Tactical Options V5 ra terminal và trả về các option hoạt động."""
    W = 86
    print("\n" + _border("top", W))
    
    # Hiển thị mode hiện tại
    mode_str = getattr(args, 'mode', 'UNKNOWN').upper()
    posture = _estimate_menu_posture(args)
    title = f"⚡ TACTICAL OPTIONS ({mode_str})"
    print(_frame_line(f"  {_BOLD}{title}{_RST}", W))
    print(_border("mid", W))

    current_mode = getattr(args, 'mode', None)
    active_options = []
    recommended_attrs = _recommended_attrs_for_mode(current_mode)
    
    # Filter options based on mode
    for opt in TACTICAL_OPTIONS:
        label, attr, desc, kind, block_id, allowed_modes = opt
        if allowed_modes is None or (current_mode and current_mode in allowed_modes):
            active_options.append(opt)

    active_count = 0
    for _, attr, _, kind, _, _ in active_options:
        value = getattr(args, attr, None)
        if kind in ("path", "value"):
            if value not in (None, "", False):
                active_count += 1
        elif bool(value):
            active_count += 1

    coverage = _estimate_menu_coverage(args, active_options)
    preset_key = _project_preset_key(args)
    meta_line = (
        f"  Profile={posture['engagement']} | Noise={_colorize_level(posture['noise'])} | "
        f"Runtime={_colorize_level(posture['runtime'])} | Coverage={coverage['score']}%/{coverage['band']} | "
        f"Active={active_count}/{len(active_options)}"
    )
    print(_frame_line(f"  {_truncate_display(meta_line, W - 2)}", W))
    preset_line = f"  PresetKey={preset_key} | Save={_GREEN}K{_RST} | Load={_GREEN}L{_RST} | Catalog={_GREEN}P{_RST}"
    print(_frame_line(f"  {_truncate_display(preset_line, W - 2)}", W))
    print(_frame_line(f"  {_DIM}No = noise | Risky flags are grouped under DANGER block{_RST}", W))
    print(_border("sep", W))
    header = (
        f"  {_DIM}{'No':<4} {'State':<8} {'Flag':<7} {'Option':<18} {'Detail':<41}{_RST}"
    )
    print(_frame_line(header, W))
    print(_border("sep", W))

    current_block = 0
    idx = 0
    for label, attr, desc, kind, block_id, allowed_modes in active_options:
        if block_id != current_block:
            current_block = block_id
            header_text, header_color = BLOCK_HEADERS[block_id]
            if block_id > 1:
                print(_border("sep", W))
            print(_frame_line(f"  {header_color}{_BOLD}{header_text}{_RST}", W))
            print(_border("sep", W))

        idx += 1
        cur = getattr(args, attr, None)

        if kind in ("path", "value"):
            if cur and str(cur):
                val_str = str(cur)
                display = val_str[:25] + "…" if len(val_str) > 25 else val_str
                state = f"{_GREEN}[{display}]{_RST}"
            else:
                state = f"{_DIM}[OFF]{_RST}"
        else:
            state = f"{_GREEN}[ON]{_RST} " if cur else f"{_DIM}[OFF]{_RST}"

        label_color = _RED if block_id == 4 else _CYAN
        lock_reason = _menu_lock_reason(args, attr)
        if lock_reason:
            flag = f"{_YELLOW}LOCK{_RST}"
        elif block_id == 4:
            flag = f"{_RED}DANGER{_RST}"
        elif attr in recommended_attrs:
            flag = f"{_GREEN}REC{_RST}"
        else:
            flag = f"{_DIM}-{_RST}"
        num = f"{_YELLOW}{idx:>2}{_RST}"
        detail = lock_reason or desc
        detail = _truncate_display(detail, 41)
        line_raw = (
            f"  {num:<4} {state:<8} {flag:<7} {label_color}{label:<18}{_RST} {detail}"
        )
        print(_frame_line(line_raw, W))
        if lock_reason:
            note = f"     {_DIM}↳ currently enforced by mode/guardrail{_RST}"
            print(_frame_line(note, W))

    print(_border("mid", W))
    mode_hint = (
        f"Preset mode: {_GREEN}R{_RST}=Recommended | {_GREEN}G{_RST}=Goal preset | "
        f"{_GREEN}B/W/S/I/R{_RST}=Quick preset | {_GREEN}K/L/P{_RST}=Preset ops | {_YELLOW}C{_RST}=Clear | {_CYAN}H{_RST}=Help"
    )
    print(_frame_line(f"  {_YELLOW}Gõ số cách nhau bởi dấu cách để bật/tắt, Enter = xác nhận{_RST}", W))
    print(_frame_line(f"  {_truncate_display(mode_hint, W - 2)}", W))
    print(_border("bottom", W))
    
    return active_options


def render_interactive_menu(args):
    """
    Hiển thị Tactical Options Menu V5 và xử lý input toggle.
    Gọi hàm này từ main.py thay vì pick_options().
    Trả về args đã được cập nhật.
    """
    import re as _re

    # Khởi tạo các attr mới nếu chưa có
    for attr, default in [
        ("origin_finder", False), ("ja3_spoof", True),
        ("tor_route", False),
        ("proxy_file", None),
        ("use_playwright", False), ("sqlmap_relay", False),
        ("chunk_size", 20),
        ("recursive_sub", False),
        ("auth_config", None),
    ]:
        if not hasattr(args, attr):
            setattr(args, attr, default)
            
    if not hasattr(args, 'scope_enforce'):
        args.scope_enforce = not getattr(args, 'permissive', False)

    while True:
        active_options = _render_menu_frame(args)
        total = len(active_options)
        
        raw = input(f"{_YELLOW}✔ Lựa chọn (1-{total}) hoặc Enter để tiếp tục: {_RST}").strip()
        if not raw:
            break
        cmd = raw.lower()
        if cmd == "r":
            _apply_mode_preset(args, active_options)
            continue
        if cmd == "c":
            _reset_menu_options(args, active_options)
            continue
        if cmd == "k":
            _save_project_preset(args, active_options)
            continue
        if cmd == "l":
            _load_project_preset(args, active_options)
            continue
        if cmd == "p":
            _open_preset_catalog(args, active_options)
            continue
        if cmd == "h":
            print(f"{_CYAN}  [Help] R = áp dụng preset khuyến nghị theo mode, C = reset menu, Enter = xác nhận.{_RST}")
            print(f"{_CYAN}  [Help] G = chọn preset theo mục tiêu engagement; option có dấu ★ là option nên bật cho mode hiện tại.{_RST}")
            print(f"{_CYAN}  [Help] Quick preset: B=Bug Bounty, W=Auth Web, S=Stealth External, I=Internal RT, R=Recon Only.{_RST}")
            print(f"{_CYAN}  [Help] K = lưu preset, L = nạp preset theo project hiện tại, P = mở catalog preset đã lưu.{_RST}")
            print(f"{_CYAN}  [Help] Dùng số để bật/tắt nhanh; path/value option sẽ prompt ngay khi bật.{_RST}")
            print(f"{_CYAN}  [Help] Option có [LOCK] đang bị khóa theo mode hoặc xung đột hiện tại, menu sẽ chặn ngay tại chỗ.{_RST}")
            continue
        if cmd in GOAL_PRESET_SHORTCUTS:
            _apply_goal_preset(args, active_options, GOAL_PRESET_SHORTCUTS[cmd])
            continue
        if cmd == "g":
            _render_goal_presets()
            selected = input(f"{_YELLOW}  ➢ Chọn Goal Preset (1-5): {_RST}").strip()
            goal_map = {
                "1": "bounty",
                "2": "auth-web",
                "3": "stealth-ext",
                "4": "internal-rt",
                "5": "recon-only",
                "b": "bounty",
                "w": "auth-web",
                "s": "stealth-ext",
                "i": "internal-rt",
                "r": "recon-only",
            }
            preset_key = goal_map.get(selected)
            if preset_key:
                _apply_goal_preset(args, active_options, preset_key)
            else:
                print(f"{_RED}  [!] Goal preset không hợp lệ.{_RST}")
            continue
        tokens = _re.split(r'[\s,]+', raw)
        for tok in tokens:
            if not tok.isdigit():
                continue
            idx = int(tok)
            if not (1 <= idx <= total):
                print(f"{_RED}  [!] Số {idx} không hợp lệ, bỏ qua.{_RST}")
                continue
            label, attr, desc, kind, block_id, allowed_modes = active_options[idx - 1]
            lock_reason = _menu_lock_reason(args, attr)
            if lock_reason:
                print(f"{_YELLOW}  [LOCK] {label}: {lock_reason}.{_RST}")
                continue
            if kind in ("path", "value"):
                cur = getattr(args, attr, None)
                if cur:
                    _set_menu_value(args, attr, None)
                    print(f"{_RED}  [-] {label} đã TẮT.{_RST}")
                else:
                    prompt = f"  {_YELLOW}➢ Nhập {'đường dẫn file' if kind == 'path' else 'giá trị'} {label}: {_RST}"
                    val = input(prompt).strip()
                    if val:
                        if attr == "rate_limit":
                            try:
                                val = int(val)
                            except ValueError:
                                print(f"{_RED}  [!] Rate Limit phải là số nguyên (VD: 5).{_RST}")
                                continue
                        _set_menu_value(args, attr, val)
                        print(f"{_GREEN}  [+] {label} = {val}{_RST}")
            else:
                cur = getattr(args, attr, False)
                new_val = not cur
                if attr == "persist" and new_val and not getattr(args, "auto_exploit", False):
                    _set_menu_value(args, "auto_exploit", True)
                    print(f"{_YELLOW}  [Guardrail] PERSISTENCE yêu cầu AUTO-EXPLOIT — đã tự bật AUTO-EXPLOIT.{_RST}")
                if attr == "auto_exploit" and new_val and getattr(args, "no_msf", False):
                    _set_menu_value(args, "no_msf", False)
                    print(f"{_YELLOW}  [Guardrail] AUTO-EXPLOIT xung đột với NO-MSF — đã tắt NO-MSF trước khi bật.{_RST}")
                _set_menu_value(args, attr, new_val)
                st = f"{_GREEN}BẬT{_RST}" if new_val else f"{_RED}TẮT{_RST}"
                print(f"  ➢ {label}: {st}")

    # Đồng bộ scope_enforce ↔ permissive
    if hasattr(args, 'scope_enforce'):
        args.permissive = not args.scope_enforce

    # [C-2 FIX] Đồng bộ header_input (menu) → args.header (argparse list)
    header_input_val = getattr(args, 'header_input', None)
    if header_input_val:
        if not hasattr(args, 'header') or args.header is None:
            args.header = []
        # Tránh trùng lặp
        if header_input_val not in args.header:
            args.header.append(header_input_val)

    _apply_menu_guardrails(args)

    return args
