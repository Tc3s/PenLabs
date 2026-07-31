#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — NSE Kill-Chain Automation Engine

Implements automated script chaining: Discovery → Vuln → Exploit.
Phase 1 output feeds Phase 2 input. No manual intervention needed.

Chains derived from Nmap NSE metadata analysis:
  - SMB: smb-os-discovery → smb-vuln-ms17-010 → smb-vuln-ms08-067
  - HTTP: http-server-header → http-vuln-cve2017-5638
  - FTP:  ftp-syst → ftp-vsftpd-backdoor / ftp-proftpd-backdoor
"""

import os
import re
import asyncio
import logging
import xml.etree.ElementTree as ET

_R = "\033[91m"
_G = "\033[92m"
_Y = "\033[93m"
_M = "\033[95m"
_C = "\033[96m"
_X = "\033[0m"


# ═══════════════════════════════════════════════════════════
# CHAIN DEFINITIONS — derived from nmap_nse_scripts.json
# ═══════════════════════════════════════════════════════════

KILL_CHAINS = {
    "smb": {
        "name": "SMB EternalBlue Chain",
        "description": "Detect SMB version → Check EternalBlue → Verify MS08-067",
        "phases": [
            {
                "phase": 1,
                "label": "Recon",
                "scripts": "smb-os-discovery",
                "trigger": lambda output: _detect_smb_vuln_os(output),
            },
            {
                "phase": 2,
                "label": "Vuln Check",
                "scripts": "smb-vuln-ms17-010",
                "trigger": lambda output: "VULNERABLE" in output.upper(),
            },
            {
                "phase": 3,
                "label": "Deep Vuln",
                "scripts": "smb-vuln-ms08-067,smb-vuln-conficker",
                "trigger": None,  # Terminal phase
            },
        ],
        "ports": "445",
    },
    "http_struts": {
        "name": "HTTP Struts RCE Chain",
        "description": "Fingerprint server → Detect Struts → Exploit OGNL Injection",
        "phases": [
            {
                "phase": 1,
                "label": "Fingerprint",
                "scripts": "http-server-header,http-title",
                "trigger": lambda output: _detect_struts(output),
            },
            {
                "phase": 2,
                "label": "CVE Check",
                "scripts": "http-vuln-cve2017-5638",
                "trigger": None,
            },
        ],
        "ports": "80,443,8080,8443",
    },
    "ftp_backdoor": {
        "name": "FTP Backdoor Detection Chain",
        "description": "Banner grab → Version check → Backdoor exploit",
        "phases": [
            {
                "phase": 1,
                "label": "Banner Grab",
                "scripts": "ftp-syst,ftp-anon",
                "trigger": lambda output: _detect_ftp_vuln(output),
            },
            {
                "phase": 2,
                "label": "Backdoor Check",
                "scripts": "ftp-vsftpd-backdoor,ftp-proftpd-backdoor",
                "trigger": None,
            },
        ],
        "ports": "21",
    },
}


# ═══════════════════════════════════════════════════════════
# TRIGGER DETECTION FUNCTIONS
# ═══════════════════════════════════════════════════════════

def _detect_smb_vuln_os(output: str) -> bool:
    """Check if SMB OS discovery reveals a potentially vulnerable Windows version."""
    vuln_patterns = [
        r"Windows\s+(XP|Vista|7|Server\s+200[38])",
        r"Windows\s+Server\s+2008\s+R2",
        r"Windows\s+6\.[01]",
        r"Samba\s+[23]\.",
    ]
    for pattern in vuln_patterns:
        if re.search(pattern, output, re.IGNORECASE):
            return True
    return False


def _detect_struts(output: str) -> bool:
    """Check if HTTP headers reveal Apache Struts or Tomcat."""
    indicators = [
        r"Apache[\-/\s]Struts",
        r"Apache[\-/\s]Tomcat",
        r"Jakarta",
        r"X-Powered-By:\s*Servlet",
    ]
    for pattern in indicators:
        if re.search(pattern, output, re.IGNORECASE):
            return True
    return False


def _detect_ftp_vuln(output: str) -> bool:
    """Check if FTP banner reveals a known vulnerable version."""
    vuln_versions = [
        r"vsFTPd\s+2\.3\.4",         # Backdoor version
        r"ProFTPD\s+1\.3\.3c",        # Backdoor version
        r"ProFTPD\s+1\.3\.[23]",      # Buffer overflow CVE-2010-4221
    ]
    for pattern in vuln_versions:
        if re.search(pattern, output, re.IGNORECASE):
            return True
    return False


# ═══════════════════════════════════════════════════════════
# XML OUTPUT EXTRACTOR
# ═══════════════════════════════════════════════════════════

def _extract_script_output(xml_path: str) -> str:
    """Extract all NSE script outputs from Nmap XML safely (prevents XXE)."""
    if not os.path.exists(xml_path):
        return ""
    try:
        import defusedxml.ElementTree as DET
        tree = DET.parse(xml_path)
        root = tree.getroot()
        outputs = []
        for script in root.findall(".//script"):
            sid = script.get("id", "")
            sout = script.get("output", "")
            outputs.append(f"[{sid}] {sout}")
        return "\n".join(outputs)
    except Exception as e:
        logging.warning(f"[KillChain] Failed to parse XML {xml_path}: {e}")
        return ""


# ═══════════════════════════════════════════════════════════
# NMAP PLUGIN BRIDGE — Stealth integration via PluginRegistry
# ═══════════════════════════════════════════════════════════

def _resolve_nmap_plugin():
    """
    Resolve NmapPlugin from PluginRegistry to inherit its
    evasion engine and OPSEC signature neutralization.

    Returns:
        NmapPlugin instance or None if not registered.
    """
    try:
        from core.registry import PluginRegistry
        plugin = PluginRegistry.get("Nmap")
        if plugin:
            logging.info("[KillChain] NmapPlugin resolved from PluginRegistry.")
            return plugin
    except ImportError:
        logging.debug("[KillChain] PluginRegistry not available.")
    except Exception as e:
        logging.debug(f"[KillChain] PluginRegistry.get('Nmap') failed: {e}")
    return None


def _build_stealth_cmd(scripts: str, ports: str, target_ip: str,
                        xml_file: str, evasion_level: int = 2) -> list:
    """
    Build a fully-stealthed Nmap command by delegating to NmapPlugin.

    Priority:
      1. If NmapPlugin is registered → use its _apply_evasion() + _get_opsec_script_args()
      2. Fallback → apply hardcoded stealth flags + OPSEC args directly

    This guarantees kill-chains NEVER run naked.
    """
    # Base command (--host-timeout 3m prevents Nmap from hanging)
    cmd = ["nmap", "-Pn", "-sV", "--host-timeout", "3m",
           "--script", scripts,
           "-p", ports, "-oX", xml_file, target_ip]

    nmap_plugin = _resolve_nmap_plugin()

    if nmap_plugin:
        # ── Delegate to NmapPlugin's battle-tested engines ──
        cmd = nmap_plugin._apply_evasion(cmd, evasion_level)

        # Inject --randomize-hosts (same as NmapPlugin._build_cmd)
        if "--randomize-hosts" not in cmd:
            cmd.insert(1, "--randomize-hosts")

        # Inject OPSEC args (patches http.lua, sip.lua, smtp.lua signatures)
        if "--script-args" not in cmd:
            opsec_args = nmap_plugin._get_opsec_script_args()
            cmd.extend(opsec_args)

        logging.info(f"[KillChain] Stealth inherited from NmapPlugin "
                     f"(evasion={evasion_level})")
    else:
        # ── Fallback: apply stealth directly if NmapPlugin unavailable ──
        logging.warning("[KillChain] NmapPlugin not in registry — applying fallback stealth.")

        # Evasion Level 2: fragmentation + MTU + DNS source port + decoys
        if evasion_level >= 2:
            cmd = [cmd[0]] + ["-f", "--mtu", "24", "-g", "53",
                              "-D", "RND:10,ME"] + cmd[1:]
        elif evasion_level >= 1:
            cmd = [cmd[0]] + ["-f", "--data-length", "24"] + cmd[1:]

        # Randomize hosts
        if "--randomize-hosts" not in cmd:
            cmd.insert(1, "--randomize-hosts")

        # OPSEC: anti-fingerprint args (fallback copy of NmapPlugin logic)
        chrome_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/125.0.0.0 Safari/537.36")
        opsec = ",".join([
            f"http.useragent={chrome_ua}",
            "sip.useragent=PolycomVVX-VVX_310-UA/5.9.1.0615",
            "smtp.domain=compliance-audit.internal",
        ])
        cmd.extend(["--script-args", opsec])

    return cmd


# ═══════════════════════════════════════════════════════════
# CHAIN EXECUTOR (V2 — Full Stealth Integration)
# ═══════════════════════════════════════════════════════════

async def execute_chain(chain_name: str, target_ip: str, out_dir: str,
                        evasion_level: int = 2, timeout: int = 180) -> dict:
    """
    Execute a kill-chain against a target with FULL stealth.

    Evasion and OPSEC args are automatically obtained from NmapPlugin
    via PluginRegistry. If NmapPlugin is not registered, falls back
    to built-in stealth flags.

    Args:
        chain_name: Key in KILL_CHAINS dict
        target_ip: Target IP address
        out_dir: Output directory for XML results
        evasion_level: Stealth level (0=none, 1=frag, 2=full decoy)
        timeout: Per-phase timeout in seconds

    Returns:
        dict with keys: chain_name, target, phases_executed, findings
    """
    if chain_name not in KILL_CHAINS:
        logging.error(f"[KillChain] Unknown chain: {chain_name}")
        return {"error": f"Unknown chain: {chain_name}"}

    chain = KILL_CHAINS[chain_name]
    os.makedirs(out_dir, exist_ok=True)

    result = {
        "chain_name": chain["name"],
        "target": target_ip,
        "phases_executed": [],
        "findings": [],
        "aborted_at": None,
        "stealth_mode": f"evasion_level={evasion_level}",
    }

    print(f"\n{_C}  ╔══════════════════════════════════════════════════════╗{_X}")
    print(f"{_C}  ║  NSE KILL-CHAIN: {chain['name']:<35s}║{_X}")
    print(f"{_C}  ║  Target: {target_ip:<43s}║{_X}")
    print(f"{_C}  ║  Stealth: Level {evasion_level} (auto-inherited)          ║{_X}")
    print(f"{_C}  ╚══════════════════════════════════════════════════════╝{_X}")

    for phase_def in chain["phases"]:
        phase_num = phase_def["phase"]
        label = phase_def["label"]
        scripts = phase_def["scripts"]
        trigger = phase_def["trigger"]

        xml_file = os.path.join(out_dir, f"chain_{chain_name}_p{phase_num}.xml")

        print(f"\n{_Y}  ── Phase {phase_num}: {label} ──{_X}")
        print(f"{_Y}  Scripts: {scripts}{_X}")

        # Build stealth command via NmapPlugin bridge
        cmd = _build_stealth_cmd(
            scripts=scripts,
            ports=chain["ports"],
            target_ip=target_ip,
            xml_file=xml_file,
            evasion_level=evasion_level,
        )

        logging.info(f"[KillChain] Phase {phase_num} CMD: {' '.join(cmd)}")
        print(f"{_M}  [STEALTH] {' '.join(cmd[:10])}...{_X}")

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            logging.warning(f"[KillChain] Phase {phase_num} timeout ({timeout}s)")
            result["aborted_at"] = phase_num
            break
        except Exception as e:
            logging.error(f"[KillChain] Phase {phase_num} error: {e}")
            result["aborted_at"] = phase_num
            break

        # Extract output
        script_output = _extract_script_output(xml_file)
        phase_result = {
            "phase": phase_num,
            "label": label,
            "scripts": scripts,
            "output_summary": script_output[:500] if script_output else "(no output)",
        }
        result["phases_executed"].append(phase_result)

        if "VULNERABLE" in script_output.upper():
            result["findings"].append({
                "phase": phase_num,
                "type": "VULNERABLE",
                "detail": script_output[:300],
            })
            print(f"{_R}  [!] VULNERABLE detected in Phase {phase_num}!{_X}")

        # Check trigger for next phase
        if trigger is None:
            print(f"{_G}  [✓] Phase {phase_num} complete (terminal phase).{_X}")
            continue

        if trigger(script_output):
            print(f"{_M}  [→] Trigger matched! Advancing to Phase {phase_num + 1}...{_X}")
        else:
            print(f"{_G}  [✓] Phase {phase_num} complete. Trigger not matched — chain stops.{_X}")
            result["aborted_at"] = phase_num
            break

    print(f"\n{_G}  ══ Kill-Chain '{chain['name']}' finished. "
          f"{len(result['phases_executed'])} phases executed, "
          f"{len(result['findings'])} findings. ══{_X}")

    return result


async def execute_all_chains(target_ip: str, out_dir: str,
                             detected_ports: set = None,
                             evasion_level: int = 2) -> list:
    """
    Auto-select and execute relevant kill-chains based on detected ports.

    Stealth is automatically enforced via NmapPlugin integration.
    No chain will ever run without evasion and OPSEC signature patches.
    """
    results = []
    port_chain_map = {
        445: "smb",
        139: "smb",
        80: "http_struts",
        443: "http_struts",
        8080: "http_struts",
        21: "ftp_backdoor",
    }

    chains_to_run = set()
    if detected_ports:
        for port in detected_ports:
            if port in port_chain_map:
                chains_to_run.add(port_chain_map[port])

    if not chains_to_run:
        logging.info("[KillChain] No matching chains for detected ports.")
        return results

    for chain_name in sorted(chains_to_run):
        chain_dir = os.path.join(out_dir, f"killchain_{chain_name}")
        result = await execute_chain(
            chain_name, target_ip, chain_dir,
            evasion_level=evasion_level,
        )
        results.append(result)

    return results

