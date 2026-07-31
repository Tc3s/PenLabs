#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Niche Protocol Scanner Module

Specialized Nmap scans for 5 under-the-radar Enterprise protocols
that are rarely audited but carry high exploitation potential.

Protocol intelligence sourced from nmap_nse_metadata.json:
  - MQTT  (mqtt.lua:  25 functions, TCP 1883/8883)
  - Modbus (inline,   TCP 502)
  - DICOM  (dicom.lua: 6 functions, TCP 104/11112)
  - BACnet (inline,   UDP 47808)
  - DRDA   (drda.lua: 34 functions, TCP 50000)
"""

import os
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
# PROTOCOL DEFINITIONS — from nselib + scripts analysis
# ═══════════════════════════════════════════════════════════

NICHE_PROTOCOLS = {
    "mqtt": {
        "name": "MQTT (Message Queuing Telemetry Transport)",
        "risk": "IoT broker wildcard subscribe → full sensor data exfiltration",
        "ports_tcp": "1883,8883",
        "ports_udp": None,
        "scripts": "mqtt-subscribe",
        # mqtt.lua provides 25 functions including CONNECT, SUBSCRIBE, PUBLISH
        "nselib": "mqtt.lua",
        "evasion_note": "MQTT brokers rarely have WAF. Default creds: admin/admin",
        "script_args": {
            "mqtt-subscribe.topic": "#",  # Wildcard: subscribe to ALL topics
        },
    },
    "modbus": {
        "name": "Modbus (SCADA/ICS Protocol)",
        "risk": "No authentication by design → direct PLC register read/write",
        "ports_tcp": "502",
        "ports_udp": None,
        "scripts": "modbus-discover",
        "nselib": None,  # Inline implementation
        "evasion_note": "Modbus has ZERO authentication. Any TCP connection = full access",
        "script_args": {},
    },
    "dicom": {
        "name": "DICOM (Digital Imaging & Communications in Medicine)",
        "risk": "Medical imaging data exposure → HIPAA violation → patient records",
        "ports_tcp": "104,11112",
        "ports_udp": None,
        "scripts": "dicom-ping,dicom-brute",
        # dicom.lua provides A-ASSOCIATE request/response, DICOM UID handling
        "nselib": "dicom.lua",
        "evasion_note": "DICOM servers rarely monitored. Default AE Title: ANY-SCP",
        "script_args": {},
    },
    "bacnet": {
        "name": "BACnet (Building Automation & Control)",
        "risk": "HVAC/lighting/access control hijack → physical security breach",
        "ports_tcp": None,
        "ports_udp": "47808",
        "scripts": "bacnet-info",
        "nselib": None,  # Inline implementation
        "evasion_note": "BACnet is UDP-only. Most IDS ignore UDP 47808",
        "script_args": {},
    },
    "drda": {
        "name": "DRDA (IBM DB2 Distributed Relational Database Architecture)",
        "risk": "Enterprise DB2 default creds → full database access → data exfil",
        "ports_tcp": "50000,50001,523",
        "ports_udp": None,
        "scripts": "drda-info,drda-brute",
        # drda.lua provides 34 functions: EXCSAT, ACCSEC, SECCHK, ACCRDB
        "nselib": "drda.lua",
        "evasion_note": "DB2 rarely behind WAF. Default user: db2admin",
        "script_args": {},
    },
}


# ═══════════════════════════════════════════════════════════
# SCAN ENGINE
# ═══════════════════════════════════════════════════════════

async def scan_niche_protocol(protocol: str, target_ip: str, out_dir: str,
                               evasion_args: list = None,
                               timeout: int = 180) -> dict:
    """
    Execute a specialized Nmap scan for a niche protocol.

    Args:
        protocol: One of: mqtt, modbus, dicom, bacnet, drda
        target_ip: Target IP address
        out_dir: Output directory for XML results
        evasion_args: Optional Nmap evasion flags
        timeout: Scan timeout in seconds

    Returns:
        dict with scan results
    """
    if protocol not in NICHE_PROTOCOLS:
        return {"error": f"Unknown protocol: {protocol}. Valid: {list(NICHE_PROTOCOLS.keys())}"}

    proto_def = NICHE_PROTOCOLS[protocol]
    os.makedirs(out_dir, exist_ok=True)
    xml_file = os.path.join(out_dir, f"niche_{protocol}.xml")

    print(f"\n{_C}  ╔══════════════════════════════════════════════════════╗{_X}")
    print(f"{_C}  ║  NICHE PROTOCOL SCANNER                              ║{_X}")
    print(f"{_C}  ╠══════════════════════════════════════════════════════╣{_X}")
    print(f"{_C}  ║  Protocol: {proto_def['name'][:41]:<41s}║{_X}")
    print(f"{_C}  ║  Risk:     {proto_def['risk'][:41]:<41s}║{_X}")
    print(f"{_C}  ║  Target:   {target_ip:<41s}║{_X}")
    print(f"{_C}  ╚══════════════════════════════════════════════════════╝{_X}")

    # Build command based on TCP vs UDP
    if proto_def["ports_udp"] and not proto_def["ports_tcp"]:
        # UDP-only protocol (e.g. BACnet)
        cmd = ["nmap", "-sU", "-Pn", "-sV",
               "--script", proto_def["scripts"],
               "-p", proto_def["ports_udp"],
               "-oX", xml_file, target_ip]
    elif proto_def["ports_tcp"]:
        # TCP protocol
        cmd = ["nmap", "-sS", "-sV", "-Pn",
               "--script", proto_def["scripts"],
               "-p", proto_def["ports_tcp"],
               "-oX", xml_file, target_ip]
    else:
        return {"error": f"No ports defined for protocol {protocol}"}

    # Inject script-args if defined
    if proto_def["script_args"]:
        args_str = ",".join(f"{k}={v}" for k, v in proto_def["script_args"].items())
        cmd.extend(["--script-args", args_str])

    # Inject evasion
    if evasion_args:
        cmd = [cmd[0]] + evasion_args + cmd[1:]

    logging.info(f"[NicheScanner] {protocol}: {' '.join(cmd)}")
    print(f"{_Y}  [*] Executing: {' '.join(cmd[:8])}...{_X}")

    result = {
        "protocol": protocol,
        "protocol_name": proto_def["name"],
        "target": target_ip,
        "risk_summary": proto_def["risk"],
        "ports_scanned": proto_def["ports_tcp"] or proto_def["ports_udp"],
        "scripts_used": proto_def["scripts"],
        "findings": [],
        "raw_output": "",
    }

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
        logging.warning(f"[NicheScanner] {protocol} timeout ({timeout}s)")
        result["findings"].append({"type": "TIMEOUT", "detail": f"Scan timed out after {timeout}s"})
        return result
    except Exception as e:
        logging.error(f"[NicheScanner] {protocol} error: {e}")
        result["findings"].append({"type": "ERROR", "detail": str(e)})
        return result

    # Parse XML results
    if os.path.exists(xml_file):
        try:
            root = ET.parse(xml_file).getroot()

            for port_elem in root.findall(".//port"):
                state = port_elem.find("state")
                if state is not None and state.get("state") == "open":
                    portid = port_elem.get("portid")
                    svc = port_elem.find("service")
                    svc_name = svc.get("name", "unknown") if svc is not None else "unknown"
                    result["findings"].append({
                        "type": "OPEN_PORT",
                        "port": portid,
                        "service": svc_name,
                    })
                    print(f"{_R}  [!] {protocol.upper()} port {portid} is OPEN ({svc_name})!{_X}")

            for script in root.findall(".//script"):
                sid = script.get("id", "")
                sout = script.get("output", "")
                result["raw_output"] += f"[{sid}] {sout}\n"
                result["findings"].append({
                    "type": "NSE_OUTPUT",
                    "script": sid,
                    "output": sout[:500],
                })
                print(f"{_M}  [NSE] {sid}: {sout[:120]}...{_X}")

        except Exception as e:
            logging.warning(f"[NicheScanner] XML parse error: {e}")

    n = len(result["findings"])
    print(f"{_G}  [✓] {protocol.upper()} scan complete: {n} findings.{_X}")
    return result


async def scan_all_niche(target_ip: str, out_dir: str,
                          protocols: list = None,
                          evasion_args: list = None) -> list:
    """
    Scan all (or selected) niche protocols against a target.

    Args:
        target_ip: Target IP
        out_dir: Output directory
        protocols: Optional list of protocols to scan (default: all 5)
        evasion_args: Optional Nmap evasion flags

    Returns:
        List of scan results
    """
    if protocols is None:
        protocols = list(NICHE_PROTOCOLS.keys())

    results = []
    for proto in protocols:
        proto_dir = os.path.join(out_dir, f"niche_{proto}")
        r = await scan_niche_protocol(proto, target_ip, proto_dir,
                                       evasion_args=evasion_args)
        results.append(r)

    # Summary
    total_findings = sum(len(r.get("findings", [])) for r in results)
    open_ports = sum(1 for r in results
                     for f in r.get("findings", [])
                     if f.get("type") == "OPEN_PORT")

    print(f"\n{_C}  ══════════════════════════════════════════════════════{_X}")
    print(f"{_C}  NICHE PROTOCOL SCAN SUMMARY{_X}")
    print(f"{_C}  Target:   {target_ip}{_X}")
    print(f"{_C}  Protocols scanned: {len(protocols)}{_X}")
    print(f"{_C}  Open ports found:  {open_ports}{_X}")
    print(f"{_C}  Total findings:    {total_findings}{_X}")
    print(f"{_C}  ══════════════════════════════════════════════════════{_X}")

    return results
