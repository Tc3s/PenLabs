#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PenLabs — Ultimate Nmap Engine V3 (Async & MSF-Sync)

- Async Subprocess: asyncio.create_subprocess_exec — no thread-pool waste.
- MSF-Sync: Auto-push hosts/services to Metasploit DB via RPC.
- NSE Selector Engine: Targeted scripts + Vulners/Vulnscan auto-inject.
- Evasion Engine: 3-level stealth + --randomize-hosts on all modes.
- OS Detection: accuracy >= 85% filter.
- Backward Compatible: run_sync() wrapper for legacy callers.
"""

import os
import re
import asyncio
import logging
import subprocess
import xml.etree.ElementTree as ET
import shutil
from core.base_plugin import BasePlugin
from core.raw_artifacts import append_manifest, write_command, write_json, write_text
from config import Config

_R = "\033[91m"
_G = "\033[92m"
_Y = "\033[93m"
_B = "\033[94m"
_M = "\033[95m"
_C = "\033[96m"
_X = "\033[0m"


class NmapPlugin(BasePlugin):
    """
    Ultimate Nmap Engine V3 — Async & MSF-Sync.
    6 modes: stealth, sniper, infra-smash, full-audit, udp-scan, fallback.
    Built-in NSE Selector + Vulners + 3-level Evasion + MSF DB Sync.
    """

    def name(self) -> str:
        return "Nmap"

    def description(self) -> str:
        return "Ultimate Nmap Engine V3 — Async subprocess, MSF-Sync, Vulners NSE, 3-level Evasion."

    def check_installed(self) -> bool:
        return shutil.which("nmap") is not None

    # ═══════════════════════════════════════════════════════════
    # NSE WEIGHTED SCORING ENGINE (V4 — Data-Driven)
    # ═══════════════════════════════════════════════════════════
    #
    # Architecture:
    #   1. Each candidate script starts with score=0.
    #   2. Hints (port, service, category) add weighted points.
    #   3. Only scripts with score >= THRESHOLD are loaded.
    #   4. Intelligence sourced from nmap_nse_scripts.json.
    #
    # Weight Matrix (derived from nselib analysis):
    #   - Direct port match:  +10  (port in script's portrule)
    #   - Service keyword:    +5   (e.g. "smb" in script name for port 445)
    #   - Category "vuln":    +3   (prioritize vulnerability checks)
    #   - Category "exploit": +2   (include if port + vuln both match)
    #   - Category "safe":    +1   (prefer safe scripts)
    #   - Universal CVE tool: +15  (vulners/vulscan always loaded)
    #
    # OPSEC Integration:
    #   Injects --script-args to neutralize hardcoded signatures
    #   discovered in http.lua:160, sip.lua:530, smtp.lua:174.
    # ═══════════════════════════════════════════════════════════

    # Score threshold: only scripts scoring >= this value get loaded
    NSE_SCORE_THRESHOLD = 5

    # ── Weighted Scoring Matrix ──
    # Maps port -> list of (script_name, bonus_score)
    _PORT_SCRIPT_MATRIX = {
        # Web
        80:    [("http-enum",10), ("http-title",8), ("http-server-header",8),
                ("http-methods",7), ("http-vhosts",6), ("http-vuln-cve2017-5638",5),
                ("http-cookie-flags",5), ("http-csrf",5), ("http-dombased-xss",5),
                ("http-sql-injection",5), ("ssl-cert",3)],
        443:   [("ssl-cert",10), ("ssl-enum-ciphers",10), ("http-title",8),
                ("http-enum",7), ("http-server-header",7), ("http-methods",6),
                ("http-vuln-cve2017-5638",5)],
        8080:  [("http-enum",10), ("http-title",8), ("http-server-header",8),
                ("http-methods",7), ("http-open-proxy",6)],
        8443:  [("ssl-cert",10), ("ssl-enum-ciphers",10), ("http-title",8)],
        8000:  [("http-title",8), ("http-enum",6)],
        8888:  [("http-title",8), ("http-enum",6)],
        3000:  [("http-title",8), ("http-enum",6)],
        # SMB — sourced from smb.lua (functions: negotiate, session_setup, tree_connect)
        445:   [("smb-os-discovery",10), ("smb-vuln-ms17-010",10),
                ("smb-vuln-ms08-067",8), ("smb-enum-shares",7),
                ("smb-enum-users",7), ("smb-vuln-conficker",6),
                ("smb-vuln-cve-2017-7494",6), ("smb-double-pulsar-backdoor",6),
                ("smb-security-mode",5)],
        139:   [("smb-os-discovery",10), ("smb-vuln-ms17-010",8),
                ("smb-enum-shares",7), ("smb-enum-users",6)],
        # RDP — sourced from rdp.lua
        3389:  [("rdp-vuln-ms12-020",10), ("rdp-enum-encryption",8),
                ("rdp-ntlm-info",7)],
        # FTP — sourced from ftp.lua (functions: connect, login, close)
        21:    [("ftp-anon",10), ("ftp-syst",8), ("ftp-vsftpd-backdoor",7),
                ("ftp-proftpd-backdoor",6), ("ftp-vuln-cve2010-4221",5),
                ("ftp-brute",3)],
        # SSH — sourced from ssh2.lua (functions: transport, kex_init)
        22:    [("ssh2-enum-algos",10), ("ssh-auth-methods",8),
                ("ssh-hostkey",7), ("ssh-brute",3)],
        # Telnet
        23:    [("telnet-encryption",8), ("telnet-ntlm-info",7),
                ("telnet-brute",3)],
        # Databases
        3306:  [("mysql-info",10), ("mysql-vuln-cve2012-2122",8),
                ("mysql-enum",7), ("mysql-brute",3)],
        5432:  [("postgresql-info",10), ("pgsql-brute",5)],
        1433:  [("ms-sql-info",10), ("ms-sql-ntlm-info",8),
                ("ms-sql-empty-password",7), ("ms-sql-brute",3)],
        1521:  [("oracle-tns-version",10), ("oracle-sid-brute",6)],
        27017: [("mongodb-info",10), ("mongodb-databases",8)],
        6379:  [("redis-info",10)],
        # Cloud/DevOps
        2375:  [("docker-version",10)],
        2376:  [("docker-version",10)],
        10250: [("http-title",5)],  # Kubelet API
        9200:  [("http-title",8)],  # Elasticsearch
        5601:  [("http-title",8)],  # Kibana
        8500:  [("http-title",8)],  # Consul
        # Mail — sourced from smtp.lua (get_domain → "nmap.scanme.org")
        25:    [("smtp-commands",10), ("smtp-vuln-cve2010-4344",8),
                ("smtp-open-relay",6)],
        110:   [("pop3-capabilities",10)],
        143:   [("imap-capabilities",10)],
        587:   [("smtp-commands",8)],
        993:   [("imap-capabilities",8), ("ssl-cert",5)],
        995:   [("pop3-capabilities",8), ("ssl-cert",5)],
        # DNS — sourced from dns.lua (query, zone_transfer)
        53:    [("dns-zone-transfer",10), ("dns-cache-snoop",8),
                ("dns-recursion",7)],
        # SNMP — sourced from snmp.lua (get, set, walk)
        161:   [("snmp-info",10), ("snmp-sysdescr",8), ("snmp-brute",5)],
        162:   [("snmp-info",8)],
        # ── NICHE PROTOCOLS (from Phase 3 analysis) ──
        1883:  [("mqtt-subscribe",10)],       # MQTT
        8883:  [("mqtt-subscribe",10)],       # MQTT TLS
        502:   [("modbus-discover",10)],      # Modbus/SCADA
        104:   [("dicom-ping",10)],           # DICOM
        11112: [("dicom-ping",10), ("dicom-brute",5)],
        50000: [("drda-info",10), ("drda-brute",5)],  # IBM DB2 DRDA
    }

    def _get_targeted_scripts(self, osint_ports: list,
                               service_hints: dict = None,
                               os_hint: str = None) -> str:
        """
        Weighted Scoring NSE Selector Engine (V4).

        Uses a scoring matrix to intelligently select scripts.
        Each port contributes weighted scores to candidate scripts.
        Only scripts exceeding NSE_SCORE_THRESHOLD are selected.

        Args:
            osint_ports: List of detected port numbers
            service_hints: Optional dict {port: service_name} from prior scans
            os_hint: Optional OS fingerprint string from prior scans

        Returns:
            Comma-separated string of selected scripts for --script flag
        """
        scores = {}  # script_name -> cumulative score
        # Safe cast: handles "80/tcp", "443/udp" formats from OSINT sources
        port_set = set(int(str(p).split('/')[0]) for p in osint_ports) if osint_ports else set()

        # ── Phase 1: Universal CVE Scanner (always loaded) ──
        offline = getattr(Config, 'OFFLINE_MODE', False)
        if offline:
            scores["vulscan"] = 15
            logging.info("[NSE-ScoringEngine] OFFLINE → vulscan (score=15)")
        else:
            scores["vulners"] = 15
            logging.info("[NSE-ScoringEngine] ONLINE → vulners (score=15)")

        # ── Phase 2: Port-based scoring ──
        for port in port_set:
            if port in self._PORT_SCRIPT_MATRIX:
                for script_name, bonus in self._PORT_SCRIPT_MATRIX[port]:
                    scores[script_name] = scores.get(script_name, 0) + bonus
                    logging.debug(f"[NSE-Score] Port {port} → {script_name} +{bonus} "
                                  f"(total={scores[script_name]})")

        # ── Phase 3: Service hint boosting ──
        if service_hints:
            for port, svc_name in service_hints.items():
                svc_lower = svc_name.lower() if svc_name else ""
                # Boost scripts whose name contains the service keyword
                for script_name in list(scores.keys()):
                    if svc_lower and svc_lower in script_name:
                        scores[script_name] = scores.get(script_name, 0) + 5
                        logging.debug(f"[NSE-Score] Service hint '{svc_name}' → "
                                      f"{script_name} +5")

        # ── Phase 4: OS hint boosting ──
        if os_hint:
            os_lower = os_hint.lower()
            if "windows" in os_lower:
                for s in ["smb-vuln-ms17-010", "smb-vuln-ms08-067",
                           "smb-os-discovery", "rdp-vuln-ms12-020"]:
                    scores[s] = scores.get(s, 0) + 3
            elif "linux" in os_lower:
                for s in ["ssh2-enum-algos", "ssh-auth-methods"]:
                    scores[s] = scores.get(s, 0) + 3

        # ── Phase 5: Universal fallback (always added at base score) ──
        scores["banner"] = scores.get("banner", 0) + self.NSE_SCORE_THRESHOLD
        scores["ssl-cert"] = scores.get("ssl-cert", 0) + self.NSE_SCORE_THRESHOLD

        # ── Phase 6: Apply threshold filter ──
        selected = {name for name, score in scores.items()
                     if score >= self.NSE_SCORE_THRESHOLD}

        # ── Scoring summary ──
        rejected = {name: score for name, score in scores.items()
                     if score < self.NSE_SCORE_THRESHOLD}
        if rejected:
            logging.debug(f"[NSE-ScoringEngine] Rejected (below threshold={self.NSE_SCORE_THRESHOLD}): "
                          f"{rejected}")

        result = ",".join(sorted(selected))
        logging.info(f"[NSE-ScoringEngine] {len(selected)} scripts selected "
                     f"(threshold={self.NSE_SCORE_THRESHOLD}): {result}")

        # ── OPSEC: Log scoring breakdown for audit ──
        top5 = sorted(scores.items(), key=lambda x: -x[1])[:5]
        logging.info(f"[NSE-ScoringEngine] Top-5 scores: "
                     f"{', '.join(f'{n}={s}' for n,s in top5)}")

        return result

    def _get_opsec_script_args(self) -> list:
        """
        Generate --script-args to neutralize hardcoded OPSEC signatures.

        Patches discovered in:
          - http.lua:160  → User-Agent "Nmap Scripting Engine"
          - sip.lua:530   → User-Agent "Nmap NSE"
          - smtp.lua:174  → EHLO domain "nmap.scanme.org"
        """
        chrome_ua = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                     "AppleWebKit/537.36 (KHTML, like Gecko) "
                     "Chrome/125.0.0.0 Safari/537.36")
        args = [
            f"http.useragent={chrome_ua}",
            "sip.useragent=PolycomVVX-VVX_310-UA/5.9.1.0615",
            "smtp.domain=compliance-audit.internal",
        ]
        return ["--script-args", ",".join(args)]

    # ═══════════════════════════════════════════════════════════
    # EVASION ENGINE
    # ═══════════════════════════════════════════════════════════

    def _apply_evasion(self, cmd: list, evasion_level: int) -> list:
        """ Apply 2026 Stealth Flags: Data Length, Fragment, Decoy, and User-Agent."""
        if evasion_level <= 0:
            return cmd
            
        from utils.ua_rotator import get_random_ua as _ua
        stealth_args = [
            "--script-args", 
            f"http.useragent='{_ua()}',"
            "smb.fingerprint=false"
        ]
        
        if evasion_level == 1:
            print(f"{_Y}  [+] Evasion Level 1: Activating Fragmentation & Data Padding...{_X}")
            logging.info("[Nmap-Evasion] Level 1: -f --data-length 16")
            return [cmd[0]] + ["-f", "--data-length", "16"] + stealth_args + cmd[1:]
            
        # level >= 2: FULL 2026 GHOST MODE
        print(f"{_R}  [+] Evasion Level 2: 2026 GHOST MODE — MTU + DNS Source Port + Mixed Data Length!{_X}")
        logging.info("[Nmap-Evasion] Level 2: --mtu 24 -g 53 --data-length 32")
        return [cmd[0]] + ["--mtu", "24", "-g", "53", "--data-length", "32"] + stealth_args + cmd[1:]

    # ═══════════════════════════════════════════════════════════
    # XML PARSER (OS accuracy >= 85%)
    # ═══════════════════════════════════════════════════════════

    def _parse_xml(self, xml_file):
        """Parse Nmap XML. OS detection: accuracy >= 85% only."""
        res = {"ports": [], "nse_cves": [], "os_detection": []}
        try:
            if not os.path.exists(xml_file):
                return res
            root = ET.parse(xml_file).getroot()

            for osmatch in root.findall(".//osmatch"):
                accuracy = int(osmatch.get("accuracy", "0"))
                if accuracy >= 85:
                    res["os_detection"].append({"name": osmatch.get("name", ""), "accuracy": accuracy})
                else:
                    logging.debug(f"[Nmap-Parse] OS REJECTED ({accuracy}%<85%): {osmatch.get('name','')}")

            for p in root.findall(".//port"):
                state = p.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = p.find("service")
                name = svc.get("name") if svc is not None else "unknown"
                ver = (svc.get("product", "") + " " + svc.get("version", "")).strip() if svc is not None else ""
                port_num = int(p.get("portid", "0"))
                cpes = []
                if svc is not None:
                    for cpe_elem in svc.findall("cpe"):
                        if cpe_elem.text:
                            cpes.append(cpe_elem.text)
                res["ports"].append({"port": port_num, "service": name, "version": ver, "cpes": cpes})

                for script in p.findall("script"):
                    sid = script.get("id", "")
                    sout = script.get("output", "")
                    cves_found = re.findall(r'CVE-\d{4}-\d{4,7}', sout, re.IGNORECASE)
                    for cve in cves_found:
                        cu = cve.upper()
                        if cu not in [c['cve'] for c in res["nse_cves"]]:
                            res["nse_cves"].append({"cve": cu, "port": port_num, "nse_script": sid,
                                                    "confidence": 0.9, "source": "Nmap-NSE"})
                    if "VULNERABLE" in sout.upper() and not cves_found:
                        res["nse_cves"].append({"cve": f"NSE-{sid}", "port": port_num, "nse_script": sid,
                                                "confidence": 0.7, "source": "Nmap-NSE"})
                    for table in script.findall(".//table"):
                        for elem in table.findall(".//elem"):
                            for cve in re.findall(r'CVE-\d{4}-\d{4,7}', elem.text or "", re.IGNORECASE):
                                cu = cve.upper()
                                if cu not in [c['cve'] for c in res["nse_cves"]]:
                                    res["nse_cves"].append({"cve": cu, "port": port_num, "nse_script": sid,
                                                            "confidence": 0.9, "source": "Nmap-NSE"})
        except Exception as e:
            logging.warning(f"Failed to parse Nmap XML ({xml_file}): {e}")
        return res

    # ═══════════════════════════════════════════════════════════
    # COMMAND BUILDER (--randomize-hosts on ALL modes)
    # ═══════════════════════════════════════════════════════════

    def _build_cmd(self, ip: str, xml_file: str, mode: str,
                   osint_ports: list, evasion_level: int = 0,
                   rate_limit_fps: int = 0,
                   strategy_profile: dict | None = None) -> list:
        """Build Nmap command. --randomize-hosts injected on all modes.
        
        Args:
            rate_limit_fps: Max packets/second (--max-rate). 0 = no limit.
        """
        # Safe cast: strip "/tcp", "/udp" suffixes before building port list
        ports = ",".join(str(int(str(p).split('/')[0])) for p in osint_ports) if osint_ports else None

        if mode == "stealth":
            print(f"{_C}  [NMAP] Mode: STEALTH — Pure SYN, zero fingerprint.{_X}")
            cmd = ["nmap", "-sS", "-Pn", "-T2"]
            if ports:
                cmd.extend(["-p", ports])
            else:
                cmd.extend(["--top-ports", "200"])
            cmd.extend(["-oX", xml_file, ip])
            cmd = self._apply_evasion(cmd, max(evasion_level, 1))

        elif mode == "sniper":
            print(f"{_B}  [NMAP] Mode: SNIPER — High-intensity version detection.{_X}")
            if not osint_ports:
                logging.warning("[Nmap] Sniper requires OSINT ports.")
                return None
            cmd = ["nmap", "-sS", "-sV", "-Pn", "--version-intensity", "9", "-p", ports, "-oX", xml_file, ip]
            cmd = self._apply_evasion(cmd, evasion_level)

        elif mode in ("infra-smash", "full-audit"):
            targeted = self._get_targeted_scripts(osint_ports)
            n = len(targeted.split(",")) if targeted else 0
            label = "INFRA-SMASH" if mode == "infra-smash" else "FULL-AUDIT"
            print(f"{_M}  [NMAP] Mode: {label} — Targeted NSE ({n} scripts) + Vulners.{_X}")
            cmd = ["nmap", "-sS", "-sV", "-sC", "-O", "-Pn", "--version-intensity", "7"]
            if targeted:
                cmd.extend(["--script", targeted])
            if ports:
                cmd.extend(["-p", ports])
            else:
                cmd.extend(["--top-ports", "500"])
            cmd.extend(["-oX", xml_file, ip])
            cmd = self._apply_evasion(cmd, evasion_level)

        elif mode == "udp-scan":
            print(f"{_Y}  [NMAP] Mode: UDP-SCAN — Top 20 UDP ports.{_X}")
            cmd = ["nmap", "-sU", "--top-ports", "20", "-sV", "--max-retries", "1", "-T4", "-Pn",
                   "-oX", xml_file, ip]
            cmd = self._apply_evasion(cmd, evasion_level)

        else:
            print(f"{_G}  [NMAP] Mode: FALLBACK — Safe version detection.{_X}")
            cmd = ["nmap", "-Pn", "-sS", "-sV", "--version-intensity", "5",
                   "--script", "banner,ssl-cert", "--top-ports", "200", "-oX", xml_file, ip]
            cmd = self._apply_evasion(cmd, evasion_level)

        if cmd and strategy_profile:
            timing = strategy_profile.get("timing")
            if timing:
                for idx, part in enumerate(list(cmd)):
                    if isinstance(part, str) and re.fullmatch(r"-T[0-5]", part):
                        cmd[idx] = f"-{timing}" if not str(timing).startswith("-") else str(timing)
                        break
            if strategy_profile.get("scripts") == "version" and "--script" in cmd:
                script_idx = cmd.index("--script")
                if script_idx + 1 < len(cmd):
                    cmd[script_idx + 1] = "banner,ssl-cert"

        # ── Inject --max-rate (V1.0 Rate Limit) ──
        if cmd and rate_limit_fps > 0:
            cmd.insert(1, str(rate_limit_fps))
            cmd.insert(1, "--max-rate")
            logging.info(f"[Nmap] Injected --max-rate {rate_limit_fps} (profile rate_limit)")

        # ── Inject --randomize-hosts on ALL modes ──
        if cmd and "--randomize-hosts" not in cmd:
            cmd.insert(1, "--randomize-hosts")
            logging.debug("[Nmap] Injected --randomize-hosts (anti-behavioral-analysis)")

        # ── Inject OPSEC signature neutralization (V4) ──
        # Patches: http.lua:160 UA, sip.lua:530 UA, smtp.lua:174 domain
        if cmd and "--script" in cmd and "--script-args" not in cmd:
            opsec_args = self._get_opsec_script_args()
            cmd.extend(opsec_args)
            logging.info("[Nmap-OPSEC] Injected anti-fingerprint --script-args")

        return cmd

    # ═══════════════════════════════════════════════════════════
    # MSF-SYNC — Push results to Metasploit DB via RPC
    # ═══════════════════════════════════════════════════════════

    async def _sync_to_msf(self, target_ip: str, nmap_results: dict):
        """
        [V3] Push Nmap results into Metasploit DB via MsfRpcPlugin.
        Uses PluginRegistry to get MsfRPC client — fully decoupled.
        """
        try:
            from core.registry import PluginRegistry
            msf_plugin = PluginRegistry.get("MsfRPC")
            if not msf_plugin:
                logging.debug("[MSF-Sync] MsfRPC plugin not registered. Skipping.")
                return
            client = msf_plugin.connect()
            if not client:
                logging.debug("[MSF-Sync] Cannot connect to msfrpcd. Skipping DB sync.")
                return

            print(f"{_M}  [+] MSF-Sync: Connected to Metasploit RPC — syncing scan data...{_X}")
            logging.info(f"[MSF-Sync] Starting DB sync for {target_ip}")

            # ── Report Host + OS ──
            os_list = nmap_results.get("os_detection", [])
            os_name = os_list[0]["name"] if os_list else "Unknown"
            try:
                client.call('db.report_host', [{'host': target_ip, 'os_name': os_name}])
                print(f"{_M}  [+] MSF-Sync: Reported host {target_ip} (OS: {os_name}){_X}")
                logging.info(f"[MSF-Sync] db.report_host: {target_ip}, os={os_name}")
            except Exception as e:
                logging.warning(f"[MSF-Sync] db.report_host failed: {e}")

            # ── Report Services ──
            svc_count = 0
            for p in nmap_results.get("ports", []):
                try:
                    client.call('db.report_service', [{
                        'host': target_ip,
                        'port': p['port'],
                        'proto': 'tcp',
                        'name': p.get('service', 'unknown'),
                        'info': p.get('version', ''),
                    }])
                    svc_count += 1
                    print(f"{_M}  [+] MSF-Sync: Reported service {p['service']}:{p['port']}/tcp{_X}")
                    logging.debug(f"[MSF-Sync] db.report_service: port={p['port']}, svc={p['service']}")
                except Exception as e:
                    logging.warning(f"[MSF-Sync] db.report_service port {p['port']} failed: {e}")

            # ── Report Vulns (from NSE CVEs) ──
            vuln_count = 0
            for cve_entry in nmap_results.get("nse_cves", []):
                try:
                    client.call('db.report_vuln', [{
                        'host': target_ip,
                        'port': cve_entry['port'],
                        'proto': 'tcp',
                        'name': cve_entry['cve'],
                        'info': f"Detected by NSE script: {cve_entry.get('nse_script', 'unknown')}",
                    }])
                    vuln_count += 1
                except Exception as e:
                    logging.debug(f"[MSF-Sync] db.report_vuln {cve_entry['cve']} failed: {e}")

            print(f"{_M}  [✓] MSF-Sync complete: {svc_count} services, {vuln_count} vulns pushed to Metasploit DB.{_X}")
            logging.info(f"[MSF-Sync] Sync complete: {svc_count} services, {vuln_count} vulns for {target_ip}")

        except ImportError:
            logging.debug("[MSF-Sync] PluginRegistry not available. Skipping.")
        except Exception as e:
            logging.warning(f"[MSF-Sync] Unexpected error: {e}")

    # ═══════════════════════════════════════════════════════════
    # ASYNC RUN — Primary entry point (V3)
    # ═══════════════════════════════════════════════════════════

    async def run_async(self, ip: str, out_dir: str, index: int, mode: str,
                        osint_ports: list, evasion_level: int = 0,
                        strategy_profile: dict | None = None) -> dict:
        """
        [V3] Async Nmap scan via asyncio.create_subprocess_exec.
        Non-blocking — allows parallel scans without thread-pool waste.
        Auto-syncs results to Metasploit DB if MsfRPC is connected.
        """
        raw_dir = os.path.join(out_dir, "raw")
        os.makedirs(raw_dir, exist_ok=True)
        xml_file = os.path.join(raw_dir, f"nm_{index}.xml")

        port_count = len(osint_ports) if osint_ports else 0
        print(f"\n{_C}  ╔══════════════════════════════════════════════════════╗{_X}")
        print(f"{_C}  ║  ULTIMATE NMAP ENGINE V3 — ASYNC TACTICAL SCAN      ║{_X}")
        print(f"{_C}  ╠══════════════════════════════════════════════════════╣{_X}")
        print(f"{_C}  ║  Target:  {ip:<43s}║{_X}")
        print(f"{_C}  ║  Mode:    {mode:<43s}║{_X}")
        print(f"{_C}  ║  Evasion: Level {str(evasion_level):<37s}║{_X}")
        print(f"{_C}  ║  OSINT:   {str(port_count) + ' ports':<43s}║{_X}")
        print(f"{_C}  ╚══════════════════════════════════════════════════════╝{_X}")

        cmd = self._build_cmd(ip, xml_file, mode, osint_ports, evasion_level, strategy_profile=strategy_profile)
        if cmd is None:
            return {"ports": [], "nse_cves": [], "os_detection": []}

        logging.info(f"[Nmap-Async] Executing: {' '.join(cmd)}")
        write_command(raw_dir, f"nm_{index}_command.txt", cmd)

        import sys
        debug_mode = "--debug" in sys.argv

        try:
            if debug_mode:
                print(f"{_Y}  [DEBUG] {' '.join(cmd)}{_X}")
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=Config.NMAP_TIMEOUT
                )
                if debug_mode and stdout:
                    print(stdout.decode(errors='replace')[:2000])
            except asyncio.TimeoutError:
                logging.warning(f"[Nmap-Async] Timeout ({Config.NMAP_TIMEOUT}s) for {ip}. Killing process.")
                print(f"{_Y}  [!] Nmap timeout ({Config.NMAP_TIMEOUT}s) — killing & parsing partial...{_X}")
                proc.kill()
                await proc.wait()

        except Exception as e:
            logging.error(f"[Nmap-Async] Error: {e}")
            print(f"{_R}  [✘] Nmap error: {e}{_X}")

        if "stdout" in locals():
            write_text(raw_dir, f"nm_{index}_stdout.txt", stdout)
        if "stderr" in locals():
            write_text(raw_dir, f"nm_{index}_stderr.txt", stderr)

        result = self._parse_xml(xml_file)
        write_json(raw_dir, f"nm_{index}_parsed.json", result)
        append_manifest(
            raw_dir,
            "nmap",
            [
                f"nm_{index}_command.txt",
                f"nm_{index}.xml",
                f"nm_{index}_stdout.txt",
                f"nm_{index}_stderr.txt",
                f"nm_{index}_parsed.json",
            ],
            note=f"ip={ip} mode={mode}",
        )

        n_ports = len(result["ports"])
        n_cves = len(result["nse_cves"])
        n_os = len(result["os_detection"])
        print(f"{_G}  [✓] Scan complete: {n_ports} ports, {n_cves} NSE CVEs, {n_os} OS (≥85%).{_X}")

        # ── Optional MSF-Sync ──
        if n_ports > 0 and getattr(Config, "NMAP_MSF_SYNC_ENABLED", False):
            await self._sync_to_msf(ip, result)

        return result

    # ═══════════════════════════════════════════════════════════
    # SYNC RUN — Backward-compatible wrapper for legacy callers
    # ═══════════════════════════════════════════════════════════

    def run(self, ip: str, out_dir: str, index: int, mode: str,
            osint_ports: list, evasion_level: int = 0,
            strategy_profile: dict | None = None) -> dict:
        """
        [V3] Backward-compatible sync wrapper.
        Legacy callers (loop.run_in_executor) call this.
        Internally delegates to run_async().
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            # Already in async context — schedule coroutine and run in new thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    asyncio.run,
                    self.run_async(ip, out_dir, index, mode, osint_ports, evasion_level, strategy_profile)
                )
                return future.result()
        else:
            return asyncio.run(
                self.run_async(ip, out_dir, index, mode, osint_ports, evasion_level, strategy_profile)
            )
