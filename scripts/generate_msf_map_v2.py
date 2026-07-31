#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FILE: scripts/generate_msf_map_v2.py
# CHỨC NĂNG: Crawl toàn bộ Metasploit modules từ Ruby source files,
#            trích xuất metadata (CVE, Port, Platform, Rank, Service Keywords),
#            tạo Multi-Key Index Database cho Smart Lookup Engine.
#
# USAGE:
#   python3 scripts/generate_msf_map_v2.py
#   python3 scripts/generate_msf_map_v2.py --msf-path /opt/metasploit-framework
#   python3 scripts/generate_msf_map_v2.py --include-post  # Include post-exploitation modules

import os
import sys
import re
import json
import argparse
import glob
from datetime import datetime
from collections import defaultdict

# ═══════════════════════════════════════════════
# Rank scoring (consistent with msf_dynamic_search.py)
# ═══════════════════════════════════════════════
RANK_MAP = {
    "ManualRanking": "manual",
    "LowRanking": "low",
    "AverageRanking": "average",
    "NormalRanking": "normal",
    "GoodRanking": "good",
    "GreatRanking": "great",
    "ExcellentRanking": "excellent",
}

RANK_SCORES = {
    "excellent": 100,
    "great": 90,
    "good": 80,
    "normal": 70,
    "average": 60,
    "low": 50,
    "manual": 10,
}

# ═══════════════════════════════════════════════
# Service keyword extraction from module paths
# ═══════════════════════════════════════════════
# Map directory names / path fragments → normalized service names
PATH_SERVICE_MAP = {
    "ftp": "ftp",
    "ssh": "ssh",
    "telnet": "telnet",
    "smtp": "smtp",
    "dns": "dns",
    "http": "http",
    "https": "http",
    "imap": "imap",
    "pop3": "pop3",
    "smb": "smb",
    "samba": "smb",
    "netbios": "smb",
    "rdp": "rdp",
    "vnc": "vnc",
    "mysql": "mysql",
    "postgres": "postgres",
    "postgresql": "postgres",
    "mssql": "mssql",
    "oracle": "oracle",
    "mongodb": "mongodb",
    "redis": "redis",
    "ldap": "ldap",
    "snmp": "snmp",
    "nfs": "nfs",
    "rpc": "rpc",
    "irc": "irc",
    "docker": "docker",
    "kubernetes": "kubernetes",
    "k8s": "kubernetes",
    "jenkins": "jenkins",
    "tomcat": "tomcat",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "weblogic": "weblogic",
    "jboss": "jboss",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "php": "php",
    "java": "java",
    "rmi": "java_rmi",
    "python": "python",
    "ruby": "ruby",
    "nodejs": "nodejs",
    "exchange": "exchange",
    "sharepoint": "sharepoint",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "elastic": "elasticsearch",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "grafana": "grafana",
    "nagios": "nagios",
    "zabbix": "zabbix",
    "citrix": "citrix",
    "vmware": "vmware",
    "vcenter": "vmware",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "paloalto": "paloalto",
    "sonicwall": "sonicwall",
    "pulse": "pulse_secure",
    "samba": "smb",
    "cups": "cups",
    "proftpd": "ftp",
    "vsftpd": "ftp",
    "distcc": "distcc",
    "ntp": "ntp",
    "sip": "sip",
    "pptp": "pptp",
    "wireguard": "wireguard",
    "openvpn": "openvpn",
}

# Nuclei template ID → service mapping (for cross-referencing)
NUCLEI_SERVICE_MAP = {
    "tomcat": "tomcat",
    "apache": "apache",
    "nginx": "nginx",
    "iis": "iis",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "jenkins": "jenkins",
    "gitlab": "gitlab",
    "confluence": "confluence",
    "grafana": "grafana",
    "elasticsearch": "elasticsearch",
    "kibana": "kibana",
    "redis": "redis",
    "mongodb": "mongodb",
    "postgres": "postgres",
    "pgsql": "postgres",
    "mysql": "mysql",
    "mssql": "mssql",
    "ftp": "ftp",
    "ssh": "ssh",
    "smb": "smb",
    "vnc": "vnc",
    "rdp": "rdp",
    "exchange": "exchange",
    "weblogic": "weblogic",
    "jboss": "jboss",
    "docker": "docker",
    "spring": "spring",
    "struts": "struts",
    "php": "php",
    "citrix": "citrix",
    "fortinet": "fortinet",
    "fortigate": "fortinet",
    "sonicwall": "sonicwall",
    "pulse": "pulse_secure",
    "vmware": "vmware",
    "vcenter": "vmware",
}


def extract_module_path(filepath, msf_modules_dir):
    """Convert filesystem path → MSF module path (e.g. exploit/unix/ftp/vsftpd_234_backdoor)."""
    rel = os.path.relpath(filepath, msf_modules_dir)
    # Remove .rb extension
    if rel.endswith(".rb"):
        rel = rel[:-3]
    return rel


def parse_ruby_module(filepath, msf_modules_dir):
    """
    Parse a Metasploit Ruby module file and extract metadata.
    Uses regex on raw Ruby source — no Ruby interpreter needed.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return None

    module_path = extract_module_path(filepath, msf_modules_dir)
    
    # Determine module type from path
    if module_path.startswith("exploits/"):
        module_type = "exploit"
        # Normalize: exploits/ → exploit/ (MSF convention)
        module_path = "exploit/" + module_path[len("exploits/"):]
    elif module_path.startswith("auxiliary/"):
        module_type = "auxiliary"
    elif module_path.startswith("post/"):
        module_type = "post"
    else:
        return None

    result = {
        "module_path": module_path,
        "type": module_type,
        "name": "",
        "rank": "normal",
        "rank_score": RANK_SCORES["normal"],
        "cves": [],
        "edb_ids": [],
        "bid_ids": [],
        "osvdb_ids": [],
        "urls": [],
        "default_port": None,
        "platforms": [],
        "archs": [],
        "service_keywords": [],
        "disclosure_date": "",
        "description": "",
    }

    # ─── Extract Rank ───
    rank_match = re.search(r"Rank\s*=\s*(\w+Ranking)", content)
    if rank_match:
        rank_const = rank_match.group(1)
        result["rank"] = RANK_MAP.get(rank_const, "normal")
        result["rank_score"] = RANK_SCORES.get(result["rank"], 70)

    # ─── Extract Name ───
    name_match = re.search(r"'Name'\s*=>\s*'([^']+)'", content)
    if not name_match:
        name_match = re.search(r'"Name"\s*=>\s*"([^"]+)"', content)
    if name_match:
        result["name"] = name_match.group(1)

    # ─── Extract Description (first line) ───
    desc_match = re.search(r"'Description'\s*=>\s*%[qQ]?\{([^}]{0,200})", content)
    if not desc_match:
        desc_match = re.search(r"'Description'\s*=>\s*'([^']{0,200})'", content)
    if desc_match:
        result["description"] = desc_match.group(1).strip().replace("\n", " ")[:200]

    # ─── Extract CVE References ───
    cve_matches = re.findall(r"\[\s*'CVE'\s*,\s*'(\d{4}-\d+)'\s*\]", content)
    result["cves"] = [f"CVE-{c}" for c in cve_matches]

    # ─── Extract EDB References ───
    edb_matches = re.findall(r"\[\s*'EDB'\s*,\s*'(\d+)'\s*\]", content)
    result["edb_ids"] = edb_matches

    # ─── Extract BID References ───
    bid_matches = re.findall(r"\[\s*'BID'\s*,\s*'(\d+)'\s*\]", content)
    result["bid_ids"] = bid_matches

    # ─── Extract OSVDB References ───
    osvdb_matches = re.findall(r"\[\s*'OSVDB'\s*,\s*'(\d+)'\s*\]", content)
    result["osvdb_ids"] = osvdb_matches

    # ─── Extract URL References ───
    url_matches = re.findall(r"\[\s*'URL'\s*,\s*'([^']+)'\s*\]", content)
    result["urls"] = url_matches[:5]  # Limit to 5

    # ─── Extract Default Port (RPORT) ───
    rport_match = re.search(r"Opt::RPORT\((\d+)\)", content)
    if rport_match:
        result["default_port"] = int(rport_match.group(1))
    else:
        # Alternative pattern: register_options with RPORT
        rport_alt = re.search(r"'RPORT'\s*(?:,\s*\[|\]\s*,\s*)\s*(\d+)", content)
        if rport_alt:
            result["default_port"] = int(rport_alt.group(1))
        else:
            # Check DefaultPort in OptPort
            rport_default = re.search(r"OptPort\.new\(\s*'RPORT'\s*,\s*\[.*?(\d+)", content)
            if rport_default:
                result["default_port"] = int(rport_default.group(1))

    # ─── Extract Platform ───
    platform_match = re.search(r"'Platform'\s*=>\s*(?:\[([^\]]+)\]|%w\{([^}]+)\}|'([^']+)')", content)
    if platform_match:
        raw = platform_match.group(1) or platform_match.group(2) or platform_match.group(3)
        platforms = re.findall(r"'(\w+)'|\b(\w+)\b", raw)
        result["platforms"] = list(set(p[0] or p[1] for p in platforms if (p[0] or p[1]).lower() not in ("true", "false", "nil", "w")))

    # ─── Extract Arch ───
    arch_match = re.search(r"'Arch'\s*=>\s*(?:\[([^\]]+)\]|(\w+))", content)
    if arch_match:
        raw = arch_match.group(1) or arch_match.group(2)
        if raw:
            archs = re.findall(r"ARCH_(\w+)", raw)
            result["archs"] = [a.lower() for a in archs]

    # ─── Extract Disclosure Date ───
    date_match = re.search(r"'DisclosureDate'\s*=>\s*'([^']+)'", content)
    if date_match:
        result["disclosure_date"] = date_match.group(1)

    # ─── Extract Service Keywords from Path + Name ───
    path_parts = module_path.lower().replace("_", " ").split("/")
    name_lower = result["name"].lower().replace("_", " ") if result["name"] else ""
    
    keywords = set()
    for part in path_parts:
        for trigger, svc in PATH_SERVICE_MAP.items():
            if trigger in part:
                keywords.add(svc)
    
    # Also extract from module Name
    for trigger, svc in PATH_SERVICE_MAP.items():
        if trigger in name_lower:
            keywords.add(svc)
    
    # Add product-specific keywords from name
    name_words = re.findall(r'\b\w+\b', name_lower)
    for word in name_words:
        if word in PATH_SERVICE_MAP:
            keywords.add(PATH_SERVICE_MAP[word])

    result["service_keywords"] = sorted(keywords)

    return result


def build_multi_key_index(modules):
    """Build the multi-key lookup index from parsed modules."""
    
    by_cve = defaultdict(list)
    by_port = defaultdict(list)
    by_service = defaultdict(list)
    by_edb = defaultdict(list)
    by_product = defaultdict(list)  # NEW: fuzzy product name matching
    
    # Compact record for index entries
    def compact(m):
        entry = {
            "path": m["module_path"],
            "name": m["name"],
            "type": m["type"],
            "rank": m["rank"],
            "rank_score": m["rank_score"],
        }
        if m["default_port"]:
            entry["default_port"] = m["default_port"]
        if m["platforms"]:
            entry["platforms"] = m["platforms"]
        if m["cves"]:
            entry["cves"] = m["cves"]
        if m["disclosure_date"]:
            entry["date"] = m["disclosure_date"]
        return entry

    for m in modules:
        c = compact(m)
        
        # Index by CVE
        for cve in m["cves"]:
            by_cve[cve].append(c)
        
        # Index by default port
        if m["default_port"]:
            by_port[str(m["default_port"])].append(c)
        
        # Index by service keywords
        for svc in m["service_keywords"]:
            by_service[svc].append(c)
        
        # Index by EDB ID
        for edb in m["edb_ids"]:
            by_edb[edb].append(c)
        
        # Index by product keywords (from name)
        if m["name"]:
            # Extract product name tokens
            name_tokens = set(re.findall(r'\b[a-z]{3,}\b', m["name"].lower()))
            # Filter out common/stop words
            stop_words = {"the", "and", "for", "via", "with", "from", "this", "that",
                         "code", "execution", "remote", "buffer", "overflow", "command",
                         "injection", "arbitrary", "file", "read", "write", "upload",
                         "download", "server", "client", "service", "daemon", "local",
                         "privilege", "escalation", "authenticated", "unauthenticated",
                         "exploit", "module", "vulnerability", "version", "multiple",
                         "stack", "heap", "based", "denial", "bypass", "default"}
            product_tokens = name_tokens - stop_words
            for token in product_tokens:
                if len(token) >= 3:
                    by_product[token].append(c)

    # Sort each index by rank_score (highest first), exploit > auxiliary
    def sort_entries(entries):
        return sorted(entries, key=lambda x: (
            0 if x["type"] == "exploit" else 1,
            -x["rank_score"]
        ))
    
    for key in by_cve:
        by_cve[key] = sort_entries(by_cve[key])
    for key in by_port:
        by_port[key] = sort_entries(by_port[key])
    for key in by_service:
        by_service[key] = sort_entries(by_service[key])
    for key in by_edb:
        by_edb[key] = sort_entries(by_edb[key])
    # by_product is too large to sort per-key; done at query time
    
    return dict(by_cve), dict(by_port), dict(by_service), dict(by_edb), dict(by_product)


def main():
    parser = argparse.ArgumentParser(description="MSF Module Map Generator V2 — Crawl & Index ALL Metasploit modules")
    parser.add_argument("--msf-path", default="/usr/share/metasploit-framework",
                        help="Path to Metasploit Framework installation")
    parser.add_argument("--output", default=None,
                        help="Output JSON file path (default: data/msf_module_map.json)")
    parser.add_argument("--include-post", action="store_true",
                        help="Include post-exploitation modules in the map")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed progress")
    args = parser.parse_args()

    msf_modules_dir = os.path.join(args.msf_path, "modules")
    
    if not os.path.isdir(msf_modules_dir):
        print(f"\033[91m❌ Không tìm thấy thư mục modules: {msf_modules_dir}\033[0m")
        print(f"   Thử: python3 {sys.argv[0]} --msf-path /opt/metasploit-framework")
        sys.exit(1)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        output_path = os.path.join(project_root, "data", "msf_module_map.json")
    
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║   MSF MODULE MAP GENERATOR V2 — Full Offline Index         ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"  MSF Path:  {msf_modules_dir}")
    print(f"  Output:    {output_path}")
    print(f"  Post Mods: {'✓' if args.include_post else '✗'}")
    print()

    # ═══════════════════════════════════════════════
    # Phase 1: Discover module files
    # ═══════════════════════════════════════════════
    scan_dirs = ["exploits", "auxiliary"]
    if args.include_post:
        scan_dirs.append("post")
    
    rb_files = []
    for subdir in scan_dirs:
        full_dir = os.path.join(msf_modules_dir, subdir)
        if os.path.isdir(full_dir):
            found = glob.glob(os.path.join(full_dir, "**", "*.rb"), recursive=True)
            rb_files.extend(found)
            print(f"  [{subdir.upper():>10}] Discovered {len(found)} .rb files")
    
    print(f"\n  [TOTAL] {len(rb_files)} module files to parse\n")

    # ═══════════════════════════════════════════════
    # Phase 2: Parse all modules
    # ═══════════════════════════════════════════════
    all_modules = []
    parse_errors = 0
    
    for i, filepath in enumerate(rb_files):
        if args.verbose and (i + 1) % 500 == 0:
            print(f"  ... parsed {i + 1}/{len(rb_files)} modules")
        
        mod = parse_ruby_module(filepath, msf_modules_dir)
        if mod:
            all_modules.append(mod)
        else:
            parse_errors += 1

    print(f"  [PARSED] {len(all_modules)} modules successfully ({parse_errors} errors)")

    # ═══════════════════════════════════════════════
    # Phase 3: Statistics
    # ═══════════════════════════════════════════════
    stats = {
        "total": len(all_modules),
        "exploits": sum(1 for m in all_modules if m["type"] == "exploit"),
        "auxiliary": sum(1 for m in all_modules if m["type"] == "auxiliary"),
        "post": sum(1 for m in all_modules if m["type"] == "post"),
        "with_cve": sum(1 for m in all_modules if m["cves"]),
        "without_cve": sum(1 for m in all_modules if not m["cves"]),
        "with_port": sum(1 for m in all_modules if m["default_port"]),
        "unique_cves": len(set(c for m in all_modules for c in m["cves"])),
        "unique_ports": len(set(m["default_port"] for m in all_modules if m["default_port"])),
        "unique_services": len(set(s for m in all_modules for s in m["service_keywords"])),
        "rank_distribution": {},
    }
    
    for rank in RANK_SCORES:
        count = sum(1 for m in all_modules if m["rank"] == rank)
        if count:
            stats["rank_distribution"][rank] = count

    print(f"\n  ┌──────────────────────────────────────────┐")
    print(f"  │           MODULE STATISTICS               │")
    print(f"  ├──────────────────────────────────────────┤")
    print(f"  │ Total Modules:     {stats['total']:>6}                │")
    print(f"  │   Exploits:        {stats['exploits']:>6}                │")
    print(f"  │   Auxiliary:       {stats['auxiliary']:>6}                │")
    print(f"  │   Post:            {stats['post']:>6}                │")
    print(f"  │ With CVE:          {stats['with_cve']:>6}                │")
    print(f"  │ Without CVE:       {stats['without_cve']:>6}  ← NEW!     │")
    print(f"  │ Unique CVEs:       {stats['unique_cves']:>6}                │")
    print(f"  │ Unique Ports:      {stats['unique_ports']:>6}                │")
    print(f"  │ Unique Services:   {stats['unique_services']:>6}                │")
    print(f"  └──────────────────────────────────────────┘")
    
    print(f"\n  Rank Distribution:")
    for rank, count in sorted(stats["rank_distribution"].items(), 
                               key=lambda x: RANK_SCORES.get(x[0], 0), reverse=True):
        bar = "█" * (count // 20)
        print(f"    {rank:>10}: {count:>5}  {bar}")

    # ═══════════════════════════════════════════════
    # Phase 4: Build Multi-Key Index
    # ═══════════════════════════════════════════════
    print(f"\n  [INDEX] Building multi-key lookup index...")
    by_cve, by_port, by_service, by_edb, by_product = build_multi_key_index(all_modules)

    print(f"    by_cve:     {len(by_cve)} entries")
    print(f"    by_port:    {len(by_port)} entries")
    print(f"    by_service: {len(by_service)} entries")
    print(f"    by_edb:     {len(by_edb)} entries")
    print(f"    by_product: {len(by_product)} entries")

    # ═══════════════════════════════════════════════
    # Phase 5: Write output
    # ═══════════════════════════════════════════════
    output = {
        "_meta": {
            "version": "2.0",
            "generated_at": datetime.now().isoformat(),
            "msf_path": args.msf_path,
            "total_modules": stats["total"],
            "total_cves": stats["unique_cves"],
            "stats": stats,
        },
        "by_cve": by_cve,
        "by_port": by_port,
        "by_service": by_service,
        "by_edb": by_edb,
        "by_product": by_product,
        "nuclei_service_map": NUCLEI_SERVICE_MAP,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    file_size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"\n  \033[92m✅ HOÀN TẤT!\033[0m")
    print(f"  Output: {output_path} ({file_size_mb:.1f} MB)")
    print(f"  Tổng: {stats['total']} modules → {stats['unique_cves']} CVE + {stats['without_cve']} non-CVE modules indexed")
    print(f"\n  Top 5 ports by module count:")
    top_ports = sorted(by_port.items(), key=lambda x: len(x[1]), reverse=True)[:5]
    for port, mods in top_ports:
        print(f"    Port {port:>5}: {len(mods)} modules")
    
    print(f"\n  Top 5 services by module count:")
    top_svcs = sorted(by_service.items(), key=lambda x: len(x[1]), reverse=True)[:5]
    for svc, mods in top_svcs:
        print(f"    {svc:>15}: {len(mods)} modules")


if __name__ == "__main__":
    main()
