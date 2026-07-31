#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REPORT GENERATOR PLUGIN (V1.0)
================================
Generate HTML pentest report từ M1+M2+M3 JSON outputs.
Sections: Executive Summary, Findings, Risk Matrix, Remediation, Visual Evidence, Appendix.
Self-contained HTML (embedded CSS + Base64 images).
"""

import os
import json
import html
from datetime import datetime
from core.base_plugin import BasePlugin


class ReportPlugin(BasePlugin):
    """Plugin tạo HTML pentest report chuẩn từ output M1+M2+M3."""

    def name(self) -> str:
        return "ReportGenerator"

    def description(self) -> str:
        return "Generate HTML/PDF pentest report từ pipeline output (PTES/OWASP format)"

    def check_installed(self) -> bool:
        return True

    def run(self, m2_json_path: str, out_dir: str = "output",
            target: str = "", mode: str = "", screenshots_dir: str = "", **kwargs) -> str:
        """
        Generate HTML report.

        Args:
            m2_json_path: Path to M2 attack plan JSON
            out_dir: Output directory
            target: Target domain/IP
            mode: Scan mode used
            screenshots_dir: Path to gowitness screenshots directory (optional)

        Returns:
            str: Path to generated HTML report
        """
        os.makedirs(out_dir, exist_ok=True)

        # Load M2 data
        findings = []
        if os.path.exists(m2_json_path):
            with open(m2_json_path, 'r', encoding='utf-8') as f:
                findings = json.load(f)

        # Load screenshots map if available
        screenshots_map = {}
        if screenshots_dir and os.path.exists(screenshots_dir):
            screenshots_map = self._load_screenshots_base64(screenshots_dir)

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        report_file = os.path.join(out_dir, f"pentest_report_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}.html")

        # Generate HTML
        html_content = self._build_html(target, mode, timestamp, findings, screenshots_map)
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        return report_file

    def _load_screenshots_base64(self, screenshots_dir: str) -> dict:
        """
        Load all screenshots from directory and convert to Base64 data URIs.
        Returns dict: {filename_key: data_uri_string}
        """
        import base64
        mapping = {}
        if not os.path.exists(screenshots_dir):
            return mapping

        mime_map = {'.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg'}

        for fname in sorted(os.listdir(screenshots_dir)):
            ext = os.path.splitext(fname)[1].lower()
            if ext not in mime_map:
                continue
            full_path = os.path.join(screenshots_dir, fname)
            try:
                with open(full_path, 'rb') as f:
                    data = f.read()
                b64 = base64.b64encode(data).decode('ascii')
                key = os.path.splitext(fname)[0]
                mapping[key] = f"data:{mime_map[ext]};base64,{b64}"
            except Exception:
                continue
        return mapping

    def _build_html(self, target: str, mode: str, timestamp: str,
                    findings: list, screenshots_map: dict = None) -> str:
        """Build complete HTML report with optional embedded screenshots."""
        screenshots_map = screenshots_map or {}

        # Count by severity
        stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("cvss_severity", "UNKNOWN").lower()
            if sev in stats:
                stats[sev] += 1
            elif f.get("cvss_score", 0) >= 9.0:
                stats["critical"] += 1
            elif f.get("cvss_score", 0) >= 7.0:
                stats["high"] += 1
            elif f.get("cvss_score", 0) >= 4.0:
                stats["medium"] += 1
            else:
                stats["low"] += 1

        kev_count = sum(1 for f in findings if f.get("is_kev"))
        msf_count = sum(1 for f in findings if f.get("msf_ready"))
        
        # [V1.0-SYNC] Specialized findings count
        email_count = sum(1 for f in findings if f.get("vuln_type") == "Email-Leak")
        secret_count = sum(1 for f in findings if "Secret:" in str(f.get("vuln_type")))
        meta_count = sum(1 for f in findings if "Metadata" in str(f.get("vuln_type")))

        findings_html = self._build_findings_table(findings, screenshots_map)
        risk_matrix = self._build_risk_matrix(stats)
        evidence_section = self._build_evidence_gallery(screenshots_map)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PenLabs Security Report — {html.escape(target)}</title>
<style>
:root {{
  /* Premium Dark Space Palette */
  --bg: #090a0f; 
  --card: rgba(22, 25, 37, 0.65);
  --card-hover: rgba(30, 34, 50, 0.85);
  --border: rgba(99, 102, 241, 0.2);
  --border-glow: rgba(99, 102, 241, 0.5);
  
  --text: #f8fafc; 
  --muted: #94a3b8; 
  --accent: #38bdf8; /* Cyber Blue */
  
  /* Severity Colors (Neon Vibe) */
  --critical: #ff003c;
  --critical-glow: rgba(255, 0, 60, 0.4);
  --high: #ff8c00;
  --high-glow: rgba(255, 140, 0, 0.4);
  --medium: #facc15;
  --medium-glow: rgba(250, 204, 21, 0.4);
  --low: #00ff66;
  --low-glow: rgba(0, 255, 102, 0.4);
  --info: #0ea5e9;
  
  /* Gradients */
  --gradient-accent: linear-gradient(135deg, #38bdf8, #818cf8);
}}

* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ 
  font-family: Inter, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
  background-color: var(--bg); 
  background-image: 
    radial-gradient(circle at 15% 50%, rgba(56, 189, 248, 0.05), transparent 25%),
    radial-gradient(circle at 85% 30%, rgba(255, 0, 60, 0.05), transparent 25%);
  color: var(--text); 
  line-height: 1.6; 
  min-height: 100vh;
  overflow-x: hidden;
}}

/* Animations */
@keyframes fadeInUp {{
  from {{ opacity: 0; transform: translateY(20px); }}
  to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes pulseGlow {{
  0% {{ box-shadow: 0 0 10px var(--critical-glow); }}
  50% {{ box-shadow: 0 0 25px var(--critical-glow); }}
  100% {{ box-shadow: 0 0 10px var(--critical-glow); }}
}}

.container {{ 
  max-width: 1400px; 
  margin: 0 auto; 
  padding: 3rem 2rem; 
  animation: fadeInUp 0.8s ease-out forwards;
}}

/* Header Area */
.header {{ 
  text-align: center; 
  padding: 4rem 0; 
  margin-bottom: 3rem; 
  position: relative;
}}
.header::after {{
  content: '';
  position: absolute;
  bottom: 0; left: 50%;
  transform: translateX(-50%);
  width: 150px; height: 3px;
  background: var(--gradient-accent);
  box-shadow: 0 0 15px rgba(56, 189, 248, 0.5);
  border-radius: 2px;
}}
.header h1 {{ 
  font-size: 3rem; 
  font-weight: 800;
  letter-spacing: -0.02em;
  background: var(--gradient-accent);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  margin-bottom: 1rem; 
  text-shadow: 0 0 30px rgba(56, 189, 248, 0.2);
}}
.header .meta {{ 
  color: var(--muted); 
  font-size: 1.05rem; 
  font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', monospace;
}}
.header .meta strong {{ color: var(--text); font-weight: 500; }}

.section {{ margin: 4rem 0; animation: fadeInUp 0.8s ease-out backwards; animation-delay: 0.2s; }}
.section h2 {{ 
  color: #fff; 
  font-size: 1.75rem; 
  font-weight: 600;
  margin-bottom: 2rem; 
  display: flex; align-items: center; gap: 12px;
}}
.section h2::before {{
  content: ''; display: inline-block;
  width: 8px; height: 24px;
  background: var(--accent);
  border-radius: 4px;
  box-shadow: 0 0 10px rgba(56, 189, 248, 0.6);
}}

/* Stat Cards (Glassmorphism) */
.stats {{ 
  display: grid; 
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
  gap: 1.5rem; 
}}
.stat-card {{ 
  background: var(--card); 
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--border); 
  border-radius: 12px; 
  padding: 2rem 1.5rem; 
  text-align: center; 
  transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
  position: relative;
  overflow: hidden;
}}
.stat-card::before {{
  content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
  background: transparent; transition: all 0.3s;
}}
.stat-card:hover {{ 
  transform: translateY(-5px); 
  background: var(--card-hover);
  border-color: var(--border-glow);
  box-shadow: 0 10px 30px rgba(0,0,0,0.5);
}}
.stat-card .number {{ font-size: 3rem; font-weight: 800; font-family: 'Fira Code', monospace; line-height: 1.1; margin-bottom: 0.5rem; }}
.stat-card .label {{ color: var(--muted); font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; }}

/* Severity specific card tops */
.stat-critical::before {{ background: var(--critical); box-shadow: 0 0 15px var(--critical-glow); }}
.stat-critical .number {{ color: var(--critical); text-shadow: 0 0 20px var(--critical-glow); }}
.stat-high::before {{ background: var(--high); box-shadow: 0 0 15px var(--high-glow); }}
.stat-high .number {{ color: var(--high); text-shadow: 0 0 20px var(--high-glow); }}
.stat-medium::before {{ background: var(--medium); box-shadow: 0 0 15px var(--medium-glow); }}
.stat-medium .number {{ color: var(--medium); text-shadow: 0 0 20px var(--medium-glow); }}
.stat-low::before {{ background: var(--low); box-shadow: 0 0 15px var(--low-glow); }}
.stat-low .number {{ color: var(--low); text-shadow: 0 0 20px var(--low-glow); }}

.summary-text {{
  font-size: 1.1rem; color: var(--muted); margin-top: 2rem;
  background: rgba(255,255,255,0.02); padding: 1.5rem; border-radius: 8px;
  border-left: 3px solid var(--accent);
}}
.summary-text strong {{ color: var(--text); }}

/* Data Table */
.table-wrapper {{
  border-radius: 12px;
  overflow: hidden;
  border: 1px solid var(--border);
  box-shadow: 0 15px 35px rgba(0,0,0,0.2);
  background: var(--card);
  backdrop-filter: blur(10px);
}}
table {{ width: 100%; border-collapse: collapse; text-align: left; }}
th, td {{ padding: 1.25rem 1rem; border-bottom: 1px solid rgba(255,255,255,0.05); }}
th {{ 
  background: rgba(0,0,0,0.4); 
  color: var(--muted); 
  font-weight: 600; 
  text-transform: uppercase; 
  font-size: 0.8rem;
  letter-spacing: 0.05em;
}}
tr {{ transition: background 0.2s; }}
tr:hover {{ background: rgba(99, 102, 241, 0.08); }}
td {{ font-size: 0.95rem; vertical-align: middle; }}
td strong {{ font-family: 'Fira Code', monospace; color: var(--text); font-size: 1.05rem; }}

/* Badges */
.badge {{ 
  display: inline-flex; align-items: center; justify-content: center;
  padding: 0.25rem 0.6rem; border-radius: 20px; 
  font-size: 0.75rem; font-weight: 700; text-transform: uppercase; 
  letter-spacing: 0.05em; margin: 0.2rem 0.2rem 0 0;
  backdrop-filter: blur(4px);
  border: 1px solid transparent;
}}
.badge-critical {{ background: rgba(255,0,60,0.15); color: #ff4d79; border-color: rgba(255,0,60,0.3); }}
.badge-high {{ background: rgba(255,140,0,0.15); color: #ffaf4d; border-color: rgba(255,140,0,0.3); }}
.badge-medium {{ background: rgba(250,204,21,0.15); color: #fce34d; border-color: rgba(250,204,21,0.3); }}
.badge-low {{ background: rgba(0,255,102,0.15); color: #4dff94; border-color: rgba(0,255,102,0.3); }}

.badge-kev {{ background: rgba(255,0,60,0.1); border-color: var(--critical); color: var(--critical); box-shadow: 0 0 10px rgba(255,0,60,0.2); animation: pulseGlow 2s infinite; }}
.badge-msf {{ background: rgba(56,189,248,0.1); border-color: var(--accent); color: var(--accent); }}
.badge-verified {{ background: rgba(0,255,102,0.1); border-color: var(--low); color: var(--low); }}
.badge-oob {{ background: rgba(168,85,247,0.15); border-color: #a855f7; color: #d8b4fe; }}
.badge-screenshot {{ background: rgba(255,255,255,0.05); color: #cbd5e1; border-color: rgba(255,255,255,0.1); cursor: pointer; transition: all 0.2s; }}
.badge-screenshot:hover {{ background: rgba(255,255,255,0.1); color: #fff; }}

/* Evidence Gallery */
.evidence-gallery {{ 
  display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); 
  gap: 2rem; 
}}
.evidence-card {{ 
  background: #0f111a; 
  border: 1px solid var(--border); 
  border-radius: 12px; 
  overflow: hidden; 
  transition: all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94); 
}}
.evidence-card:hover {{ 
  transform: translateY(-8px) scale(1.02); 
  box-shadow: 0 20px 40px rgba(0,0,0,0.6), 0 0 20px rgba(56,189,248,0.2); 
  border-color: rgba(56,189,248,0.4);
}}
.evidence-card .img-wrapper {{ position: relative; overflow: hidden; padding-top: 60%; }}
.evidence-card img {{ 
  position: absolute; top: 0; left: 0; width: 100%; height: 100%; object-fit: cover;
  border-bottom: 1px solid rgba(255,255,255,0.05); transition: transform 0.5s; 
}}
.evidence-card:hover img {{ transform: scale(1.05); }}
.evidence-card .caption {{ 
  padding: 1rem; font-size: 0.85rem; color: var(--text); 
  font-family: 'Fira Code', monospace; word-break: break-all;
  background: rgba(0,0,0,0.4);
}}
.finding-screenshot {{ margin-top: 0.8rem; }}
.finding-screenshot img {{ 
  max-width: 240px; border-radius: 6px; border: 1px solid var(--border); 
  cursor: zoom-in; opacity: 0.8; transition: all 0.2s; 
}}
.finding-screenshot img:hover {{ opacity: 1; transform: scale(1.03); box-shadow: 0 5px 15px rgba(0,0,0,0.5); }}

/* Priority List */
.priority-list {{ background: var(--card); border-radius: 12px; border: 1px solid var(--border); padding: 1.5rem 2rem; }}
.priority-list ol {{ margin-left: 1.5rem; color: var(--muted); }}
.priority-list li {{ margin-bottom: 0.8rem; padding-left: 0.5rem; }}
.priority-list li strong {{ font-family: 'Fira Code', monospace; color: var(--critical); font-size: 1.1rem; }}

/* Lightbox overlay */
.lightbox {{ 
  display: flex; opacity: 0; pointer-events: none; 
  position: fixed; inset: 0; background: rgba(0,0,0,0.95); 
  backdrop-filter: blur(5px); z-index: 9999; justify-content: center; align-items: center; 
  transition: opacity 0.3s ease; cursor: zoom-out; 
}}
.lightbox.active {{ opacity: 1; pointer-events: auto; }}
.lightbox img {{ 
  max-width: 90vw; max-height: 90vh; border-radius: 8px; 
  box-shadow: 0 0 40px rgba(56,189,248,0.15); 
  transform: scale(0.95); transition: transform 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}}
.lightbox.active img {{ transform: scale(1); }}

.footer {{ text-align: center; color: var(--muted); padding: 3rem 0; border-top: 1px solid var(--border); font-size: 0.85rem; font-family: 'Fira Code', monospace; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>THREAT INTELLIGENCE REPORT</h1>
    <div class="meta">
      Target: <strong>{html.escape(target)}</strong> &nbsp;|&nbsp; 
      Mode: <strong>{html.escape(mode or 'N/A').upper()}</strong> &nbsp;|&nbsp; 
      Class: <strong>CONFIDENTIAL</strong><br><br>
      Date: {timestamp} &nbsp;|&nbsp; Generated by PenLabs V1.0 Engine
      {' &nbsp;|&nbsp; <span class="badge badge-screenshot">📸 ' + str(len(screenshots_map)) + ' Assets</span>' if screenshots_map else ''}
    </div>
  </div>

  <div class="section" style="animation-delay: 0.1s;">
    <h2>Executive Summary</h2>
    <div class="stats">
      <div class="stat-card stat-critical"><div class="number">{stats['critical']}</div><div class="label">Critical Risks</div></div>
      <div class="stat-card stat-high"><div class="number">{stats['high']}</div><div class="label">High Risks</div></div>
      <div class="stat-card stat-medium"><div class="number">{stats['medium']}</div><div class="label">Medium Risks</div></div>
      <div class="stat-card stat-low"><div class="number">{stats['low']}</div><div class="label">Low Risks</div></div>
      <div class="stat-card" style="border-left: 3px solid var(--accent);"><div class="number" style="color: var(--accent);">{secret_count}</div><div class="label">JS Secrets</div></div>
      <div class="stat-card" style="border-left: 3px solid #10b981;"><div class="number" style="color: #10b981;">{email_count}</div><div class="label">Emails</div></div>
      <div class="stat-card" style="border-color: rgba(255,255,255,0.2);"><div class="number" style="color:#fff;">{len(findings)}</div><div class="label">Total Findings</div></div>
    </div>
    <div class="summary-text">
      Security assessment of <strong>{html.escape(target)}</strong> identified <strong>{len(findings)}</strong> unique vulnerabilities across <strong>{len(set(f.get('target','') for f in findings))}</strong> active targets.<br>
      {"<span style='color: var(--critical);'>⚠️ <strong>" + str(kev_count) + " CVEs are actively exploited in the wild (CISA KEV)</strong>. Immediate remediation required.</span><br>" if kev_count else ""}
      {"<span style='color: var(--accent);'>⚔️ <strong>" + str(msf_count) + " findings have ready-to-use exploit modules</strong>.</span><br>" if msf_count else ""}
      {"<span style='color: #4ade80;'>✅ <strong>" + str(sum(1 for f in findings if f.get('confidence',0) >= 1.0)) + " vulnerabilities confirmed via Out-Of-Band/Live exploitation</strong>.</span>" if any(f.get('confidence',0) >= 1.0 for f in findings) else ""}
    </div>
  </div>

  {risk_matrix}

  <div class="section" style="animation-delay: 0.3s;">
    <h2>Detailed Findings Matrix</h2>
    <div class="table-wrapper">
      {findings_html}
    </div>
  </div>

  {evidence_section}

  <div class="section" style="animation-delay: 0.5s;">
    <h2>Remediation Priorities</h2>
    <div class="priority-list">
      <ol>
        {"".join(f"<li><strong>{html.escape(str(f.get('cve','N/A')))}</strong> (CVSS {f.get('cvss_score', 'N/A')}) &mdash; Target: {html.escape(str(f.get('target', '')))}:{html.escape(str(f.get('port', f.get('rport', 'N/A'))))} {' <span class=\"badge badge-kev\" style=\"margin-left: 10px;\">CISA KEV</span>' if f.get('is_kev') else ''}</li>" for f in sorted(findings, key=lambda x: x.get('priority_score', 0), reverse=True)[:15])}
      </ol>
    </div>
  </div>

  <div class="footer">
    PenLabs V1.0 // Stealth & Precision Red Team Architecture<br>
    Report generated on {timestamp}<br><br>
    <span style="color: var(--critical); font-weight: bold;">RESTRICTED TLP:RED</span>
  </div>
</div>

<div class="lightbox" id="lightbox" onclick="this.classList.remove('active')">
  <img id="lightbox-img" src="" alt="Proof Evidence">
</div>
<script>
function showLightbox(src) {{
  var lb = document.getElementById('lightbox');
  document.getElementById('lightbox-img').src = src;
  lb.classList.add('active');
}}
</script>
</body>
</html>"""

    def _build_findings_table(self, findings: list, screenshots_map: dict = None) -> str:
        """Build HTML table for findings with optional inline screenshots."""
        screenshots_map = screenshots_map or {}
        if not findings:
            return "<p>No findings.</p>"

        rows = []
        for i, f in enumerate(sorted(findings, key=lambda x: x.get("priority_score", 0), reverse=True), 1):
            cve = html.escape(str(f.get("cve", "N/A")))
            target_val = html.escape(str(f.get("target", "N/A")))
            # [BUG-017 FIX] M2 lưu port dưới key 'rport' thay vì 'port'
            port = html.escape(str(f.get("port", f.get("rport", "N/A"))))
            cvss = f.get("cvss_score", 0)
            epss = f.get("epss_score", 0)
            confidence = f.get("confidence", 0)
            priority = f.get("priority_score", 0)

            # Severity badge
            if cvss >= 9.0:
                sev_badge = '<span class="badge badge-critical">CRITICAL</span>'
            elif cvss >= 7.0:
                sev_badge = '<span class="badge badge-high">HIGH</span>'
            elif cvss >= 4.0:
                sev_badge = '<span class="badge badge-medium">MEDIUM</span>'
            else:
                sev_badge = '<span class="badge badge-low">LOW</span>'

            # Tags
            tags = ""
            if f.get("is_kev"):
                tags += ' <span class="badge badge-kev">KEV</span>'
            if f.get("msf_ready"):
                tags += ' <span class="badge badge-msf">MSF</span>'
            if f.get("verified"):
                tags += ' <span class="badge badge-verified">\u2713 VERIFIED</span>'
            if confidence >= 1.0:
                tags += ' <span class="badge badge-oob">\U0001f4e1 OOB</span>'

            # [V1.0] Match screenshot to finding target/port
            screenshot_html = ""
            if screenshots_map:
                screenshot_html = self._match_screenshot_to_finding(
                    target_val, port, screenshots_map
                )

            rows.append(f"""<tr>
<td>{i}</td>
<td><strong>{cve}</strong>{tags}{screenshot_html}</td>
<td>{target_val}:{port}</td>
<td>{sev_badge}<br>CVSS {cvss}</td>
<td>{epss:.1%}</td>
<td>{confidence:.0%}</td>
<td>{priority:.4f}</td>
</tr>""")

        return f"""<table>
<thead><tr>
<th>#</th><th>CVE / Finding</th><th>Target</th><th>Severity</th><th>EPSS</th><th>Confidence</th><th>Priority</th>
</tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>"""

    def _match_screenshot_to_finding(self, target: str, port: str,
                                       screenshots_map: dict) -> str:
        """
        Try to match a finding's target:port to a screenshot.
        Gowitness filenames contain URLs — we do fuzzy matching.
        """
        if not screenshots_map:
            return ""

        # Build search patterns from target and port
        search_patterns = [
            target.replace(".", "-"),
            target,
            f"{target}-{port}",
            f"http-{target.replace('.', '-')}-{port}",
            f"https-{target.replace('.', '-')}-{port}",
        ]

        for key, data_uri in screenshots_map.items():
            key_lower = key.lower()
            for pattern in search_patterns:
                if pattern.lower() in key_lower:
                    return f"""<div class="finding-screenshot">
<img src="{data_uri}" alt="Evidence: {html.escape(target)}:{html.escape(port)}"
     onclick="showLightbox(this.src)" title="Click to enlarge">
<br><span class="badge badge-screenshot">📸 Visual Evidence</span>
</div>"""
        return ""

    def _build_evidence_gallery(self, screenshots_map: dict) -> str:
        """Build a visual evidence gallery section with all screenshots."""
        if not screenshots_map:
            return ""

        cards = []
        for key, data_uri in screenshots_map.items():
            # Reconstruct readable URL from gowitness filename key
            readable = key.replace("-", ".").replace("_", "/")
            cards.append(f"""<div class="evidence-card">
  <div class="img-wrapper">
    <img src="{data_uri}" alt="{html.escape(readable)}" onclick="showLightbox(this.src)">
  </div>
  <div class="caption">{html.escape(readable)}</div>
</div>""")

        return f"""<div class="section" style="animation-delay: 0.4s;">
    <h2>📸 Visual Evidence Gallery <span style="font-size: 1rem; color: var(--muted); font-weight: normal; margin-left: 10px;">({len(screenshots_map)} Screenshots)</span></h2>
    <p style="color: var(--muted); margin-bottom: 2rem; font-size: 0.95rem;">
      Automated visual reconnaissance assets. All imagery is Base64 encoded and statically embedded within this report to preserve OPSEC and eliminate external callbacks. Click to enlarge.
    </p>
    <div class="evidence-gallery">
      {"".join(cards)}
    </div>
  </div>"""

    def _build_risk_matrix(self, stats: dict) -> str:
        """Build visual risk summary."""
        total = sum(stats.values())
        if total == 0:
            return ""

        return f"""<div class="section" style="animation-delay: 0.2s;">
    <h2>Risk Distribution</h2>
    <div class="stats">
      <div class="stat-card">
        <div class="number" style="color: var(--critical); text-shadow: 0 0 15px var(--critical-glow);">{stats['critical']/total*100:.0f}%</div>
        <div class="label">Critical</div>
      </div>
      <div class="stat-card">
        <div class="number" style="color: var(--high); text-shadow: 0 0 15px var(--high-glow);">{stats['high']/total*100:.0f}%</div>
        <div class="label">High</div>
      </div>
      <div class="stat-card">
        <div class="number" style="color: var(--medium); text-shadow: 0 0 15px var(--medium-glow);">{stats['medium']/total*100:.0f}%</div>
        <div class="label">Medium</div>
      </div>
    </div>
  </div>"""
