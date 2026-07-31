import os
import json
import re
import logging
import subprocess
import shutil
import socket
import requests
from core.base_plugin import BasePlugin


class CloudDevOpsPlugin(BasePlugin):
    """Cloud & DevOps Recon — S3 Buckets, Subdomain Takeover, DevOps Leaks."""

    def name(self) -> str:
        return "CloudDevOps"

    def description(self) -> str:
        return "Cloud/DevOps Scanner — S3 bucket enum, subdomain takeover, exposed Docker/K8s ports, Nuclei cloud templates."

    def check_installed(self) -> bool:
        return True

    def run(self, target: str, ip: str = "", out_dir: str = "/tmp") -> dict:
        """
        Chạy toàn bộ Cloud/DevOps recon pipeline.

        Returns:
            dict: {
                "bucket_findings": [...],
                "takeover_candidates": [...],
                "devops_exposed": [...],
                "nuclei_cloud": [...],
            }
        """
        os.makedirs(out_dir, exist_ok=True)

        results = {
            "bucket_findings": [],
            "takeover_candidates": [],
            "devops_exposed": [],
            "nuclei_cloud": [],
        }

        # 1. S3/Cloud Bucket Fuzzing
        logging.info(f"[CloudDevOps] Scanning cloud buckets for {target}...")
        results["bucket_findings"] = self._check_buckets(target)

        # 2. Subdomain Takeover Detection
        logging.info(f"[CloudDevOps] Checking subdomain takeover for {target}...")
        results["takeover_candidates"] = self._check_subdomain_takeover(target)

        # 3. Exposed DevOps Ports
        if ip:
            logging.info(f"[CloudDevOps] Checking exposed DevOps ports on {ip}...")
            results["devops_exposed"] = self._check_devops_ports(ip)

        # 4. Nuclei Cloud Templates
        if shutil.which("nuclei"):
            logging.info(f"[CloudDevOps] Running Nuclei cloud templates...")
            results["nuclei_cloud"] = self._run_nuclei_cloud(target, out_dir)

        return results

    def _check_buckets(self, target: str) -> list:
        """Kiểm tra các S3/Azure/GCP buckets dựa trên tên miền."""
        findings = []
        # Sinh các tên bucket phổ biến từ domain
        try:
            import tldextract
        except ImportError:
            logging.warning("[CloudDevOps] tldextract not installed, skipping bucket enumeration")
            return findings
        ext = tldextract.extract(target)
        company = ext.domain
        base = target.replace(".", "-").replace("www-", "")

        bucket_names = [
            company, f"{company}-dev", f"{company}-staging", f"{company}-prod",
            f"{company}-backup", f"{company}-assets", f"{company}-uploads",
            f"{company}-static", f"{company}-data", f"{company}-logs",
            f"{company}-internal", f"{company}-test", f"{company}-cdn",
            base, f"{base}-backup", f"{base}-assets",
        ]

        # AWS S3
        for name in bucket_names:
            url = f"https://{name}.s3.amazonaws.com"
            try:
                r = requests.head(url, timeout=5, allow_redirects=True)
                if r.status_code in [200, 403]:
                    status = "PUBLIC_READ" if r.status_code == 200 else "EXISTS_NO_READ"
                    findings.append({
                        "provider": "AWS_S3",
                        "bucket": name,
                        "url": url,
                        "status": status,
                        "severity": "critical" if r.status_code == 200 else "info",
                    })
            except requests.RequestException:
                continue

        # Azure Blob Storage
        for name in bucket_names[:8]:  # Giới hạn để tránh quá nhiều
            url = f"https://{name}.blob.core.windows.net"
            try:
                r = requests.head(url, timeout=5)
                if r.status_code != 404:
                    findings.append({
                        "provider": "Azure_Blob",
                        "bucket": name,
                        "url": url,
                        "status": "EXISTS",
                        "severity": "medium",
                    })
            except requests.RequestException:
                continue

        # GCP Storage
        for name in bucket_names[:8]:
            url = f"https://storage.googleapis.com/{name}"
            try:
                r = requests.head(url, timeout=5)
                if r.status_code in [200, 403]:
                    status = "PUBLIC_READ" if r.status_code == 200 else "EXISTS_NO_READ"
                    findings.append({
                        "provider": "GCP_Storage",
                        "bucket": name,
                        "url": url,
                        "status": status,
                        "severity": "critical" if r.status_code == 200 else "info",
                    })
            except requests.RequestException:
                continue

        return findings

    # CNAME fingerprints cho các dịch vụ cloud phổ biến bị dangling
    TAKEOVER_FINGERPRINTS = {
        "s3.amazonaws.com": "AWS S3",
        "herokuapp.com": "Heroku",
        "ghost.io": "Ghost",
        "github.io": "GitHub Pages",
        "azurewebsites.net": "Azure",
        "cloudfront.net": "AWS CloudFront",
        "elasticbeanstalk.com": "AWS Elastic Beanstalk",
        "zendesk.com": "Zendesk",
        "shopify.com": "Shopify",
        "fastly.net": "Fastly",
        "pantheon.io": "Pantheon",
        "unbouncepages.com": "Unbounce",
        "surge.sh": "Surge",
        "bitbucket.io": "Bitbucket",
        "readme.io": "ReadMe",
    }

    def _check_subdomain_takeover(self, target: str) -> list:
        """Kiểm tra CNAME dangling cho subdomain takeover."""
        candidates = []
        # Chỉ check trên domain gốc — SubdomainHunter plugin sẽ cung cấp danh sách đầy đủ hơn
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            try:
                answers = resolver.resolve(target, 'CNAME')
                for rdata in answers:
                    cname = str(rdata.target).rstrip('.')
                    for fingerprint, service in self.TAKEOVER_FINGERPRINTS.items():
                        if fingerprint in cname:
                            # Verify: thử truy cập xem có trả về lỗi service not found không
                            try:
                                r = requests.get(f"http://{target}", timeout=5, allow_redirects=False)
                                if r.status_code in [404, 502, 503] or "NoSuchBucket" in r.text or "There isn't a GitHub Pages" in r.text:
                                    candidates.append({
                                        "subdomain": target,
                                        "cname": cname,
                                        "service": service,
                                        "status": "VULNERABLE",
                                        "severity": "critical",
                                    })
                            except requests.RequestException:
                                candidates.append({
                                    "subdomain": target,
                                    "cname": cname,
                                    "service": service,
                                    "status": "POTENTIALLY_VULNERABLE",
                                    "severity": "high",
                                })
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
        except ImportError:
            logging.warning("[CloudDevOps] dnspython not installed, skipping takeover check")

        return candidates

    # Các port DevOps thường bị expose
    DEVOPS_PORTS = {
        2375: {"service": "Docker API (unencrypted)", "severity": "critical"},
        2376: {"service": "Docker API (TLS)", "severity": "high"},
        5000: {"service": "Docker Registry", "severity": "high"},
        8500: {"service": "Consul", "severity": "high"},
        8200: {"service": "Vault", "severity": "critical"},
        2379: {"service": "etcd", "severity": "critical"},
        2380: {"service": "etcd peer", "severity": "high"},
        10250: {"service": "Kubelet API", "severity": "critical"},
        10255: {"service": "Kubelet Read-Only", "severity": "high"},
        6443: {"service": "Kubernetes API Server", "severity": "critical"},
        8443: {"service": "Kubernetes Dashboard", "severity": "high"},
        9090: {"service": "Prometheus", "severity": "medium"},
        3000: {"service": "Grafana", "severity": "medium"},
        9200: {"service": "Elasticsearch", "severity": "high"},
        5601: {"service": "Kibana", "severity": "high"},
        6379: {"service": "Redis", "severity": "high"},
        27017: {"service": "MongoDB", "severity": "critical"},
    }

    def _check_devops_ports(self, ip: str) -> list:
        """Quick TCP connect scan on common DevOps ports."""
        exposed = []
        for port, info in self.DEVOPS_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    exposed.append({
                        "port": port,
                        "service": info["service"],
                        "severity": info["severity"],
                        "status": "OPEN",
                    })
            except Exception:
                continue

        return exposed

    def _run_nuclei_cloud(self, target: str, out_dir: str) -> list:
        """Chạy Nuclei với cloud-specific templates."""
        jsonl_file = os.path.join(out_dir, "nuclei_cloud.jsonl")
        cmd = [
            "nuclei",
            "-target", target,
            "-tags", "cloud,aws,azure,gcp,kubernetes,docker,devops,exposure",
            "-jsonl",
            "-output", jsonl_file,
            "-severity", "medium,high,critical",
            "-silent",
            "-rate-limit", "100",
        ]

        try:
            import sys
            if "--debug" in sys.argv:
                subprocess.run(cmd, timeout=600)
            else:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logging.warning(f"[CloudDevOps] Nuclei cloud scan failed: {e}")
            return []

        findings = []
        if os.path.exists(jsonl_file):
            try:
                with open(jsonl_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            try:
                                findings.append(json.loads(line.strip()))
                            except json.JSONDecodeError:
                                continue
            except Exception as e:
                logging.warning(f"[CloudDevOps] Failed to parse nuclei cloud output: {e}")

        return findings

    # ================================================================
    # [V1.0] ADVANCED CLOUD AUDIT METHODS
    # ================================================================

    def _check_imds(self, ip: str) -> list:
        """[V1.0] Probe cloud metadata services (IMDS) — SSRF vector detection."""
        findings = []
        imds_endpoints = [
            # AWS EC2 IMDSv1 (no token required)
            {"url": f"http://{ip}/latest/meta-data/", "provider": "AWS_IMDS",
             "severity": "critical", "note": "AWS IMDSv1 — direct access without token"},
            # GCP Metadata
            {"url": f"http://{ip}/computeMetadata/v1/", "provider": "GCP_Metadata",
             "headers": {"Metadata-Flavor": "Google"}, "severity": "critical",
             "note": "GCP metadata endpoint"},
            # Azure IMDS
            {"url": f"http://{ip}/metadata/instance?api-version=2021-02-01",
             "provider": "Azure_IMDS", "headers": {"Metadata": "true"},
             "severity": "critical", "note": "Azure IMDS endpoint"},
        ]

        # Also check the standard metadata IP from the target
        metadata_ip = "169.254.169.254"
        for ep in [
            {"url": f"http://{metadata_ip}/latest/meta-data/", "provider": "AWS_IMDS_Std",
             "severity": "info", "note": "Standard AWS metadata IP (requires SSRF to exploit)"},
        ]:
            imds_endpoints.append(ep)

        for ep in imds_endpoints:
            try:
                headers = ep.get("headers", {})
                r = requests.get(ep["url"], headers=headers, timeout=3, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    findings.append({
                        "provider": ep["provider"],
                        "url": ep["url"],
                        "severity": ep["severity"],
                        "status": "ACCESSIBLE",
                        "note": ep.get("note", ""),
                        "response_preview": r.text[:200],
                    })
            except requests.RequestException:
                continue

        return findings

    def _check_k8s_api(self, ip: str) -> list:
        """[V1.0] Check Kubernetes API for anonymous access."""
        findings = []
        k8s_endpoints = [
            {"path": "/api/v1", "port": 6443, "name": "K8s API v1"},
            {"path": "/api/v1/namespaces", "port": 6443, "name": "K8s Namespaces"},
            {"path": "/api/v1/pods", "port": 6443, "name": "K8s Pods"},
            {"path": "/api/v1/secrets", "port": 6443, "name": "K8s Secrets"},
            {"path": "/apis", "port": 6443, "name": "K8s API Groups"},
            {"path": "/healthz", "port": 6443, "name": "K8s Health"},
            {"path": "/pods", "port": 10250, "name": "Kubelet Pods"},
            {"path": "/metrics", "port": 10255, "name": "Kubelet Metrics"},
        ]

        for ep in k8s_endpoints:
            for scheme in ["https", "http"]:
                try:
                    url = f"{scheme}://{ip}:{ep['port']}{ep['path']}"
                    r = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                    if r.status_code in [200, 201]:
                        severity = "critical" if "secrets" in ep["path"] else "high"
                        findings.append({
                            "endpoint": ep["name"],
                            "url": url,
                            "status_code": r.status_code,
                            "severity": severity,
                            "anonymous_access": True,
                            "response_preview": r.text[:200],
                        })
                        break  # Don't check both schemes
                except requests.RequestException:
                    continue

        return findings

    def _check_cicd_exposure(self, target: str) -> list:
        """[V1.0] Detect exposed CI/CD configuration files."""
        findings = []
        ci_paths = [
            {"path": "/.github/workflows/", "name": "GitHub Actions"},
            {"path": "/Jenkinsfile", "name": "Jenkins Pipeline"},
            {"path": "/.gitlab-ci.yml", "name": "GitLab CI"},
            {"path": "/.circleci/config.yml", "name": "CircleCI"},
            {"path": "/.env", "name": "Environment Variables"},
            {"path": "/.env.local", "name": "Local Env Variables"},
            {"path": "/.env.production", "name": "Production Env Variables"},
            {"path": "/docker-compose.yml", "name": "Docker Compose"},
            {"path": "/terraform.tfstate", "name": "Terraform State"},
            {"path": "/.terraform/", "name": "Terraform Directory"},
            {"path": "/webpack.config.js", "name": "Webpack Config"},
            {"path": "/.git/config", "name": "Git Config"},
            {"path": "/.git/HEAD", "name": "Git HEAD"},
            {"path": "/wp-config.php.bak", "name": "WordPress Config Backup"},
        ]

        for scheme in ["https", "http"]:
            for ci in ci_paths:
                try:
                    url = f"{scheme}://{target}{ci['path']}"
                    r = requests.get(url, timeout=5, verify=False, allow_redirects=False)
                    if r.status_code == 200 and len(r.text) > 5:
                        # Check for false positives (generic 200 pages)
                        if "404" not in r.text.lower()[:100] and "not found" not in r.text.lower()[:100]:
                            severity = "critical" if any(x in ci["path"] for x in [".env", "tfstate", "config"]) else "high"
                            findings.append({
                                "file": ci["name"],
                                "url": url,
                                "severity": severity,
                                "status": "EXPOSED",
                                "content_preview": r.text[:200],
                            })
                except requests.RequestException:
                    continue
            if findings:
                break  # If found on one scheme, skip the other

        return findings

    # Secret patterns (compiled once)
    SECRET_PATTERNS = {
        "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "AWS Secret Key": re.compile(r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]'),
        "GCP Service Account": re.compile(r'"type"\s*:\s*"service_account"'),
        "Generic API Key": re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*[\'"][a-zA-Z0-9]{20,}[\'"]'),
        "JWT Token": re.compile(r'eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+'),
        "Private Key": re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "GitHub Token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        "Slack Token": re.compile(r'xox[baprs]-[0-9]{10,13}-[a-zA-Z0-9-]+'),
        "Generic Password": re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*[\'"][^\'"]{6,}[\'"]'),
    }

    def _scan_secrets_in_response(self, text: str) -> list:
        """[V1.0] Scan HTTP response body for leaked secrets."""
        findings = []
        for secret_name, pattern in self.SECRET_PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                findings.append({
                    "type": secret_name,
                    "count": len(matches),
                    "severity": "critical",
                    "preview": str(matches[0])[:50] + "..." if matches else "",
                })
        return findings
