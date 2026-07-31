# P1-2: Cloud-native Plugin chuyên biệt — DETAILED PLAN

## Hiện trạng đã verify

### Vấn đề
- cloud-native mode hiện tại chỉ có Nuclei generic templates
- Rating: 5/10 (yếu so với 8 mode khác)
- Thiếu: S3Scanner, cloud_enum, kube-hunter, ScoutSuite
- Setup.sh có install aws-cli nhưng không có wrapper plugin

### Evidence từ code
- `cloud_plugin.py` (428 dòng) chỉ wrap Nuclei + subfinder thông thường
- profiles/cloud-native.yaml chỉ có 1 step: vuln_scan với Nuclei tags `cloud, takeovers, k8s, s3`
- KHÔNG có S3 bucket enumeration thật sự
- KHÔNG có Kubernetes API discovery

## Files cần tạo

### 1. plugins/s3_scanner_plugin.py (MỚI)
**Mục đích**: S3 bucket enumeration + permissions check

```python
"""S3 Bucket Scanner Plugin — wrap S3Scanner + custom logic."""
import os
import re
import json
import logging
import subprocess
import shutil
from typing import List, Dict
from core.base_plugin import BasePlugin

class S3ScannerPlugin(BasePlugin):
    def name(self) -> str:
        return "S3Scanner"
    
    def description(self) -> str:
        return "S3 bucket enumeration + permissions audit (ListObjects, PutObject, etc.)"
    
    def check_installed(self) -> bool:
        return shutil.which("s3scanner") is not None
    
    def run(self, target: str, wordlist: str = None) -> List[Dict]:
        """
        Scan S3 buckets liên quan đến target.
        Args:
            target: domain (vd: example.com) hoặc organization name
            wordlist: file chứa bucket name candidates
        Returns:
            List[{bucket, region, public, permissions, findings}]
        """
        wordlist = wordlist or os.path.join(
            os.path.dirname(__file__), "..", "wordlists", "s3_buckets.txt"
        )
        
        buckets_to_test = self._generate_bucket_names(target, wordlist)
        findings = []
        
        for bucket in buckets_to_test:
            result = self._check_bucket(bucket)
            if result["exists"]:
                findings.append(result)
                # Nếu public, check permissions
                if result.get("public"):
                    perms = self._check_permissions(bucket)
                    result["permissions"] = perms
        
        return findings
    
    def _generate_bucket_names(self, target: str, wordlist: str) -> List[str]:
        """Generate bucket name candidates từ target domain."""
        # Strip TLD, replace dots with dashes
        base = target.replace(".", "-").replace("www-", "")
        candidates = [base, f"{base}-backup", f"{base}-data", f"{base}-assets"]
        
        # Load từ wordlist
        if os.path.exists(wordlist):
            with open(wordlist) as f:
                candidates.extend([line.strip() for line in f if line.strip()])
        
        return list(set(candidates))
    
    def _check_bucket(self, bucket: str) -> Dict:
        """Check nếu bucket tồn tại và public."""
        import requests
        try:
            # Try HTTPS first (us-east-1)
            r = requests.get(
                f"https://{bucket}.s3.amazonaws.com/",
                timeout=10
            )
            if r.status_code == 200:
                return {
                    "bucket": bucket,
                    "region": "us-east-1",
                    "exists": True,
                    "public": True,
                    "size": len(r.content),
                    "sample_objects": self._extract_object_keys(r.content)[:5]
                }
            elif r.status_code == 403:
                return {
                    "bucket": bucket, "exists": True, "public": False,
                    "region": "us-east-1", "permissions": "exists but no list"
                }
            elif r.status_code == 404:
                return {"bucket": bucket, "exists": False}
        except Exception as e:
            logging.debug(f"[S3Scanner] {bucket}: {e}")
        return {"bucket": bucket, "exists": False}
    
    def _check_permissions(self, bucket: str) -> Dict:
        """Check permissions: ListObjects, PutObject, GetObject."""
        # TODO: implement bằng cách tạo temporary credentials hoặc dùng
        # anonymous request với PutObject test
        return {"ListObjects": "public", "PutObject": "unknown", "GetObject": "public"}
    
    def _extract_object_keys(self, xml_content: bytes) -> List[str]:
        """Extract object keys từ S3 ListBucketResult XML."""
        keys = re.findall(rb"<Key>([^<]+)</Key>", xml_content)
        return [k.decode("utf-8", errors="ignore") for k in keys]
```

### 2. plugins/cloud_enum_plugin.py (MỚI)
**Mục đích**: Multi-cloud storage enumeration (AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces)

```python
"""Cloud Storage Enumeration Plugin — wrap cloud_enum."""
import os
import shutil
import logging
import subprocess
import tempfile
from typing import List, Dict
from core.base_plugin import BasePlugin

class CloudEnumPlugin(BasePlugin):
    """Multi-cloud storage enumeration.
    Supports: AWS S3, Azure Blob, GCP Storage, DigitalOcean Spaces.
    """
    
    PROVIDERS = ["aws", "azure", "gcp", "digitalocean"]
    
    def name(self) -> str:
        return "CloudEnum"
    
    def description(self) -> str:
        return "Multi-cloud storage enumeration (S3/Blob/GCS/Spaces)"
    
    def check_installed(self) -> bool:
        return shutil.which("cloud_enum") is not None
    
    def run(self, target: str, providers: List[str] = None) -> Dict[str, List[Dict]]:
        """Enumerate cloud storage across providers."""
        providers = providers or self.PROVIDERS
        results = {p: [] for p in providers}
        
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(target + "\n")
            # Add common prefixes
            for prefix in ["", "backup", "data", "assets", "media", "files", "static"]:
                f.write(f"{prefix}{target}\n")
            keyword_file = f.name
        
        try:
            for provider in providers:
                if provider not in self.PROVIDERS:
                    continue
                cmd = ["cloud_enum", "-k", keyword_file, "-t", "10", "--provider", provider]
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                    results[provider] = self._parse_output(result.stdout)
                except subprocess.TimeoutExpired:
                    logging.warning(f"[CloudEnum] {provider} timeout")
                except Exception as e:
                    logging.error(f"[CloudEnum] {provider} error: {e}")
        finally:
            os.unlink(keyword_file)
        
        return results
    
    def _parse_output(self, output: str) -> List[Dict]:
        """Parse cloud_enum output."""
        findings = []
        for line in output.splitlines():
            if "[+]" in line or "FOUND" in line.upper():
                # Extract bucket/container name
                parts = line.split()
                if len(parts) >= 2:
                    findings.append({"resource": parts[-1], "raw": line})
        return findings
```

### 3. plugins/kube_hunter_plugin.py (MỚI)
**Mục đích**: Kubernetes penetration testing

```python
"""Kubernetes Hunter Plugin — wrap kube-hunter."""
import os
import shutil
import subprocess
import logging
from typing import Dict, List
from core.base_plugin import BasePlugin

class KubeHunterPlugin(BasePlugin):
    """Kubernetes penetration testing — discover và attack k8s clusters."""
    
    def name(self) -> str:
        return "KubeHunter"
    
    def description(self) -> str:
        return "Kubernetes cluster discovery + vulnerability hunting"
    
    def check_installed(self) -> bool:
        return shutil.which("kube-hunter") is not None
    
    def run(self, target: str = None, mode: str = "remote") -> Dict:
        """
        Args:
            target: k8s API server (vd: https://k8s.example.com:6443)
            mode: "remote" (scan remote cluster), "internal" (run pod inside)
        Returns:
            {findings: [...], nodes: [...], summary: {...}}
        """
        if mode == "remote" and not target:
            raise ValueError("target required for remote mode")
        
        cmd = ["kube-hunter"] + (["--remote", target] if mode == "remote" else ["--internal"])
        cmd += ["--report", "json", "--log", "level=ERROR"]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return self._parse_report(result.stdout)
        except subprocess.TimeoutExpired:
            logging.error("[KubeHunter] scan timeout")
            return {"findings": [], "error": "timeout"}
        except Exception as e:
            logging.error(f"[KubeHunter] error: {e}")
            return {"findings": [], "error": str(e)}
    
    def _parse_report(self, output: str) -> Dict:
        import json
        try:
            data = json.loads(output)
            return {
                "findings": data.get("vulnerabilities", []),
                "nodes": data.get("nodes", []),
                "summary": {
                    "high": sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "high"),
                    "medium": sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "medium"),
                    "low": sum(1 for v in data.get("vulnerabilities", []) if v.get("severity") == "low"),
                }
            }
        except json.JSONDecodeError:
            return {"findings": [], "error": "parse_failed"}
```

### 4. setup.sh — thêm install cho cloud tools
```bash
# === [P1-2] Cloud-Native Tools ===
# S3Scanner
if ! command -v s3scanner &> /dev/null; then
    echo -e "   ${YELLOW}➜ Installing S3Scanner...${NC}"
    pip3 install S3Scanner --quiet 2>/dev/null || true
fi

# cloud_enum
if ! command -v cloud_enum &> /dev/null; then
    echo -e "   ${YELLOW}➜ Installing cloud_enum...${NC}"
    pip3 install cloud_enum --quiet 2>/dev/null || true
fi

# kube-hunter
if ! command -v kube-hunter &> /dev/null; then
    echo -e "   ${YELLOW}➜ Installing kube-hunter...${NC}"
    pip3 install kube-hunter --quiet 2>/dev/null || true
fi
```

### 5. requirements.txt — thêm deps
```
S3Scanner>=0.1.0
cloud_enum>=0.1.0
kube-hunter>=0.1.0
```

### 6. wordlists/s3_buckets.txt (MỚI)
Common bucket name patterns:
```
backup
data
assets
media
files
static
uploads
downloads
images
docs
logs
archive
tmp
test
dev
prod
staging
admin
internal
private
public
www
web
app
api
cdn
```

## Files cần sửa

### profiles/cloud-native.yaml
Thêm steps:
```yaml
pipeline:
  - step: s3_enumeration
    tool: s3_scanner
    enabled: true
    config:
      timeout: 300
      wordlist: wordlists/s3_buckets.txt
  
  - step: cloud_storage_enum
    tool: cloud_enum
    enabled: true
    config:
      providers: [aws, azure, gcp]
      timeout: 600
  
  - step: k8s_discovery
    tool: kube_hunter
    enabled: false  # Manual trigger
    config:
      mode: remote
      timeout: 600
  
  - step: vuln_scan
    tool: nuclei
    enabled: true
    config:
      tags: [cloud, takeovers, k8s, s3, azure, gcp]
      severity: [critical, high, medium]
```

## Acceptance Criteria

1. **4 cloud plugins** hoạt động đúng, mỗi plugin có test pass
2. **cloud-native mode rating** tăng từ 5/10 lên 8/10
3. **Test trên AWS mock account** (test-bucket-public-read):
   - S3Scanner phát hiện bucket tồn tại
   - CloudEnum phát hiện resource
   - Nuclei tags cloud match với findings
4. **kube-hunter** detect được cluster nếu target có k8s API
5. **No regression**: existing cloud-native scans vẫn chạy được

## Verification Steps

1. Chạy pytest tests/test_cloud_plugins.py
2. Test S3Scanner với mock AWS endpoint
3. Verify profiles/cloud-native.yaml parse đúng
4. Dispatch subagent review code changes
