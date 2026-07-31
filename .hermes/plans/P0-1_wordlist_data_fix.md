# P0-1: Fix wordlist/data corrupt — DETAILED PLAN

## Hiện trạng đã verify (evidence-based)

### Bug #1: wordlists/top-1000.txt = 0 dòng
- File path: /home/tcus/Desktop/PenLabs/wordlists/top-1000.txt
- Evidence: `wc -l` returns 0
- Root cause: setup.sh wget from SecLists thất bại silent
- Setup.sh line: `wget -q "...10-million-password-list-top-1000.txt" -O wordlists/top-1000.txt`
- Vấn đề: `wget -q` quiet mode không in error, file được tạo (empty) khi wget fail

### Bug #2: data/kev_cache/kev_catalog.json = 0 KB
- File path: /home/tcus/Desktop/PenLabs/data/kev_cache/kev_catalog.json
- Evidence: file size = 0 bytes
- Root cause: Unknown (chưa đọc code tạo file này)
- Impact: core/notifier.py hoặc core/diff_engine.py gọi json.load() sẽ crash

### Bug #3: wordlists/common.txt chứa sai nội dung
- File path: /home/tcus/Desktop/PenLabs/wordlists/common.txt
- Evidence: First 5 lines = .bash_history, .bashrc, .cache, .config, .cvs
- Expected: web content discovery paths (admin/, login/, api/, .git/, etc.)
- Root cause: setup.sh wget URL sai hoặc redirect sai

### Bug #4: wordlists/pass.txt quá ngắn
- File path: /home/tcus/Desktop/PenLabs/wordlists/pass.txt
- Evidence: chỉ 5 dòng (admin, 123456, password, root, tomcat)
- Use case: password spraying → không đủ

## Files cần sửa

### 1. setup.sh
**Vị trí**: /home/tcus/Desktop/PenLabs/setup.sh
**Dòng liên quan**: 330-342 (SecLists download section)

**Thay đổi**:
```bash
# Trước (buggy):
wget -q "...url..." -O wordlists/top-1000.txt

# Sau (fixed):
download_wordlist() {
    local url=$1
    local output=$2
    local min_size=$3  # minimum size in bytes
    local label=$4
    
    wget -q "$url" -O "$output.tmp"
    if [ ! -s "$output.tmp" ] || [ $(stat -c%s "$output.tmp") -lt $min_size ]; then
        echo -e "   ${RED}✘ $label download FAILED (file empty or too small)${NC}"
        rm -f "$output.tmp"
        return 1
    fi
    mv "$output.tmp" "$output"
    echo -e "   ${GREEN}✔ $label downloaded ($(wc -l < "$output") lines)${NC}"
}

# Usage:
download_wordlist "https://raw.githubusercontent.com/.../top-1000.txt"     "wordlists/top-1000.txt" 1000 "SecLists Passwords Top 1000"
download_wordlist "https://raw.githubusercontent.com/.../common.txt"     "wordlists/common.txt" 10000 "SecLists Web Content Common"
```

### 2. core/kev_loader.py (MỚI)
**Mục đích**: Safe load KEV catalog với fallback khi file rỗng
**Path**: /home/tcus/Desktop/PenLabs/core/kev_loader.py

```python
"""Safe loader cho CISA KEV catalog — xử lý file rỗng/corrupt."""
import os
import json
import logging
from typing import Dict, Any

DEFAULT_KEV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "data", "kev_cache", "kev_catalog.json"
)

def load_kev_catalog(path: str = None) -> Dict[str, Any]:
    """Load KEV catalog, return empty dict nếu file rỗng hoặc corrupt."""
    path = path or DEFAULT_KEV_PATH
    if not os.path.exists(path):
        logging.warning(f"[KEV] File not found: {path}")
        return {"vulnerabilities": []}
    
    size = os.path.getsize(path)
    if size == 0:
        logging.warning(f"[KEV] File is empty: {path}")
        return {"vulnerabilities": []}
    
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or "vulnerabilities" not in data:
            logging.warning(f"[KEV] Invalid format: {path}")
            return {"vulnerabilities": []}
        logging.info(f"[KEV] Loaded {len(data.get('vulnerabilities', []))} entries")
        return data
    except json.JSONDecodeError as e:
        logging.error(f"[KEV] JSON decode error in {path}: {e}")
        return {"vulnerabilities": []}

def is_in_kev(cve_id: str, catalog: Dict[str, Any] = None) -> bool:
    """Check nếu CVE có trong CISA KEX catalog."""
    if catalog is None:
        catalog = load_kev_catalog()
    for vuln in catalog.get("vulnerabilities", []):
        if vuln.get("cveID") == cve_id:
            return True
    return False
```

### 3. Cập nhật các file dùng kev_catalog
**Search**: Tìm tất cả `json.load` của kev_catalog
**Fix**: Dùng `core.kev_loader.load_kev_catalog()` thay vì raw json.load

### 4. Re-download các wordlist đúng URL
**Command**:
```bash
# SecLists Passwords
wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt" \
    -O /home/tcus/Desktop/PenLabs/wordlists/top-1000.txt

# SecLists Web Content (correct path)
wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -O /home/tcus/Desktop/PenLabs/wordlists/common.txt

# Expand pass.txt
wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt" \
    -O /home/tcus/Desktop/PenLabs/wordlists/pass.txt
```

## Acceptance Criteria

1. **wordlists/top-1000.txt**: ≥ 100 dòng (SecLists có 1000 entries)
2. **wordlists/common.txt**: chứa web paths, không phải unix dotfiles
3. **wordlists/pass.txt**: ≥ 100 dòng (10k most common)
4. **data/kev_cache/kev_catalog.json**: empty thì không crash app
5. **setup.sh**: validate function chạy đúng, in error rõ ràng
6. **Test**: tạo tests/test_kev_loader.py với 5 test cases

## Verification Steps

1. Chạy `wc -l wordlists/*.txt` — verify line counts
2. Chạy `head -5 wordlists/common.txt` — verify content
3. Chạy pytest tests/test_kev_loader.py
4. Dispatch subagent review code changes
