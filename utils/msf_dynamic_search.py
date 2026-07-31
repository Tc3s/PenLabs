#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# FILE: utils/msf_dynamic_search.py
# CHỨC NĂNG: Query Metasploit Console động để tìm module theo CVE, parse Rank & Type. Có hỗ trợ Cache.

import os
import sys
import json
import logging
import subprocess
import re

# Rank ưu tiên (càng lớn càng ưu tiên hiển thị trước)
RANK_SCORES = {
    "excellent": 100,
    "great": 90,
    "good": 80,
    "normal": 70,
    "average": 60,
    "low": 50,
    "manual": 10
}

def search_msf_for_cve(cve, cache_dir):
    """
    Tìm module MSF dựa vào CVE, lấy tối đa 6 kết quả ngon nhất (exploit > auxiliary, rank cao > rank thấp).
    """
    os.makedirs(cache_dir, exist_ok=True)
    cache_file = os.path.join(cache_dir, "msf_cache.json")
    
    # 1. Đọc Cache
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
                if cve in cache_data:
                    return cache_data[cve]
        except Exception as e:
            logging.debug(f"MSF cache read error: {e}")
    else:
        cache_data = {}

    # 2. Query thật nếu chưa có Cache
    print(f"[*] Đang query MSFConsole để tìm module cho: {cve} ... (timeout 10s)")
    try:
        cmd = ["msfconsole", "-q", "-x", f"search cve:{cve}; exit"]
        output = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=10)
    except subprocess.TimeoutExpired:
        print(f"[!] msfconsole search timeout (10s) cho {cve}. Bỏ qua.")
        return []
    except Exception as e:
        print(f"[!] Lỗi khi gọi msfconsole: {e}")
        return []

    # 3. Phân tích Output (Tìm các dòng có vẻ giống module format)
    modules_found = []
    
    # Hàm gỡ mã màu ANSI
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_output = ansi_escape.sub('', output)
    
    lines = clean_output.split('\n')
    for line in lines:
        line = line.strip()
        # Bỏ qua Header và empty lines
        if not line or line.startswith('#') or line.startswith('Name') or line.startswith('-'): continue
        
        # Regex tìm chuỗi có dạng exploit/... hoặc auxiliary/... với kí tự hợp lệ bao gồm cả dấu gạch chéo
        match = re.search(r'(exploit|auxiliary)\/([A-Za-z0-9_\-\.\/]+)', line)
        if match:
            m_type = match.group(1)
            full_path = match.group(0)
            
            # Gỡ Rank (nếu có cột chứa rank thì thường là chữ Excellent, Normal, v.v)
            rank = "normal"
            for rk in RANK_SCORES.keys():
                if rk in line.lower():
                    rank = rk
                    break
            
            # Tính điểm phân loại
            score = RANK_SCORES.get(rank, 50)
            if m_type == "exploit": score += 500  # Ưu tiên exploit hơn auxiliary
            
            modules_found.append({
                "path": full_path,
                "type": m_type,
                "rank": rank,
                "score": score
            })

    # 4. Filter và Sort
    # Sắp xếp theo score từ trên xuống
    modules_found.sort(key=lambda x: x['score'], reverse=True)
    # Cắt top 6
    top6 = modules_found[:6]

    # 5. Lưu Cache
    cache_data[cve] = top6
    with open(cache_file, 'w') as f:
        json.dump(cache_data, f, indent=4)

    return top6

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 msf_dynamic_search.py <cve>")
        sys.exit(1)
    
    c = search_msf_for_cve(sys.argv[1], "/tmp")
    for m in c:
        print(f"[{m['type'].upper()}] - {m['path']} (Rank: {m['rank']})")
