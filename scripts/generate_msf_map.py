#!/usr/bin/env python3
# FILE: generate_msf_map.py
# CHỨC NĂNG: Tự động trích xuất CVE và đường dẫn module từ Metasploit

import json
import os
import sys
import re
import time
from datetime import datetime

try:
    from pymetasploit3.msfrpc import MsfRpcClient
except ImportError:
    print("\033[91m❌ LỖI: Cần thư viện pymetasploit3\033[0m")
    sys.exit(1)

OUTPUT_FILE = "msf_module_map.json"
RPC_PASS = os.getenv('MSF_RPC_PASS', 'obsidian')  # Ưu tiên env var, fallback 'obsidian'
RPC_PORT = int(os.getenv('MSF_RPC_PORT', '55553'))
RPC_HOST = os.getenv('MSF_RPC_HOST', '127.0.0.1')

def generate_map():
    print("--- MSF MODULE MAP GENERATOR ---")
    
    # 1. Kết nối RPC
    try:
        print(f"[*] Connecting to msfrpcd ({RPC_HOST}:{RPC_PORT})...")
        # NOTE: Dịch vụ msfrpcd phải được chạy trước đó (service postgresql start && msfrpcd -P obsidian -n -f -S)
        client = MsfRpcClient(RPC_PASS, port=RPC_PORT, server=RPC_HOST, ssl=True, timeout=5)
    except Exception as e:
        print(f"\033[91m❌ KẾT NỐI THẤT BẠI. Đảm bảo msfrpcd đang chạy với pass '{RPC_PASS}'\033[0m")
        return

    # 2. Trích xuất dữ liệu
    cve_map = {}
    exploit_count = 0
    
    # Lấy danh sách tất cả các module exploit
    exploits = client.modules.exploits
    
    print(f"[*] Analyzing {len(exploits)} exploit modules...")
    
    for module_path in exploits:
        try:
            # Lấy thông tin chi tiết của module
            info = client.modules.info('exploit', module_path)
            
            # Trích xuất tham chiếu (References)
            references = info.get('references', [])
            
            for ref in references:
                if ref[0] == 'CVE':
                    cve_id = ref[1]
                    # Map CVE ID đến đường dẫn module
                    cve_map[cve_id] = module_path
                    exploit_count += 1
        except Exception as e:
            # Bỏ qua các module bị lỗi hoặc không có info
            pass

    # 3. Lưu kết quả ra JSON
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(cve_map, f, indent=4)
    
    print("-" * 40)
    print(f"\033[92m✅ THÀNH CÔNG!\033[0m")
    print(f"Đã lưu {len(cve_map)} CVE mappings vào file: {OUTPUT_FILE}")
    print(f"Vui lòng tích hợp file này vào Module 3.")
    print("-" * 40)

if __name__ == "__main__":
    # Đảm bảo dịch vụ msfrpcd đã chạy:
    # service postgresql start
    # msfrpcd -P obsidian -n -f -S -a 127.0.0.1
    generate_map()
