import os
import re
import time
import subprocess
import logging
import tempfile

class CloudflareTunnel:
    """Plugin để khởi chạy Cloudflared Quick Tunnel vượt tường lửa."""
    def __init__(self):
        self.process = None
        self.url = None
        # [CRIT-01] Dùng tempfile thay vì hardcoded /tmp/ tránh symlink attack
        _fd, self.log_file = tempfile.mkstemp(suffix='.log', prefix='penl_cf_')
        os.close(_fd)  # Close fd, cloudflared sẽ ghi vào path

    def start_tunnel(self, local_port=4444):
        """Khởi động Cloudflared Quick Tunnel chỉ vào cổng HTTP nội bộ."""
        if self.process:
            self.stop_tunnel()

        # Dọn log cũ
        if os.path.exists(self.log_file):
            os.remove(self.log_file)

        cmd = [
            "cloudflared", "tunnel",
            "--url", f"http://127.0.0.1:{local_port}",
            "--logfile", self.log_file,
            "--loglevel", "info"
        ]

        self.process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        # Đợi Cloudflared lấy URL (parse từ file log)
        logging.info(f"[*] Starting Cloudflare tunnel to local port {local_port}...")
        url_regex = re.compile(r"https://([a-zA-Z0-9-]+\.trycloudflare\.com)")
        
        for _ in range(15):  # Đợi tối đa 15 giây
            time.sleep(1)
            if os.path.exists(self.log_file):
                with open(self.log_file, "r") as f:
                    content = f.read()
                    match = url_regex.search(content)
                    if match:
                        self.url = match.group(0)
                        logging.info(f"[+] Tunnel established: {self.url}")
                        return self.url

        logging.error("[-] Failed to establish Cloudflare tunnel.")
        self.stop_tunnel()
        return None

    def stop_tunnel(self):
        """Dừng tunnel và cleanup temp files."""
        if self.process:
            self.process.terminate()
            self.process.wait()
            self.process = None
            self.url = None
            logging.info("[*] Tunnel stopped.")
        #  Cleanup temp log file tạo bởi mkstemp()
        # Tránh để lại C2 URL trong filesystem
        if self.log_file and os.path.exists(self.log_file):
            try:
                os.remove(self.log_file)
            except OSError:
                pass
