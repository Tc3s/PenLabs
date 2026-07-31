import os
import json
import logging
import subprocess
import shutil
from core.base_plugin import BasePlugin


class NaabuPlugin(BasePlugin):
    """Naabu — Port scanner siêu tốc viết bằng Go (ProjectDiscovery)."""

    def name(self) -> str:
        return "Naabu"

    def description(self) -> str:
        return "Naabu Fast Port Scanner — Xác nhận port mở nhanh gấp 10x Nmap, dùng cho Active Verification."

    def check_installed(self) -> bool:
        return shutil.which("naabu") is not None

    def run(self, target: str, ports: list = None, top_ports: str = "",
            scan_all: bool = False, rate: int = 1000,
            out_dir: str = "/tmp", extra_flags: list = None) -> list:
        """
        Chạy Naabu port scan và trả về danh sách port mở.

        Args:
            target: IP hoặc domain mục tiêu
            ports: List port cụ thể cần verify
            top_ports: "100", "1000" — quét top ports
            scan_all: Quét toàn bộ 65535 ports
            rate: Packet rate (packets/sec)
            out_dir: Thư mục chứa file ouput tạm thời
            extra_flags: Flags bổ sung
        Returns:
            list[dict]: [{"port": 80, "host": "1.2.3.4", "protocol": "tcp"}, ...]
        """
        if not self.check_installed():
            logging.error("Naabu is not installed. Run setup.sh first.")
            return []

        os.makedirs(out_dir, exist_ok=True)
        json_file = os.path.join(out_dir, "naabu_output.json")

        cmd = [
            "naabu",
            "-host", target,
            "-json",
            "-output", json_file,
            "-rate", str(rate),
            "-silent",
        ]

        if scan_all:
            cmd.extend(["-p", "-"])  # All 65535 ports
        elif ports:
            cmd.extend(["-p", ",".join(map(str, ports))])
        elif top_ports:
            cmd.extend(["-top-ports", top_ports])
        else:
            cmd.extend(["-top-ports", "1000"])  # Default

        if extra_flags:
            cmd.extend(extra_flags)

        import sys
        try:
            if "--debug" in sys.argv:
                logging.info(f"[Naabu] CMD: {' '.join(cmd)}")
                subprocess.run(cmd, timeout=300)
            else:
                subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=300)
        except subprocess.TimeoutExpired:
            logging.warning("[Naabu] Timed out after 300 seconds.")

        return self._parse_json(json_file)

    def _parse_json(self, json_file: str) -> list:
        """Parse Naabu JSON output thành list of open ports."""
        results = []
        if not os.path.exists(json_file):
            return results

        try:
            with open(json_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        results.append({
                            "port": int(data.get("port", 0)),
                            "host": data.get("host", "") or data.get("ip", ""),
                            "protocol": data.get("protocol", "tcp"),
                        })
                    except (json.JSONDecodeError, ValueError):
                        continue
        except Exception as e:
            logging.warning(f"[Naabu] Failed to parse {json_file}: {e}")

        return results

    def get_open_ports(self, target: str, ports: list = None, top_ports: str = "", scan_all: bool = False, rate: int = 1000, out_dir: str = "/tmp", extra_flags: list = None) -> list:
        """Shortcut: trả về chỉ danh sách port numbers."""
        results = self.run(target, ports=ports, top_ports=top_ports, scan_all=scan_all, rate=rate, out_dir=out_dir, extra_flags=extra_flags)
        return [r["port"] for r in results if r.get("port")]
