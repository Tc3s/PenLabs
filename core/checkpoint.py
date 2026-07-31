#!/usr/bin/env python3
"""
CHECKPOINT SYSTEM — PenLabs V1.0
==================================
Tham khảo reconFTW: Ghi lại state sau mỗi module/plugin hoàn thành.
Nếu scan bị gián đoạn → resume từ checkpoint cuối cùng.

Cách dùng:
    from core.checkpoint import CheckpointManager

    ckpt = CheckpointManager(session_dir="/path/to/session")
    
    # Trước khi chạy module
    if ckpt.is_completed("MODULE_1_RECON"):
        print("Module 1 đã chạy rồi, skip!")
    else:
        run_module_1()
        ckpt.mark_completed("MODULE_1_RECON", metadata={"subdomains": 42})
    
    # Resume: ckpt tự động biết nên chạy từ đâu
    next_step = ckpt.get_resume_point()
"""

import os
import json
import time
import logging
from datetime import datetime
from typing import Optional, List


class CheckpointManager:
    """
    Quản lý checkpoint cho pipeline execution.
    
    Lưu trạng thái vào file `.checkpoint.json` trong session directory.
    Format:
    {
        "session_id": "...",
        "target": "...",
        "started_at": "...",
        "checkpoints": [
            {"step": "MODULE_1_RECON", "status": "completed", "timestamp": "...", "metadata": {...}},
            {"step": "DUAL_CHANNEL_SPLIT", "status": "completed", "timestamp": "..."},
            ...
        ],
        "last_completed": "MODULE_1_RECON",
        "pipeline_status": "in_progress"  // "completed" | "failed" | "interrupted"
    }
    """
    
    # Thứ tự chuẩn của pipeline
    PIPELINE_ORDER = [
        "PREFLIGHT_CHECK",
        "MODULE_1_RECON",
        "DUAL_CHANNEL_SPLIT",
        "MODULE_2_VULN_ANALYSIS",
        "WEB_LOGIC_INJECTION",
        "MODULE_3_EXPLOIT",
        "MODULE_4_POST_EXPLOIT",
        "REPORT_GENERATION",
    ]
    
    def __init__(self, session_dir: str, session_id: str = "", target: str = ""):
        self.session_dir = session_dir
        self.checkpoint_file = os.path.join(session_dir, ".checkpoint.json")
        self._data = self._load_or_create(session_id, target)
    
    def _load_or_create(self, session_id: str, target: str) -> dict:
        """Load checkpoint file nếu có, hoặc tạo mới."""
        if os.path.isfile(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, "r") as f:
                    data = json.load(f)
                logging.info(f"[Checkpoint] Loaded checkpoint: {data.get('last_completed', 'N/A')}")
                return data
            except (json.JSONDecodeError, Exception) as e:
                logging.warning(f"[Checkpoint] Corrupt checkpoint file, creating new: {e}")
        
        return {
            "session_id": session_id,
            "target": target,
            "started_at": datetime.now().isoformat(),
            "checkpoints": [],
            "last_completed": None,
            "pipeline_status": "in_progress",
        }
    
    def _save(self):
        """
        Lưu checkpoint ra đĩa — Atomic Write Pattern.
        [F-03 FIX] Ghi vào tempfile trước, rồi os.replace() để tránh
        state corruption nếu process crash giữa chừng.
        """
        import tempfile as _tf
        os.makedirs(self.session_dir, exist_ok=True)
        try:
            # Write to temp file in same directory (same filesystem for atomic rename)
            fd, tmp_path = _tf.mkstemp(
                dir=self.session_dir, suffix=".checkpoint.tmp"
            )
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(self._data, f, indent=2, default=str)
                    f.flush()
                    os.fsync(f.fileno())
                # Atomic replace — POSIX guarantees this is atomic on same filesystem
                os.replace(tmp_path, self.checkpoint_file)
            except Exception:
                # Clean up temp file on failure
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except Exception as e:
            logging.error(f"[Checkpoint] Failed to save: {e}")
    
    def is_completed(self, step: str) -> bool:
        """Kiểm tra xem step đã hoàn thành chưa."""
        return any(
            c["step"] == step and c["status"] == "completed"
            for c in self._data["checkpoints"]
        )
    
    def is_chunk_completed(self, step: str, chunk_id: str) -> bool:
        """Kiểm tra xem một chunk cụ thể trong step đã hoàn thành chưa."""
        for c in self._data["checkpoints"]:
            if c["step"] == step:
                chunks = c.get("metadata", {}).get("chunks", {})
                return chunks.get(str(chunk_id)) == "completed"
        return False

    def mark_chunk_completed(self, step: str, chunk_id: str, metadata: dict = None):
        """Đánh dấu một chunk đã hoàn thành."""
        found = False
        for c in self._data["checkpoints"]:
            if c["step"] == step:
                if "chunks" not in c.get("metadata", {}):
                    c.setdefault("metadata", {})["chunks"] = {}
                c["metadata"]["chunks"][str(chunk_id)] = "completed"
                if metadata:
                    c["metadata"].setdefault("chunk_meta", {})[str(chunk_id)] = metadata
                found = True
                break
        
        if not found:
            # Tạo step mới với chunk đầu tiên
            self._data["checkpoints"].append({
                "step": step,
                "status": "in_progress",
                "timestamp": datetime.now().isoformat(),
                "metadata": {"chunks": {str(chunk_id): "completed"}}
            })
        
        self._save()

    def mark_completed(self, step: str, metadata: dict = None):
        """Đánh dấu step đã hoàn thành."""
        # Remove existing entry for this step (nếu retry)
        self._data["checkpoints"] = [
            c for c in self._data["checkpoints"] if c["step"] != step
        ]
        
        self._data["checkpoints"].append({
            "step": step,
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "duration_hint": None,
            "metadata": metadata or {},
        })
        self._data["last_completed"] = step
        self._save()
        logging.info(f"[Checkpoint] ✅ {step} marked completed")
    
    def mark_failed(self, step: str, error: str = ""):
        """Đánh dấu step đã fail."""
        self._data["checkpoints"] = [
            c for c in self._data["checkpoints"] if c["step"] != step
        ]
        
        self._data["checkpoints"].append({
            "step": step,
            "status": "failed",
            "timestamp": datetime.now().isoformat(),
            "error": error[:500],
        })
        self._data["pipeline_status"] = "failed"
        self._save()
        logging.warning(f"[Checkpoint] ❌ {step} marked failed: {error[:200]}")
    
    def mark_pipeline_complete(self):
        """Đánh dấu toàn bộ pipeline hoàn tất."""
        self._data["pipeline_status"] = "completed"
        self._data["completed_at"] = datetime.now().isoformat()
        self._save()
    
    def get_resume_point(self) -> Optional[str]:
        """
        Tìm step tiếp theo cần chạy (step đầu tiên chưa completed).
        Returns None nếu pipeline đã hoàn tất.
        """
        completed_steps = {
            c["step"] for c in self._data["checkpoints"]
            if c["status"] == "completed"
        }
        
        for step in self.PIPELINE_ORDER:
            if step not in completed_steps:
                return step
        
        return None  # Tất cả đã xong
    
    def should_skip(self, step: str) -> bool:
        """
        Nên skip step này không? Dùng khi resume scan.
        Returns True nếu step đã completed trước đó.
        """
        if self.is_completed(step):
            logging.info(f"[Checkpoint] ⏭️  Skipping {step} (already completed)")
            return True
        return False
    
    def get_completed_steps(self) -> List[str]:
        """Trả về danh sách các step đã hoàn thành."""
        return [
            c["step"] for c in self._data["checkpoints"]
            if c["status"] == "completed"
        ]
    
    def get_summary(self) -> str:
        """In summary cho terminal."""
        lines = [f"[Checkpoint] Pipeline Status: {self._data['pipeline_status']}"]
        completed = self.get_completed_steps()
        
        for step in self.PIPELINE_ORDER:
            if step in completed:
                lines.append(f"  ✅ {step}")
            else:
                resume = self.get_resume_point()
                if step == resume:
                    lines.append(f"  ▶️  {step} ← resume point")
                else:
                    lines.append(f"  ⬜ {step}")
        
        return "\n".join(lines)
    
    @property
    def is_resuming(self) -> bool:
        """True nếu đang resume từ checkpoint (có ít nhất 1 step đã completed)."""
        return len(self.get_completed_steps()) > 0
