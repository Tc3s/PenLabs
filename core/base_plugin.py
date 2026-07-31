import abc
from typing import Any

class BasePlugin(abc.ABC):
    """
    Interface cơ sở cho mọi Plugin trong PenLabs V1.0.
    Lấy cảm hứng từ file wrapper.go của xpfarm.
    """
    
    @abc.abstractmethod
    def name(self) -> str:
        """Tên của Plugin."""
        pass
    
    @abc.abstractmethod
    def description(self) -> str:
        """Mô tả ngắn gọn về plugin."""
        pass
    
    @abc.abstractmethod
    def check_installed(self) -> bool:
        """Kiểm tra xem tools/binary có khả dụng không."""
        pass
        
    @abc.abstractmethod
    def run(self, *args, **kwargs) -> Any:
        """Hàm thực thi lõi của Plugin."""
        pass
