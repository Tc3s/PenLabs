import re
from urllib.parse import urlparse

try:
    import tldextract
    _HAS_TLDEXTRACT = True
except ImportError:
    _HAS_TLDEXTRACT = False

class TargetSanitizer:
    """
    Tiện ích làm sạch và chuẩn hoá target đầu vào.
    Hỗ trợ IP, Domain, và URL.
    Sử dụng tldextract để xử lý đúng ccTLD phức tạp (.co.uk, .com.vn, .edu.vn).
    """

    # [SECURITY-FIX][CRIT-02] Whitelist ký tự hợp lệ cho target (hostname/IP/URL)
    # Cho phép: chữ, số, dấu chấm, dấu gạch ngang, dấu hai chấm (IPv6/port), dấu gạch chéo (path)
    # Cấm: ;  |  $  `  (  )  {  }  &  !  ~  '  "  <  >  \n  \r  và các shell metacharacters khác
    _VALID_TARGET = re.compile(r'^[a-zA-Z0-9\.\-\:\/\[\]\_\@\%\?\=\#\+\,]+$')
    
    @staticmethod
    def clean(target: str) -> str:
        """
        Làm sạch URL thành domain/IP, loại bỏ protocol, path.
        Ví dụ: https://example.com/admin -> example.com
        192.168.1.1 -> 192.168.1.1
        
        [SECURITY-FIX][CRIT-02] Validates against shell metacharacters to prevent
        command injection when target strings are used in subprocess or remote commands.
        
        Raises:
            ValueError: If target contains forbidden characters
        """
        target = target.strip()
        
        if not target:
            raise ValueError("Target cannot be empty")
        
        # [CRIT-02] Block shell metacharacters TRƯỚC khi parse
        if not TargetSanitizer._VALID_TARGET.match(target):
            raise ValueError(f"Invalid target '{target}': contains forbidden characters (shell metacharacters)")
        
        # Xử lý URL có chứa protocol
        if "://" in target:
            parsed = urlparse(target)
            netloc = parsed.netloc
            # Validate netloc riêng vì nó sẽ được dùng trong subprocess
            if netloc and not TargetSanitizer._VALID_TARGET.match(netloc):
                raise ValueError(f"Invalid hostname '{netloc}': contains forbidden characters")
            return netloc
            
        # Không thay đổi với IP hoặc domain thuần
        return target
        
    @staticmethod
    def get_base_domain(domain: str) -> str:
        """
        Lấy base domain từ subdomain.
        Sử dụng tldextract (Public Suffix List) để xử lý đúng mọi ccTLD.
        VD: sub.example.co.uk -> example.co.uk
            deep.sub.test.com.vn -> test.com.vn
        """
        # Nếu là IP, trả về nguyên bản
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
            return domain
        
        if _HAS_TLDEXTRACT:
            ext = tldextract.extract(domain)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
            # Fallback nếu tldextract không parse được
            return domain
        
        # Legacy fallback (khi tldextract chưa cài)
        parts = domain.split(".")
        if len(parts) > 2:
            return ".".join(parts[-2:])
        return domain
