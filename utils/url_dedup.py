import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class URLDeduplicator:
    """
    [V1.0] Smart URL Deduplication Engine.
    
    Katana/Ffuf/gau thường trả về hàng trăm URL chỉ khác nhau giá trị tham số:
        /search?q=apple   vs  /search?q=banana   → chỉ giữ 1
        /page?id=1&lang=en vs /page?id=2&lang=vi → chỉ giữ 1
    
    Thuật toán: Nhóm URL theo fingerprint = (scheme, netloc, path, frozenset(query_keys)).
    Với mỗi nhóm, giữ lại URL đầu tiên (đại diện).
    Thêm: loại bỏ static assets (css/js/font/image) không cần quét DAST.
    """

    # Extensions của static assets — không cần quét vuln (XSS/SQLi)
    # [V1.0-SYNC] Removed .js and .json from here as they are needed for discovery
    # [V1.0-SYNC] Removed .js and .json from here as they are needed for discovery
    _STATIC_EXTENSIONS = frozenset({
        '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.mp3', '.mp4', '.avi', '.mov', '.webm', '.webp',
        '.pdf', '.zip', '.gz', '.tar', '.rar',
        '.map', '.min.css',
    })

    # Tracking domains — loại bỏ khỏi DAST/Recon scanning
    _TRACKING_DOMAINS = frozenset({
        'google-analytics.com', 'googletagmanager.com', 'googleadservices.com',
        'google.com', 'facebook.com', 'facebook.net', 'doubleclick.net',
        'yandex.ru', 'bing.com', 'clarity.ms', 'segment.io', 'mixpanel.com',
    })

    # Paths lặp lại vô nghĩa (pagination, sorting, anchors)
    _NOISE_PARAM_KEYS = frozenset({
        'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
        'fbclid', 'gclid', 'mc_cid', 'mc_eid',
        '_ga', '_gid', 'ref', 'source', 'share',
    })

    @classmethod
    def deduplicate(cls, urls: list, keep_params: bool = True) -> list:
        """
        Loại bỏ URL trùng lặp thông minh.
        
        Args:
            urls: Danh sách URL thô từ Katana/Ffuf/gau
            keep_params: Nếu True, giữ 1 URL đại diện có tham số (cho DAST scan).
                         Nếu False, loại toàn bộ tham số (chỉ giữ base path).
        
        Returns:
            list: URL đã được loại bỏ trùng lặp
        """
        if not urls:
            return []

        seen_fingerprints = {}  # fingerprint -> first_url
        deduped = []

        for url in urls:
            url = url.strip()
            if not url:
                continue

            # Bỏ qua non-HTTP URLs
            if not url.startswith(('http://', 'https://')):
                continue

            try:
                parsed = urlparse(url)
            except Exception:
                continue

            # Bỏ tracking domains
            netloc_lower = parsed.netloc.lower().split(':')[0]
            if any(netloc_lower == td or netloc_lower.endswith('.' + td) for td in cls._TRACKING_DOMAINS):
                continue

            # Bỏ static assets
            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in cls._STATIC_EXTENSIONS):
                continue

            # Loại bỏ fragment (#)
            clean_path = parsed.path.rstrip('/')
            if not clean_path:
                clean_path = '/'

            # Parse query parameters
            query_params = parse_qs(parsed.query, keep_blank_values=True)

            # Loại bỏ tracking/noise parameters
            clean_params = {
                k: v for k, v in query_params.items()
                if k.lower() not in cls._NOISE_PARAM_KEYS
            }

            # [V1.0-APEX] BLACK BOX PRECISION MODE
            # Tạo fingerprint bao gồm cả giá trị tham số nếu là ID (numeric/uuid) 
            # để không bỏ sót BOLA/IDOR trên các tài liệu khác nhau.
            # Tuy nhiên để tránh "Recursive Hell", chúng ta chỉ làm điều này cho top 10 values.
            
            param_fingerprint = []
            for k, v in sorted(clean_params.items()):
                val = v[0] if v else ""
                # Nếu value trông giống ID (số hoặc UUID)
                if val.isdigit() or len(val) > 30:
                    param_fingerprint.append(f"{k}={val}")
                else:
                    param_fingerprint.append(k)
            
            param_keys = frozenset(param_fingerprint)
            fingerprint = (parsed.scheme, parsed.netloc, clean_path, param_keys)

            if fingerprint not in seen_fingerprints:
                seen_fingerprints[fingerprint] = url
                
                if keep_params and clean_params:
                    # Rebuild URL với params sạch (giữ giá trị đầu tiên nhìn thấy)
                    clean_query = urlencode(
                        {k: v[0] if v else '' for k, v in sorted(clean_params.items())},
                        doseq=False
                    )
                    clean_url = urlunparse((
                        parsed.scheme, parsed.netloc, clean_path,
                        '', clean_query, ''
                    ))
                    deduped.append(clean_url)
                else:
                    # Chỉ giữ base URL không tham số
                    deduped.append(urlunparse((
                        parsed.scheme, parsed.netloc, clean_path,
                        '', '', ''
                    )))

        return deduped

    @classmethod
    def deduplicate_with_params(cls, urls: list) -> tuple:
        """
        Trả về 2 list:
          1. base_urls: URL sạch (không tham số) cho dir scan
          2. param_urls: URL có tham số (đại diện) cho DAST scan (SQLi, XSS, SSTI...)
        
        Returns:
            (base_urls, param_urls)
        """
        if not urls:
            return [], []

        seen_base = {}   # (scheme, netloc, path) -> url
        seen_param = {}  # (scheme, netloc, path, param_keys) -> url
        base_urls = []
        param_urls = []

        for url in urls:
            url = url.strip()
            if not url or not url.startswith(('http://', 'https://')):
                continue

            try:
                parsed = urlparse(url)
            except Exception:
                continue

            netloc_lower = parsed.netloc.lower().split(':')[0]
            if any(netloc_lower == td or netloc_lower.endswith('.' + td) for td in cls._TRACKING_DOMAINS):
                continue

            path_lower = parsed.path.lower()
            if any(path_lower.endswith(ext) for ext in cls._STATIC_EXTENSIONS):
                continue

            clean_path = parsed.path.rstrip('/') or '/'
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            clean_params = {
                k: v for k, v in query_params.items()
                if k.lower() not in cls._NOISE_PARAM_KEYS
            }

            base_fp = (parsed.scheme, parsed.netloc, clean_path)

            if base_fp not in seen_base:
                seen_base[base_fp] = url
                base_urls.append(urlunparse((
                    parsed.scheme, parsed.netloc, clean_path, '', '', ''
                )))

            if clean_params:
                param_keys = frozenset(clean_params.keys())
                param_fp = (parsed.scheme, parsed.netloc, clean_path, param_keys)
                if param_fp not in seen_param:
                    seen_param[param_fp] = url
                    clean_query = urlencode(
                        {k: v[0] if v else '' for k, v in sorted(clean_params.items())},
                        doseq=False
                    )
                    param_urls.append(urlunparse((
                        parsed.scheme, parsed.netloc, clean_path,
                        '', clean_query, ''
                    )))

        return base_urls, param_urls
