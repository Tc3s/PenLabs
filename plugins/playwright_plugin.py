import os
import asyncio
import logging
import json
from urllib.parse import urlparse
from core.base_plugin import BasePlugin

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


class PlaywrightPlugin(BasePlugin):
    """
    Playwright Plugin — Deep SPA Discovery.
    Sử dụng trình duyệt thực để tìm kiếm API endpoints và tương tác với DOM.
    """

    def name(self) -> str:
        return "Playwright"

    def description(self) -> str:
        return "Headless Browser Discovery — Crawl SPA và lắng nghe API traffic."

    def check_installed(self) -> bool:
        return HAS_PLAYWRIGHT

    async def run(self, url: list, out_dir: str, timeout: int = 30, 
                  headers: dict = None, proxy: str = None) -> dict:
        """
        Quét một hoặc nhiều URL bằng Playwright.
        """
        if not self.check_installed():
            logging.warning("[Playwright] Playwright not installed. Skip.")
            return {}

        if isinstance(url, str):
            urls = [url]
        else:
            urls = url

        results = {
            "endpoints": set(),
            "js_files": set(),
            "screenshots": [],
            "js_secrets": []
        }

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, proxy={"server": proxy} if proxy else None)
            context = await browser.new_context(
                user_agent=headers.get("User-Agent") if headers else None,
                extra_http_headers=headers or {},
                ignore_https_errors=True
            )

            for target_url in urls:
                page = await context.new_page()
                self._setup_interceptor(page, target_url, results)

                try:
                    logging.info(f"[Playwright] Navigating to {target_url}...")
                    await page.goto(target_url, wait_until="networkidle", timeout=timeout * 1000)
                    
                    # Tương tác cơ bản: Scroll xuống cuối trang để trigger lazy load
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await asyncio.sleep(2)

                    # Click ngẫu nhiên một số nút bấm trông có vẻ là API triggers
                    buttons = await page.query_selector_all("button, a")
                    for btn in buttons[:5]: # Chỉ thử 5 cái đầu tiên để tránh loop
                        try:
                            await btn.click(timeout=1000)
                            await asyncio.sleep(0.5)
                        except Exception:
                            continue

                except Exception as e:
                    logging.warning(f"[Playwright] Error scanning {target_url}: {e}")
                finally:
                    await page.close()

            await browser.close()

        # Convert sets to lists for JSON serialization
        return {
            "endpoints": list(results["endpoints"]),
            "js_files": list(results["js_files"]),
            "js_secrets": results["js_secrets"]
        }

    def _setup_interceptor(self, page, base_url, results):
        """Lắng nghe các request đi ra từ trình duyệt."""
        base_domain = urlparse(base_url).netloc

        async def handle_request(request):
            url = request.url
            parsed = urlparse(url)
            
            # Chỉ thu thập các request cùng domain hoặc API-like
            if parsed.netloc == base_domain or "api" in url.lower() or "v1" in url.lower() or "v2" in url.lower():
                if request.resource_type in ["fetch", "xhr"]:
                    results["endpoints"].add(url)
                elif request.resource_type == "script":
                    results["js_files"].add(url)

        page.on("request", handle_request)
