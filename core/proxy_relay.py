#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PENLABS — PROXY RELAY (V1.0)
Cầu nối giữa các công cụ truyền thống (SQLMap, FFuf) và StealthNet.
Nhận request -> StealthNet "mông má" (JA3, Headers, Proxy Rotation) -> Target.
"""

import asyncio
import logging
from aiohttp import web
from plugins.stealth_net_plugin import StealthNetPlugin
from core.proxy_env import set_active_relay, clear_active_relay

class ProxyRelay:
    def __init__(self, host="127.0.0.1", port=0, scan_mode="sniper"):
        self.host = host
        self.port = port
        self.scan_mode = scan_mode
        self.stealth_net = StealthNetPlugin(scan_mode=scan_mode)
        self.stealth_net.run(proxy=True) # Luôn bật proxy rotation cho relay
        self.app = web.Application()
        self.app.router.add_route('*', '/{path:.*}', self.handle_request)
        self.runner = None

    async def handle_request(self, request):
        """Chuyển tiếp request qua StealthNet."""
        method = request.method
        # SQLMap gửi toàn bộ URL trong request khi dùng proxy
        url = str(request.url)
        
        # Nếu url không có scheme (do aiohttp parse), cố gắng lấy từ headers
        if not url.startswith("http"):
            host = request.headers.get("Host", "")
            url = f"http://{host}{request.rel_url}"

        headers = dict(request.headers)
        # Loại bỏ các headers có thể gây xung đột hoặc lộ dấu vết SQLMap
        headers.pop("Host", None)
        headers.pop("User-Agent", None) # Để StealthNet tự sinh UA xịn
        headers.pop("Content-Length", None) # Để StealthNet tự tính toán lại size
        
        body = await request.read()
        
        logging.debug(f"[Relay] {method} {url}")
        
        # Gọi StealthNet (hỗ trợ chuyển tiếp body thô qua json_data của _request)
        resp = self.stealth_net._request(method, url, headers=headers, json_data=body if body else None)

        # Trả về kết quả cho SQLMap
        return web.Response(
            body=resp.content,
            status=resp.status_code,
            headers=resp.headers
        )

    async def start(self):
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, self.host, self.port)
        await site.start()
        
        # Lấy port thực tế nếu dùng port=0
        self.port = site._server.sockets[0].getsockname()[1]
        
        # [V2026-FIX] Register relay port so process_manager auto-injects it
        set_active_relay(self.port)
        
        logging.info(f"[ProxyRelay] Started on http://{self.host}:{self.port}")
        return self.port

    async def stop(self):
        if self.runner:
            await self.runner.cleanup()
            # [V2026-FIX] Clear relay registration
            clear_active_relay()
            logging.info("[ProxyRelay] Stopped.")

if __name__ == "__main__":
    # Test chạy độc lập
    logging.basicConfig(level=logging.INFO)
    relay = ProxyRelay(port=8888)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(relay.start())
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        loop.run_until_complete(relay.stop())
