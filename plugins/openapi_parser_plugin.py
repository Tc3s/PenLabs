#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import logging
import requests
from typing import List, Dict, Any
from urllib.parse import urljoin
from core.base_plugin import BasePlugin

class OpenAPIParserPlugin(BasePlugin):
    """
    Plugin phân tích OpenAPI/Swagger Schema để trích xuất endpoints
    và tự động điền dữ liệu mẫu vào path parameters (Discovery 9/10).
    """
    
    def name(self) -> str:
        return "OpenAPIParser"

    def description(self) -> str:
        return "Parse OpenAPI/Swagger schemas and populate endpoints with mock data."

    def check_installed(self) -> bool:
        return True
        
    def run(self, schema_url_or_path: str, timeout: int = 15) -> Dict[str, List[str]]:
        """
        Phân tích schema OpenAPI và trả về danh sách endpoints theo HTTP method.
        VD: {"GET": ["/api/users/1"], "POST": ["/api/auth"]}
        """
        schema_data = self._load_schema(schema_url_or_path, timeout)
        if not schema_data:
            return {}
            
        base_path = schema_data.get("basePath", "")
        paths = schema_data.get("paths", {})
        endpoints = {}
        
        for path, methods in paths.items():
            for method, details in methods.items():
                method = method.upper()
                if method not in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]:
                    continue
                    
                # Thay thế các tham số trong path bằng mock data
                mocked_path = path
                parameters = details.get("parameters", [])
                
                # Check for path-level parameters
                if "parameters" in methods and isinstance(methods["parameters"], list):
                    parameters.extend(methods["parameters"])
                    
                for param in parameters:
                    if param.get("in") == "path":
                        param_name = param.get("name")
                        param_type = param.get("type", "string")
                        
                        mock_val = "1" if param_type in ["integer", "number"] else "test"
                        mocked_path = mocked_path.replace(f"{{{param_name}}}", mock_val)
                
                full_path = f"{base_path}{mocked_path}" if base_path else mocked_path
                # Chống lặp dấu /
                full_path = "/" + full_path.lstrip("/")
                
                if method not in endpoints:
                    endpoints[method] = []
                endpoints[method].append(full_path)
                
        return endpoints

    def _load_schema(self, source: str, timeout: int) -> Dict[str, Any]:
        """Tải schema từ URL hoặc local file."""
        if source.startswith(("http://", "https://")):
            try:
                resp = requests.get(source, timeout=timeout, verify=False)
                if resp.status_code == 200:
                    return resp.json()
            except Exception as e:
                logging.debug(f"[OpenAPI] Error loading {source}: {e}")
        else:
            try:
                with open(source, "r") as f:
                    return json.load(f)
            except Exception as e:
                logging.debug(f"[OpenAPI] Error reading {source}: {e}")
        return {}
