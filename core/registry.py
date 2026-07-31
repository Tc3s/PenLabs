from typing import Dict
from core.base_plugin import BasePlugin

class PluginRegistry:
    """
    Registry quản lý các Plugin (Nmap, Shodan, MSF,...).
    Thiết kế theo mẫu Singleton lấy cảm hứng từ xpfarm/registry.go.
    """
    
    _registry: Dict[str, BasePlugin] = {}
    _discovered: bool = False  #  Tránh auto_discover() trùng lặp
    _lazy_index: dict[str, tuple[str, str]] = {
        "Amass": ("plugins.amass_plugin", "AmassPlugin"),
        "Arjun": ("plugins.arjun_plugin", "ArjunPlugin"),
        "BlindXSS": ("plugins.blind_xss_plugin", "BlindXSSPlugin"),
        "BOLAEngine": ("plugins.bola_engine_plugin", "BOLAEnginePlugin"),
        "Bypass403": ("plugins.bypass_403_plugin", "Bypass403Plugin"),
        "CISAKEV": ("plugins.kev_plugin", "CISAKEVPlugin"),
        "CloudDevOps": ("plugins.cloud_plugin", "CloudDevOpsPlugin"),
        "CloudEnum": ("plugins.cloud_enum_plugin", "CloudEnumPlugin"),
        "Corsy": ("plugins.corsy_plugin", "CorsyPlugin"),
        "CRLFScan": ("plugins.crlf_plugin", "CRLFPlugin"),
        "Dalfox": ("plugins.dalfox_plugin", "DalfoxPlugin"),
        "EmailFinder": ("plugins.emailfinder_plugin", "EmailFinderPlugin"),
        "EPSS": ("plugins.epss_plugin", "EPSSPlugin"),
        "GraphQLProbe": ("plugins.graphql_probe_plugin", "GraphQLProbePlugin"),
        "Httpx": ("plugins.httpx_plugin", "HttpxPlugin"),
        "JA3Proxy": ("plugins.ja3_proxy_plugin", "JA3ProxyPlugin"),
        "Katana": ("plugins.katana_plugin", "KatanaPlugin"),
        "Kiterunner": ("plugins.kiterunner_plugin", "KiterunnerPlugin"),
        "KubeHunter": ("plugins.kube_hunter_plugin", "KubeHunterPlugin"),
        "LinkFinder": ("plugins.linkfinder_plugin", "LinkFinderPlugin"),
        "MassAssignment": ("plugins.mass_assignment_plugin", "MassAssignmentPlugin"),
        "Metagoofil": ("plugins.metagoofil_plugin", "MetagoofilPlugin"),
        "MSFSearch": ("plugins.msf_search_plugin", "MSFSearchPlugin"),
        "MsfRPC": ("plugins.msfrpc_plugin", "MsfRpcPlugin"),
        "Naabu": ("plugins.naabu_plugin", "NaabuPlugin"),
        "Nmap": ("plugins.nmap_plugin", "NmapPlugin"),
        "Nuclei": ("plugins.nuclei_plugin", "NucleiPlugin"),
        "NVD": ("plugins.nvd_plugin", "NVDPlugin"),
        "NvdCPE": ("plugins.nvd_cpe_plugin", "NvdCpePlugin"),
        "OpenAPIParser": ("plugins.openapi_parser_plugin", "OpenAPIParserPlugin"),
        "OpenRedirect": ("plugins.open_redirect_plugin", "OpenRedirectPlugin"),
        "PayloadGenerator": ("plugins.payload_plugin", "PayloadGeneratorPlugin"),
        "PayloadObfuscator": ("plugins.payload_obfuscator_plugin", "PayloadObfuscatorPlugin"),
        "Playwright": ("plugins.playwright_plugin", "PlaywrightPlugin"),
        "RaceTest": ("plugins.race_condition_plugin", "RaceConditionPlugin"),
        "ReportGenerator": ("plugins.report_plugin", "ReportPlugin"),
        "S3Scanner": ("plugins.s3_scanner_plugin", "S3ScannerPlugin"),
        "ShodanHostname": ("plugins.shodan_plugin", "ShodanHostnamePlugin"),
        "ShodanInternetDB": ("plugins.shodan_internetdb_plugin", "InternetDBPlugin"),
        "SmartXSS": ("plugins.smart_xss_plugin", "SmartXSSPlugin"),
        "SQLMapDetect": ("plugins.sqlmap_detect_plugin", "SQLMapDetectPlugin"),
        "SSRFProbe": ("plugins.ssrf_probe_plugin", "SSRFProbePlugin"),
        "StealthNet": ("plugins.stealth_net_plugin", "StealthNetPlugin"),
        "SubdomainHunter": ("plugins.subdomain_plugin", "SubdomainHunterPlugin"),
        "TheHarvester": ("plugins.theharvester_plugin", "TheHarvesterPlugin"),
        "VirusTotal": ("plugins.virustotal_plugin", "VirusTotalPlugin"),
        "WPScan": ("plugins.wpscan_plugin", "WPScanPlugin"),
        "XnLinkFinder": ("plugins.xnlinkfinder_plugin", "XnLinkFinderPlugin"),
    }

    @classmethod
    def register(cls, plugin: BasePlugin):
        """Đăng ký một plugin vào hệ thống."""
        name = plugin.name()
        if name not in cls._registry:
            cls._registry[name] = plugin
            # print(f"[*] Registered Plugin: {Colors.OKBLUE}{name}{Colors.ENDC}")

    @classmethod
    def get(cls, name: str) -> BasePlugin:
        """Lấy một plugin theo tên. Lazy-load exact plugin before full discovery."""
        if name not in cls._registry:
            cls._load_plugin(name)
        return cls._registry.get(name)

    @classmethod
    def get_all(cls) -> Dict[str, BasePlugin]:
        """Trả về toàn bộ plugin đang có."""
        if not cls._discovered:
            cls.auto_discover()
        return cls._registry

    @classmethod
    def _load_plugin(cls, name: str) -> bool:
        spec = cls._lazy_index.get(name)
        if not spec:
            if not cls._discovered:
                cls.auto_discover()
            return name in cls._registry
        module_name, class_name = spec
        try:
            import importlib
            module = importlib.import_module(module_name)
            plugin_cls = getattr(module, class_name)
            cls.register(plugin_cls())
            return True
        except Exception as exc:
            import logging
            logging.warning(f"[PluginRegistry] Failed to lazy-load plugin '{name}': {exc}")
            return False

    @classmethod
    def auto_discover(cls):
        """
        Tự động nạp toàn bộ Plugin có sẵn trong thư mục plugins/.
         Chỉ chạy MỘT LẦN duy nhất — tránh import lặp.
        """
        if cls._discovered:
            return
        cls._discovered = True

        import importlib
        import pkgutil
        import plugins
        
        #  Force registration of new core plugins if not auto-detected
        from plugins.playwright_plugin import PlaywrightPlugin
        cls.register(PlaywrightPlugin())

        for _, module_name, is_pkg in pkgutil.iter_modules(plugins.__path__):
            try:
                # Nạp module vào runtime
                module = importlib.import_module(f"plugins.{module_name}")
                
                # Quét hàm/class trong module đó để tìm class inherit BasePlugin
                for attribute_name in dir(module):
                    attribute = getattr(module, attribute_name)
                    # Đảm bảo attribute là class, nhưng không phải là BasePlugin gốc
                    if isinstance(attribute, type) and issubclass(attribute, BasePlugin) and attribute is not BasePlugin:
                        # Khởi tạo và đăng ký plugin
                        cls.register(attribute())
            except Exception as _plugin_err:
                import logging
                logging.warning(f"[PluginRegistry] Failed to load plugin '{module_name}': {_plugin_err}")
                continue
