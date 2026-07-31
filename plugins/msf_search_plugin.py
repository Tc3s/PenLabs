from core.base_plugin import BasePlugin
from utils.msf_smart_lookup import get_lookup, search_msf_for_cve

class MSFSearchPlugin(BasePlugin):
    def name(self) -> str:
        return "MSFSearch"

    def description(self) -> str:
        return "Động cơ tìm kiếm MSF Modules V2 — Offline Multi-Key Index (CVE/Port/Service/Product/Nuclei)."

    def check_installed(self) -> bool:
        import os
        map_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "msf_module_map.json")
        return os.path.exists(map_path)

    def run(self, cve_id: str, session_dir: str):
        """Backward-compatible: tìm modules theo CVE ID."""
        return search_msf_for_cve(cve_id, session_dir)

    def smart_search(self, cve=None, port=None, service=None, product=None,
                     nuclei_template=None, limit=6):
        """V2 API: Tìm kiếm đa chiều (CVE/Port/Service/Product/Nuclei)."""
        lookup = get_lookup()
        return lookup.smart_search(
            cve=cve, port=port, service=service,
            product=product, nuclei_template=nuclei_template,
            limit=limit
        )
