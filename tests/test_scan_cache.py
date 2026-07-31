"""Test ScanCache table and helper functions (get_cached_result, save_to_cache)."""
import pytest
from datetime import datetime, timezone, timedelta
from core.db import init_db, get_session, get_or_create_project, get_cached_result, save_to_cache, ScanCache

def test_scan_cache_lifecycle():
    # Use in-memory database for testing
    db_url = "sqlite:///:memory:"
    init_db(db_url)
    
    with get_session(db_url) as session:
        # Create dummy project
        project = get_or_create_project(session, name="Test Project", slug="test-project")
        project_id = project.id
        
        host = "example.com"
        tool = "nuclei"
        cache_key = "tags=cve:sev=high"
        result_data = {"vulns": [{"id": "CVE-2021-44228", "severity": "critical"}]}
        
        # 1. Cache HIT should return None initially
        cached = get_cached_result(session, project_id, host, tool, cache_key, ttl_hours=24)
        assert cached is None
        
        # 2. Save result to cache
        save_to_cache(session, project_id, host, tool, cache_key, result_data, ttl_hours=24)
        
        # 3. Retrieve from cache — should HIT and return the identical structure
        cached = get_cached_result(session, project_id, host, tool, cache_key, ttl_hours=24)
        assert cached is not None
        assert cached["vulns"][0]["id"] == "CVE-2021-44228"
        
        # 4. Check expired cache — ttl_hours=0 should cause expiry
        cached_expired = get_cached_result(session, project_id, host, tool, cache_key, ttl_hours=0)
        assert cached_expired is None
