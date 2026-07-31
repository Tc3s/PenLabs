from core.wordlist_registry import build_wordlist_profile, resolve_wordlist


def test_wordlist_registry_resolves_mode_aware_defaults():
    stealth = resolve_wordlist("web_content", mode="stealth")
    normal = resolve_wordlist("web_content", mode="web-vuln")
    deep = resolve_wordlist("web_content", mode="full-audit")
    api = resolve_wordlist("api_routes", mode="api-bounty")
    s3 = resolve_wordlist("s3_buckets", mode="cloud-native")

    assert stealth["exists"] is True
    assert stealth["resolved_purpose"] == "web_content_stealth"
    assert normal["exists"] is True
    assert normal["resolved_purpose"] == "web_content"
    assert deep["exists"] is True
    assert deep["resolved_purpose"] == "web_content_deep"
    assert api["path"].endswith("routes-small.kite")
    assert s3["path"].endswith("s3_buckets.txt")


def test_wordlist_profile_marks_password_lists_not_auto_enabled():
    profile = build_wordlist_profile("api-bounty")

    assert profile["web_content"]["exists"] is True
    assert profile["api_params"]["path"].endswith("params.txt")
    assert profile["passwords"]["auto_enabled"] is False

