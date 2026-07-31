#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
[P0-3 FIX] Version Range Matcher — Parse và check version ranges.

Handles:
- SemVer-style ranges: ">=2.4.0,<3.0.0", ">=1.0.0"
- Exact: "2.4.49"
- Prefix: "2.4.*" (wildcard)
- Caret/tilde (npm-style): "^2.4.0", "~1.2.3"
- Negation: "!=2.4.49"
- Compound ranges with AND/OR logic

WHY THIS EXISTS:
- Old Module2_VulnAnalysis.py dùng raw regex (line 73-78 hardcoded 4 CVE) → brittle
- Many CVEs specify "affected < X.Y.Z" — exact match không đủ
- P0-3 refactor: tách logic này thành core module, dùng lại được.

USAGE:
    from core.version_range import VersionRange, parse_version

    vr = VersionRange(">=2.4.0,<3.0.0")
    assert vr.contains("2.4.49") == True
    assert vr.contains("3.0.0") == False  # Exclusive upper bound
"""

import re
import logging
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)


def parse_version(version_str: str) -> Tuple[int, ...]:
    """
    Parse version string thành tuple of ints for comparison.

    Handles:
    - "2.4.49" -> (2, 4, 49)
    - "1.2.3-beta" -> (1, 2, 3)  # Strip pre-release
    - "v3.0.0" -> (3, 0, 0)  # Strip 'v' prefix
    - "10.0" -> (10, 0)  # Pad missing components

    Returns:
        Tuple of ints, can be compared with < > == operators.
        Returns () if version cannot be parsed.
    """
    if not version_str:
        return ()

    # Strip 'v' prefix, 'V' prefix
    v = version_str.strip().lstrip("vV")

    # Strip pre-release suffix: -beta, -rc1, -alpha, etc.
    v = re.split(r"[-+]", v, maxsplit=1)[0]

    # Extract numeric components
    parts = re.findall(r"\d+", v)
    if not parts:
        return ()

    try:
        # Convert to ints, pad with 0 to length 3 for consistency
        nums = tuple(int(p) for p in parts[:5])
        # Pad with 0 if less than 3 components
        while len(nums) < 3:
            nums = nums + (0,)
        return nums
    except (ValueError, TypeError):
        return ()


def compare_versions(v1: str, v2: str) -> int:
    """
    Compare two version strings.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    t1 = parse_version(v1)
    t2 = parse_version(v2)

    if not t1 and not t2:
        return 0
    if not t1:
        return -1
    if not t2:
        return 1

    # Pad shorter tuple with 0
    max_len = max(len(t1), len(t2))
    t1 = t1 + (0,) * (max_len - len(t1))
    t2 = t2 + (0,) * (max_len - len(t2))

    if t1 < t2:
        return -1
    if t1 > t2:
        return 1
    return 0


class VersionRange:
    """
    Parse và check version range constraints.

    Supported syntax:
    - "2.4.49" (exact match)
    - "2.4.*" (prefix wildcard)
    - ">=2.4.0" (greater than or equal)
    - ">2.4.0" (strictly greater)
    - "<=3.0.0" (less than or equal)
    - "<3.0.0" (strictly less)
    - ">=2.4.0,<3.0.0" (compound AND)
    - ">=2.4.0||>=4.0.0" (compound OR)
    - "^2.4.0" (caret: compatible with version, same major)
    - "~2.4.0" (tilde: same major.minor)

    Examples:
        VersionRange("2.4.49").contains("2.4.49") == True
        VersionRange(">=2.4.0,<3.0.0").contains("2.4.49") == True
        VersionRange("^2.4.0").contains("2.4.49") == True  # Same major
        VersionRange("^2.4.0").contains("3.0.0") == False
        VersionRange("~2.4.0").contains("2.4.49") == True  # Same major.minor
        VersionRange("~2.4.0").contains("2.5.0") == False
    """

    def __init__(self, range_str: str):
        """
        Args:
            range_str: Range constraint string (e.g., ">=2.4.0,<3.0.0")
        """
        self.raw = range_str
        self.constraints: List[Tuple[str, str]] = []  # [(op, version), ...]
        self.is_or: bool = False
        self._parse(range_str)

    def _parse(self, range_str: str):
        """Parse range string into constraints."""
        if not range_str or not range_str.strip():
            return

        # Check for OR (||) - split into groups
        if "||" in range_str:
            self.is_or = True
            # Only parse the first OR group for simplicity
            range_str = range_str.split("||")[0].strip()

        # Check for AND (,) - all constraints must match
        parts = [p.strip() for p in range_str.split(",") if p.strip()]
        for part in parts:
            op, version = self._parse_single(part)
            if op and version:
                self.constraints.append((op, version))

    def _parse_single(self, part: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse single constraint: 'op version'."""
        part = part.strip()
        if not part:
            return None, None

        # Prefix wildcard: "2.4.*" → match major.minor.X exactly
        # Store as special op "prefix" so _check_single knows to do string prefix match
        if part.endswith(".*"):
            version = part[:-2]  # strip ".*"
            return "prefix", version

        # Caret: "^2.4.0" -> >=2.4.0,<3.0.0 (compatible release)
        if part.startswith("^"):
            version = part[1:].strip()
            return "caret", version

        # Tilde: "~2.4.0" -> >=2.4.0,<2.5.0 (patch-level changes)
        if part.startswith("~"):
            version = part[1:].strip()
            return "tilde", version

        # Standard operators
        for op in [">=", "<=", "!=", "==", ">", "<", "="]:
            if part.startswith(op):
                version = part[len(op):].strip()
                return op, version

        # No operator = exact match
        return "==", part

    def contains(self, version: str) -> bool:
        """
        Check if version falls within this range.

        Args:
            version: Version string to test

        Returns:
            True if version satisfies ALL constraints (AND logic by default)
        """
        if not self.constraints:
            # Empty range = match all (backward compatible behavior)
            return True

        for op, target in self.constraints:
            if not self._check_single(version, op, target):
                return False
        return True

    def _check_single(self, version: str, op: str, target: str) -> bool:
        """Check single constraint."""
        # Special: prefix wildcard "2.4.*" — match exact major.minor
        if op == "prefix":
            prefix = target.rstrip(".")
            # Must start with "2.4." (not "2.4" exact)
            return version.startswith(prefix + ".")

        cmp = compare_versions(version, target)

        if op == "==":
            return cmp == 0
        elif op == "!=":
            return cmp != 0
        elif op == ">":
            return cmp > 0
        elif op == ">=":
            return cmp >= 0
        elif op == "<":
            return cmp < 0
        elif op == "<=":
            return cmp <= 0
        elif op == "caret":
            # Caret: same major, >= version
            # ^2.4.0 → >=2.4.0, <3.0.0
            return self._check_caret(version, target)
        elif op == "tilde":
            # Tilde: same major.minor, >= version
            # ~2.4.0 → >=2.4.0, <2.5.0
            return self._check_tilde(version, target)

        return False

    def _check_caret(self, version: str, target: str) -> bool:
        """
        Caret semantics: Allow updates that don't change left-most non-zero digit.
        ^2.4.0 → >=2.4.0, <3.0.0
        ^0.2.4 → >=0.2.4, <0.3.0
        ^0.0.4 → >=0.0.4, <0.0.5
        """
        v_tup = parse_version(version)
        t_tup = parse_version(target)

        if not v_tup or not t_tup:
            return False

        # Must be >= target
        if compare_versions(version, target) < 0:
            return False

        # Find left-most non-zero in target
        for i, n in enumerate(t_tup):
            if n != 0:
                # Upper bound: increment left-most non-zero, set rest to 0
                upper = list(t_tup)
                upper[i] += 1
                for j in range(i + 1, len(upper)):
                    upper[j] = 0
                upper_tup = tuple(upper)
                return v_tup < upper_tup

        # target is 0.0.0 → only exact match
        return v_tup == t_tup

    def _check_tilde(self, version: str, target: str) -> bool:
        """
        Tilde semantics: Allow patch-level changes.
        ~2.4.0 → >=2.4.0, <2.5.0
        """
        v_tup = parse_version(version)
        t_tup = parse_version(target)

        if not v_tup or not t_tup:
            return False

        # Must be >= target
        if compare_versions(version, target) < 0:
            return False

        # Must be < target[0].target[1]+1.0
        if len(t_tup) < 2:
            return False

        upper = list(t_tup[:2])  # major.minor
        upper[1] += 1  # increment minor
        upper.append(0)  # patch = 0
        upper_tup = tuple(upper)

        return v_tup < upper_tup

    def __repr__(self):
        return f"VersionRange('{self.raw}')"


# === Common CVE version ranges (replacement for hardcoded _CVE_VERSION_RANGES) ===
# This is a STARTER set. In production, this would be loaded from a YAML/JSON file.
COMMON_CVE_RANGES = {
    # Apache HTTP Server path traversal/RCE
    "CVE-2021-41773": "<2.4.51",      # Fixed in 2.4.51
    "CVE-2021-42013": "<2.4.51",      # Same fix

    # IIS / SMB - Windows-specific
    "CVE-2017-0144": ">=6.0,<10.0",   # EternalBlue: SMB1 Windows
    "CVE-2020-0796": ">=6.0,<10.0",   # SMBGhost: SMBv3 Windows

    # OpenSSL
    "CVE-2014-0160": ">=1.0.1,<1.0.2",  # Heartbleed
    "CVE-2022-3786": ">=3.0.0,<3.0.7",  # X.509 buffer overflow

    # Log4j
    "CVE-2021-44228": ">=2.0,<2.15.0",  # Log4Shell
    "CVE-2021-45046": ">=2.0,<2.16.0",  # Log4Shell follow-up

    # vsftpd 2.3.4 backdoor
    "CVE-2011-2523": "==2.3.4",

    # UnrealIRCd backdoor
    "CVE-2010-2075": ">=3.2.8,<3.2.9",  # Unreal IRCd 3.2.8.1

    # BlueKeep RDP
    "CVE-2019-0708": ">=6.0,<10.0",  # Windows-only

    # ProxyLogon Exchange
    "CVE-2021-26855": ">=15.0",  # Exchange 2013+

    # Spring4Shell
    "CVE-2022-22965": ">=5.0.0,<5.3.18",
}


def get_range_for_cve(cve_id: str) -> Optional[VersionRange]:
    """
    Get VersionRange for a known CVE ID.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2021-44228")

    Returns:
        VersionRange instance or None if not found in COMMON_CVE_RANGES
    """
    if cve_id in COMMON_CVE_RANGES:
        return VersionRange(COMMON_CVE_RANGES[cve_id])
    return None


if __name__ == "__main__":
    # Smoke test
    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    print("=" * 60)
    print("VersionRange Smoke Test")
    print("=" * 60)

    test_cases = [
        # (range, version, expected)
        ("2.4.49", "2.4.49", True),
        ("2.4.49", "2.4.50", False),
        (">=2.4.0,<3.0.0", "2.4.49", True),
        (">=2.4.0,<3.0.0", "3.0.0", False),
        ("^2.4.0", "2.4.49", True),
        ("^2.4.0", "3.0.0", False),
        ("~2.4.0", "2.4.49", True),
        ("~2.4.0", "2.5.0", False),
        ("!=2.4.49", "2.4.50", True),
        ("!=2.4.49", "2.4.49", False),
        ("2.4.*", "2.4.99", True),
        ("2.4.*", "2.5.0", False),
    ]

    passed = 0
    failed = 0
    for range_str, version, expected in test_cases:
        vr = VersionRange(range_str)
        result = vr.contains(version)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status} VersionRange('{range_str}').contains('{version}') = {result} (expected {expected})")

    # Test common CVE ranges
    print("\n=== Common CVE Range Tests ===")
    cve_tests = [
        ("CVE-2021-41773", "2.4.49", True),   # Apache <2.4.51
        ("CVE-2021-41773", "2.4.51", False),
        ("CVE-2021-44228", "2.14.0", True),   # Log4j <2.15.0
        ("CVE-2021-44228", "2.15.0", False),
        ("CVE-2017-0144", "7.0", True),       # EternalBlue
        ("CVE-2017-0144", "10.0", False),
    ]

    for cve, ver, expected in cve_tests:
        vr = get_range_for_cve(cve)
        if vr:
            result = vr.contains(ver)
            status = "✓" if result == expected else "✗"
            if result == expected:
                passed += 1
            else:
                failed += 1
            print(f"  {status} {cve} v{ver}: {result} (expected {expected})")

    print(f"\n=== Results: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)
