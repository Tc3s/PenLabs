#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GOWITNESS WRAPPER — Visual Recon (V1.0)
========================================
Standalone wrapper for gowitness screenshotting.
Captures screenshots of target URLs and returns paths.
Supports Base64 encoding for embedding in HTML reports.
"""

import os
import sys
import subprocess
import shutil
import base64
import logging
from typing import List, Dict, Optional

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from config import Config

# ANSI Colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


def check_gowitness() -> bool:
    """Check if gowitness is installed and available."""
    if shutil.which("gowitness"):
        return True
    go_bin = os.path.expanduser("~/go/bin/gowitness")
    return os.path.isfile(go_bin) and os.access(go_bin, os.X_OK)


def take_screenshots(
    target_list_path: str = "",
    urls: List[str] = None,
    output_dir: str = "output/screenshots",
    timeout: int = None,
    threads: int = None,
) -> List[str]:
    """
    Capture screenshots of target web services using gowitness.

    Args:
        target_list_path: Path to a file containing URLs (one per line).
        urls: List of URLs to screenshot (alternative to target_list_path).
        output_dir: Directory to save screenshots.
        timeout: Timeout per URL in seconds (default from Config).
        threads: Number of concurrent threads (default from Config).

    Returns:
        List of paths to captured screenshot files.
    """
    if not check_gowitness():
        print(f"{RED}[!] gowitness not installed. Install: go install github.com/sensepost/gowitness@latest{RESET}")
        return []

    timeout = timeout or Config.GOWITNESS_TIMEOUT
    threads = threads or Config.GOWITNESS_THREADS

    screenshots_dir = os.path.join(output_dir, "screenshots")
    os.makedirs(screenshots_dir, exist_ok=True)

    # Prepare input file
    input_file = target_list_path
    if not input_file and urls:
        input_file = os.path.join(output_dir, "gowitness_targets.txt")
        os.makedirs(output_dir, exist_ok=True)
        with open(input_file, 'w') as f:
            f.write("\n".join(urls))

    if not input_file or not os.path.exists(input_file):
        print(f"{RED}[!] No target file provided for gowitness.{RESET}")
        return []

    # Count targets
    with open(input_file, 'r') as f:
        target_count = sum(1 for line in f if line.strip())

    print(f"{CYAN}[*] gowitness: Capturing {target_count} targets → {screenshots_dir}{RESET}")
    print(f"    Timeout: {timeout}s | Threads: {threads}")

    # Build command
    gowitness_bin = shutil.which("gowitness") or os.path.expanduser("~/go/bin/gowitness")
    cmd = [
        gowitness_bin, "scan", "file",
        "-f", input_file,
        "--timeout", str(timeout),
        "--threads", str(threads),
        "--screenshot-path", screenshots_dir,
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in process.stdout:
            logging.debug(f"[gowitness] {line.strip()}")
        process.wait(timeout=target_count * timeout + 30)

        if process.returncode == 0:
            # Collect screenshot paths
            screenshots = []
            if os.path.exists(screenshots_dir):
                for fname in sorted(os.listdir(screenshots_dir)):
                    if fname.lower().endswith(('.png', '.jpg', '.jpeg')):
                        screenshots.append(os.path.join(screenshots_dir, fname))

            print(f"{GREEN}[+] gowitness: Captured {len(screenshots)} screenshots successfully.{RESET}")
            return screenshots
        else:
            print(f"{RED}[!] gowitness exited with code {process.returncode}{RESET}")
            return _collect_partial(screenshots_dir)

    except subprocess.TimeoutExpired:
        print(f"{YELLOW}[!] gowitness timed out. Collecting partial results...{RESET}")
        process.kill()
        return _collect_partial(screenshots_dir)
    except Exception as e:
        print(f"{RED}[!] gowitness exception: {e}{RESET}")
        return _collect_partial(screenshots_dir)


def _collect_partial(screenshots_dir: str) -> List[str]:
    """Collect any partial screenshots that were captured."""
    screenshots = []
    if os.path.exists(screenshots_dir):
        for fname in sorted(os.listdir(screenshots_dir)):
            if fname.lower().endswith(('.png', '.jpg', '.jpeg')):
                screenshots.append(os.path.join(screenshots_dir, fname))
    return screenshots


def screenshot_to_base64(screenshot_path: str) -> str:
    """
    Convert a screenshot file to Base64 data URI string.
    For embedding directly into HTML reports (Zero External Dependency).

    Args:
        screenshot_path: Full path to screenshot file.

    Returns:
        Base64 data URI string (e.g., "data:image/png;base64,...")
    """
    if not os.path.exists(screenshot_path):
        return ""

    ext = os.path.splitext(screenshot_path)[1].lower()
    mime_map = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
    }
    mime = mime_map.get(ext, 'image/png')

    try:
        with open(screenshot_path, 'rb') as f:
            data = f.read()
        b64 = base64.b64encode(data).decode('ascii')
        return f"data:{mime};base64,{b64}"
    except Exception as e:
        logging.warning(f"[gowitness_wrapper] Failed to encode {screenshot_path}: {e}")
        return ""


def get_screenshots_map(screenshots_dir: str) -> Dict[str, str]:
    """
    Build a mapping from URL/hostname to Base64-encoded screenshot.
    Gowitness names screenshots based on the URL, so we parse the filename.

    Args:
        screenshots_dir: Directory containing gowitness screenshots.

    Returns:
        Dict mapping hostname/URL patterns to Base64 data URIs.
    """
    mapping = {}
    if not os.path.exists(screenshots_dir):
        return mapping

    for fname in os.listdir(screenshots_dir):
        if not fname.lower().endswith(('.png', '.jpg', '.jpeg')):
            continue
        full_path = os.path.join(screenshots_dir, fname)
        # Gowitness filenames: http-example.com-80.png or similar
        # We use the filename (minus extension) as the key
        key = os.path.splitext(fname)[0]
        b64 = screenshot_to_base64(full_path)
        if b64:
            mapping[key] = b64

    return mapping


def export_live_urls(urls: List[str], output_path: str) -> str:
    """
    Export live URLs to a file for gowitness consumption.

    Args:
        urls: List of live URL strings.
        output_path: Path to write the output file.

    Returns:
        Path to the written file.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w') as f:
        for url in urls:
            url = url.strip()
            if url and (url.startswith('http://') or url.startswith('https://')):
                f.write(url + '\n')
    return output_path


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Gowitness Screenshot Wrapper")
    p.add_argument("-f", "--file", help="File containing URLs (one per line)")
    p.add_argument("-u", "--urls", nargs="+", help="URLs to screenshot")
    p.add_argument("-o", "--output", default="output/screenshots", help="Output directory")
    p.add_argument("--timeout", type=int, default=15, help="Timeout per URL")
    p.add_argument("--threads", type=int, default=4, help="Number of threads")
    args = p.parse_args()

    results = take_screenshots(
        target_list_path=args.file or "",
        urls=args.urls,
        output_dir=args.output,
        timeout=args.timeout,
        threads=args.threads,
    )
    print(f"\nCaptured {len(results)} screenshots:")
    for r in results:
        print(f"  → {r}")
