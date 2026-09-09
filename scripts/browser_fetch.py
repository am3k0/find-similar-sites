#!/usr/bin/env python3
"""Render a page with a real browser (headless Chrome/Edge), optionally via proxy.

Used when the raw HTTP fetch is not enough (JS-rendered content, anti-bot
gates).  Works without any pip dependency by shelling out to chrome.exe /
msedge.exe with --headless=new --dump-dom.

The user-data-dir is a throwaway temp directory that is deleted afterwards —
this script never leaves files behind.

Usage:
    python scripts/browser_fetch.py http://example.com/ [--proxy rule|global|none|auto]
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402
import net_utils  # noqa: E402

BROWSER_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]
CHROME_FLAGS = [
    "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
    "--disable-extensions", "--disable-background-networking", "--mute-audio",
    "--dump-dom",
]


def find_browser():
    for path in BROWSER_CANDIDATES:
        if os.path.exists(path):
            return path
    return None


def pick_proxy(mode, url):
    """Resolve --proxy mode to a concrete proxy URL."""
    if mode == "none":
        return None
    if mode == "rule":
        return config.get_proxy_rule()
    if mode == "global":
        return config.get_proxy_global()
    # auto: only use a proxy when the direct path looks intercepted.
    probe = net_utils.fetch(url, timeout=8, proxies=())
    if probe["intercepted"] or probe["status"] is None:
        for proxy in (config.get_proxy_rule(), config.get_proxy_global()):
            if net_utils._proxy_alive(proxy):
                return proxy
    return None


def render(url, proxy=None, timeout=30, virtual_budget=9000, max_dom=2_000_000):
    """Render `url` and return {'dom', 'title', 'proxy', 'browser'}."""
    browser = find_browser()
    if not browser:
        return {"error": "no chrome/edge found"}

    user_data = tempfile.mkdtemp(prefix="fss-browser-")
    try:
        cmd = [browser] + CHROME_FLAGS + [
            f"--user-data-dir={user_data}",
            f"--virtual-time-budget={virtual_budget}",
            f"--timeout={int(timeout * 1000)}",
        ]
        if proxy:
            cmd.append(f"--proxy-server={proxy}")
        cmd.append(url)
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout + 15,
            stdin=subprocess.DEVNULL,
        )
        dom = proc.stdout.decode("utf-8", "replace")[:max_dom]
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", dom, re.I | re.S)
        if m:
            title = re.sub(r"\s+", " ", m.group(1)).strip()
        return {
            "dom": dom,
            "title": title,
            "bytes": len(dom),
            "proxy": proxy or "direct",
            "browser": os.path.basename(browser),
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "browser timeout"}
    except Exception as error:
        return {"error": repr(error)}
    finally:
        shutil.rmtree(user_data, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Headless browser page render")
    parser.add_argument("url")
    parser.add_argument("--proxy", default="auto", choices=["auto", "rule", "global", "none"])
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--budget", type=int, default=9000, help="virtual time budget ms")
    parser.add_argument("--dom", action="store_true", help="print the DOM instead of JSON summary")
    args = parser.parse_args()

    proxy = pick_proxy(args.proxy, args.url)
    result = render(args.url, proxy=proxy, timeout=args.timeout, virtual_budget=args.budget)
    if args.dom:
        sys.stdout.write(result.get("dom") or "")
        return
    print(json.dumps({
        k: v for k, v in result.items() if k != "dom"
    } | {"dom_chars": len(result.get("dom") or "")}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
