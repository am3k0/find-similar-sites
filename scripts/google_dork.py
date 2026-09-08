#!/usr/bin/env python3
"""Search Google for unique site markers to find same-CMS domains.

A free fallback when Hunter quota is exhausted or returns nothing.
Uses exact-quoted search strings from fingerprint markers.

Usage:
  python scripts/google_dork.py "/bt-stats.js?site=" "/assets/news/comm.js" --proxy http://127.0.0.1:7898

Output is JSON with discovered domains and the queries used.
"""
import argparse
import json
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request

_SEARCH_URL = "https://www.google.com/search"
_DOMAIN_RE = re.compile(r"https?://([^/\"<>]+)")


def _build_opener(proxy):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def search(marker, opener, timeout, max_results):
    """Return domain names found for a single marker query."""
    params = urllib.parse.urlencode({"q": f'"{marker}"', "num": min(max_results, 100)})
    url = f"{_SEARCH_URL}?{params}"
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    })
    try:
        with opener.open(req, timeout=timeout) as resp:
            html = resp.read().decode("utf-8", "replace")
    except Exception as exc:
        return set(), str(exc)

    domains = set()
    for match in _DOMAIN_RE.finditer(html):
        raw = match.group(1)
        # Filter out Google-owned domains and CDNs
        if any(bad in raw for bad in ("google.", "googleapis.", "gstatic.", "youtube.")):
            continue
        domains.add(raw)
    return domains, None


def main():
    parser = argparse.ArgumentParser(description="Google dork for same-CMS domains.")
    parser.add_argument("markers", nargs="+", help="Unique marker strings to search")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--max-results", type=int, default=50)
    parser.add_argument("--delay", type=float, default=2.0,
                        help="Delay between queries in seconds (default: 2)")
    args = parser.parse_args()

    opener = _build_opener(args.proxy)
    results = {}
    all_domains = set()

    for marker in args.markers:
        domains, error = search(marker, opener, args.timeout, args.max_results)
        results[marker] = {
            "domains": sorted(domains),
            "count": len(domains),
        }
        if error:
            results[marker]["error"] = error
        all_domains |= domains
        if len(args.markers) > 1:
            time.sleep(args.delay)

    output = {
        "queries": args.markers,
        "marker_results": results,
        "unique_domains": sorted(all_domains),
        "domain_count": len(all_domains),
    }
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
