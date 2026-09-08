#!/usr/bin/env python3
"""Query URL collection records via 106.75.114.125 ck_sh_urls_all API.

Two modes:
  --by-host    prefix-match on host (default)
  --by-domain  extract main domain first, then query

Usage:
  $env:FLINT_USERNAME = "..."
  $env:FLINT_PASSWORD = "..."
  python scripts/url_collection.py bj.fqf312.com kk.fqfhoutai.com --by-domain --proxy http://127.0.0.1:7898
"""
import argparse
import json
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from flint_auth import post_json


def query_by_host(hosts, proxy=None):
    return post_json("/api/v1/ck/sh_urls_all/query_by_host", {"hosts": hosts}, proxy=proxy)


def query_by_domain(hosts, proxy=None):
    return post_json("/api/v1/ck/sh_urls_all/query_by_domain", {"hosts": hosts}, proxy=proxy)


def main():
    parser = argparse.ArgumentParser(description="Query URL collection records.")
    parser.add_argument("hosts", nargs="+", help="Host(s) to query")
    parser.add_argument("--by-domain", action="store_true", help="Extract main domain first")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL for the API call")
    args = parser.parse_args()

    if args.by_domain:
        payload = query_by_domain(args.hosts, args.proxy)
    else:
        payload = query_by_host(args.hosts, args.proxy)

    if payload.get("code") != 200:
        print(f"API error: {payload.get('msg')}", file=sys.stderr)
        raise SystemExit(1)

    data = payload["data"]

    # Build a compact summary
    summary = {
        "input_count": data.get("input_count"),
        "row_limit": data.get("row_limit"),
        "table": data.get("table"),
        "hosts": {},
    }
    all_paths = set()
    for host, result in data.get("hosts", {}).items():
        entry = {
            "total": result.get("total"),
        }
        if "query_domain" in result:
            entry["query_domain"] = result.get("query_domain")
        if "msg" in result:
            entry["msg"] = result.get("msg")
        rows = result.get("rows") or []
        entry["urls"] = [r.get("raw") for r in rows]
        entry["domains"] = sorted({r.get("domain") for r in rows if r.get("domain")})
        entry["sources"] = sorted({r.get("source") for r in rows if r.get("source")})
        summary["hosts"][host] = entry
        for r in rows:
            raw = r.get("raw") or ""
            if raw:
                all_paths.add(raw)

    summary["unique_urls"] = sorted(all_paths)
    json.dump(summary, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
