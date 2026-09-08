#!/usr/bin/env python3
"""Pivot through same-IP / same-CNAME sites via 106.75.114.125 flint_cms API.

For each seed host, returns all other hosts sharing an IP or CNAME,
with CMS labels when available.  Useful for finding same-CMS sites
on different infrastructure without FOFA API access.

Usage:
  $env:FLINT_USERNAME = "..."
  $env:FLINT_PASSWORD = "..."
  python scripts/flint_cms_pivot.py bj.fqf312.com --proxy http://127.0.0.1:7898

Output is JSON with IP_cms and CDN_cms grouped by seed, plus a
deduplicated unified candidate list.
"""
import argparse
import json
import os
import sys

# Allow running from the skill's scripts directory
_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)

from flint_auth import post_json


def pivot(hosts, proxy=None):
    payload = post_json("/api/v1/flint_cms/query", {"hosts": hosts}, proxy=proxy)
    if payload.get("code") != 200:
        print(f"API error: {payload.get('msg')}", file=sys.stderr)
        raise SystemExit(1)
    return payload["data"]


def main():
    parser = argparse.ArgumentParser(description="Pivot through same-IP/CNAME CMS sites.")
    parser.add_argument("hosts", nargs="+", help="Seed host(s)")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL for the API call")
    parser.add_argument("--json", dest="raw", action="store_true", help="Output raw API response")
    args = parser.parse_args()

    data = pivot(args.hosts, args.proxy)
    if args.raw:
        json.dump(data, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return

    unified = []
    for host, result in data.get("hosts", {}).items():
        summary = result.get("master_summary", {})
        ip_candidates = result.get("IP_cms") or []
        cdn_candidates = result.get("CDN_cms") or []

        seed_ips = set((summary.get("IP") or "").replace(",", " ").split())
        seed_cdns = set((summary.get("CDN") or "").replace(",", " ").split())

        for entry in ip_candidates:
            unified.append({
                "seed": host,
                "type": "same_ip",
                "target": entry.get("IP"),
                "host": entry.get("host"),
                "first_seen": entry.get("first_seen"),
                "feature_value": entry.get("feature_value"),
                "cms_value": entry.get("cms_value"),
            })
        for entry in cdn_candidates:
            unified.append({
                "seed": host,
                "type": "same_cdn",
                "target": entry.get("CDN"),
                "host": entry.get("host"),
                "first_seen": entry.get("first_seen"),
                "feature_value": entry.get("feature_value"),
                "cms_value": entry.get("cms_value"),
            })

    output = {
        "input_hosts": args.hosts,
        "ip_targets": data.get("ip_targets"),
        "cdn_targets": data.get("cdn_targets"),
        "hosts": {
            host: {
                "master_summary": result.get("master_summary"),
                "IP_cms_count": result.get("IP_cms_count"),
                "CDN_cms_count": result.get("CDN_cms_count"),
                "ip_targets": result.get("ip_targets"),
                "cdn_targets": result.get("cdn_targets"),
            }
            for host, result in data.get("hosts", {}).items()
        },
        "unified_candidates": unified,
        "unique_hosts": sorted({c["host"] for c in unified if c["host"]}),
    }
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
