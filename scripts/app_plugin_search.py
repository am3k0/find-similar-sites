#!/usr/bin/env python3
"""Query app_analysis API by host, domain, ip, plugin, or family."""
import argparse
import json
import os
import ssl
import sys
import urllib.request

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
from flint_auth import get_token

CTX = ssl._create_unverified_context()
BASE = "https://106.75.114.125:23320/api/v1/app_analysis"


def query(params, proxy=None):
    token = get_token(proxy)
    from urllib.parse import urlencode
    url = BASE + "?" + urlencode(params, doseq=True)
    req = urllib.request.Request(url, headers={
        "Access-Token": token,
        "User-Agent": "Mozilla/5.0",
    })
    with urllib.request.urlopen(req, timeout=30, context=CTX) as resp:
        return json.loads(resp.read().decode())


def main():
    parser = argparse.ArgumentParser(description="Query app_analysis API")
    parser.add_argument("--host")
    parser.add_argument("--domain")
    parser.add_argument("--ip")
    parser.add_argument("--plugin")
    parser.add_argument("--family")
    parser.add_argument("--page-size", type=int, default=50)
    parser.add_argument("--page", type=int, default=1)
    parser.add_argument("--proxy", default="http://127.0.0.1:7898")
    args = parser.parse_args()

    params = {"page_size": str(args.page_size), "page": str(args.page)}
    for key in ["host", "domain", "ip", "plugin", "family"]:
        val = getattr(args, key)
        if val:
            params[key] = val

    data = query(params, args.proxy)
    apps = data.get("data") or []
    print(f"Found {len(apps)} apps")
    for i, app in enumerate(apps[:args.page_size]):
        print(f"\n--- App {i+1} ---")
        for key in ["app_name", "package", "family", "family_app_count",
                     "app_plugin_names", "is_app_plugin", "is_site_plugin",
                     "labels", "sha1", "host"]:
            print(f"  {key}: {app.get(key)}")
        hosts_raw = app.get("hosts") or []
        hosts = []
        for h in hosts_raw:
            if isinstance(h, dict):
                hosts.append(h.get("host", str(h)))
            else:
                hosts.append(str(h))
        print(f"  hosts ({len(hosts)}):")
        for h in hosts[:30]:
            print(f"    {h}")

if __name__ == "__main__":
    main()
