#!/usr/bin/env python3
"""Explore 106.75.114.125 platform: app_analysis, plugin query, link analysis, 准星."""
import argparse
import json
import os
import ssl
import sys
import urllib.request
import urllib.parse

_here = os.path.dirname(os.path.abspath(__file__))
if _here not in sys.path:
    sys.path.insert(0, _here)
from flint_auth import get_token

CTX = ssl._create_unverified_context()
BASE_23320 = "https://106.75.114.125:23320"


def api_get(endpoint, params=None, proxy=None):
    token = get_token(proxy)
    url = BASE_23320 + endpoint
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)
    req = urllib.request.Request(url, headers={
        "Access-Token": token, "User-Agent": "Mozilla/5.0",
    })
    with urllib.request.urlopen(req, timeout=30, context=CTX) as resp:
        return json.loads(resp.read().decode())


def extract_hosts(app):
    hosts_raw = app.get("hosts") or []
    hosts = []
    for h in hosts_raw:
        if isinstance(h, dict):
            hosts.append(h.get("host", ""))
        else:
            hosts.append(str(h))
    return [h for h in hosts if h]


def explore(seed_host, proxy):
    print(f"\n{'='*60}")
    print(f"Exploring: {seed_host}")
    print(f"{'='*60}")

    # 1. App analysis by host
    print("\n--- app_analysis?host ---")
    try:
        data = api_get("/api/v1/app_analysis", {"host": seed_host, "page_size": "5"}, proxy)
        apps = data.get("data") or []
        print(f"  Results: {len(apps)}")
        for app in apps[:3]:
            hosts = extract_hosts(app)
            print(f"  APP: {app.get('app_name')}")
            print(f"    sha1: {app.get('sha1')}")
            print(f"    family: {app.get('family')} ({app.get('family_app_count')} total)")
            print(f"    plugins: {app.get('app_plugin_names')} (is_app_plugin={app.get('is_app_plugin')})")
            print(f"    labels: {app.get('labels')}")
            print(f"    host (searched): {app.get('host')}")
            print(f"    hosts ({len(hosts)}):")
            for h in hosts[:10]:
                print(f"      {h}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 2. Plugin via plugin param
    print("\n--- app_analysis?plugin ---")
    try:
        for plugin in ["plugin/messenger", "plugin/flutter_touzi", "capacitor_config"]:
            data = api_get("/api/v1/app_analysis", {"plugin": plugin, "page_size": "3"}, proxy)
            apps = data.get("data") or []
            names = [a.get("app_name","?") for a in apps[:5]]
            print(f"  {plugin}: {len(apps)} apps -> {names}")
    except Exception as e:
        print(f"  ERROR: {e}")

    # 3. Try link analysis endpoints
    print("\n--- case/link endpoints ---")
    for endpoint in ["/api/v1/case/link", "/api/v1/case/links", "/api/v1/link/list",
                      "/api/v1/link_analysis", "/api/v1/case/link/list"]:
        try:
            data = api_get(endpoint, {"host": seed_host, "page_size": "3"}, proxy)
            print(f"  GET {endpoint}: {data.get('code')} | {str(data)[:200]}")
        except urllib.error.HTTPError as e:
            print(f"  GET {endpoint}: HTTP {e.code}")
        except Exception as e:
            print(f"  GET {endpoint}: {str(e)[:80]}")

    # 4. Try query zone / plugin lookup by host
    print("\n--- query zone / plugin lookup ---")
    for endpoint in ["/api/v1/plugin/query", "/api/v1/zone/query",
                      "/api/v1/app_plugin/search", "/api/v1/search/plugin"]:
        for method in ["GET", "POST"]:
            try:
                if method == "GET":
                    params = {"host": seed_host, "page_size": "3"}
                    data = api_get(endpoint, params, proxy)
                else:
                    token = get_token(proxy)
                    url = BASE_23320 + endpoint
                    body = json.dumps({"hosts": [seed_host]}).encode()
                    req = urllib.request.Request(url, data=body, headers={
                        "Content-Type": "application/json",
                        "Access-Token": token,
                        "User-Agent": "Mozilla/5.0",
                    })
                    with urllib.request.urlopen(req, timeout=15, context=CTX) as resp:
                        data = json.loads(resp.read().decode())
                print(f"  {method} {endpoint}: {data.get('code')} | {str(data)[:150]}")
                break
            except urllib.error.HTTPError as e:
                if method == "POST":
                    print(f"  {method} {endpoint}: HTTP {e.code}")
            except Exception as e:
                if method == "POST":
                    print(f"  {method} {endpoint}: {str(e)[:80]}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("hosts", nargs="*", default=["bj.fqf312.com", "zhaoshanghuanqiu20.cc", "wbmykcxr.cn"])
    parser.add_argument("--proxy", default="http://127.0.0.1:7898")
    args = parser.parse_args()
    for host in args.hosts:
        explore(host, args.proxy)

if __name__ == "__main__":
    main()
