#!/usr/bin/env python3
"""APP plugin discovery — find same-plugin sites on different IPs via the 106.75.114.125 platform.

Chain: host -> app_hits -> plugin_name -> app_analysis (filter by app_plugin_names[]) -> detail hosts -> DNS diff

Usage:
  python scripts/app_discovery.py 146.56.227.102
  python scripts/app_discovery.py 146.56.227.102 --json
"""
import argparse
import base64
import json
import os
import socket
import ssl
import sys
import urllib.request
from collections import defaultdict

CTX = ssl._create_unverified_context()
LOGIN_URL = "https://106.75.114.125:23322/api/v1/login"
APP_ANALYSIS = "https://106.75.114.125:23320/api/v1/app_analysis"
APP_HITS = "https://106.75.114.125:23322/api/v1/commons/app_hits"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_config  # noqa: E402


def _basic_auth():
    cfg = load_config()
    user = os.environ.get("FLINT_BASIC_USER") or cfg.get("flint_basic_user") or "app"
    password = os.environ.get("FLINT_BASIC_PASS") or cfg.get("flint_basic_pass")
    if not password:
        raise SystemExit("Missing gateway basic-auth password. "
                         "Set env FLINT_BASIC_PASS or config flint_basic_pass.")
    return base64.b64encode(f"{user}:{password}".encode()).decode()


BASIC_AUTH = None  # resolved lazily in _login()


def _login():
    global BASIC_AUTH
    cfg = load_config()
    username = os.environ.get("FLINT_USERNAME") or cfg.get("flint_username")
    password = os.environ.get("FLINT_PASSWORD") or cfg.get("flint_password")
    if not username or not password:
        raise SystemExit("Missing Flint credentials. "
                         "Run: python scripts/init.py --flint-user U --flint-pass P")
    BASIC_AUTH = _basic_auth()
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(LOGIN_URL, data=data, headers={
        "Content-Type": "application/json",
        "Authorization": f"Basic {BASIC_AUTH}",
        "User-Agent": "Mozilla/5.0",
    })
    with urllib.request.urlopen(req, timeout=15, context=CTX) as resp:
        return json.loads(resp.read().decode())["data"]["access_token"]


def _api_get(url, token, timeout=30):
    req = urllib.request.Request(url, headers={
        "Access-Token": token,
        "Authorization": f"Basic {BASIC_AUTH}",
        "User-Agent": "Mozilla/5.0",
    })
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as resp:
        return json.loads(resp.read().decode())


def resolve_hosts(hosts):
    """DNS-resolve a list of hostnames, return {host: [ips]}."""
    resolved = {}
    for host in hosts:
        host = host.strip().rstrip(".")
        if not host:
            continue
        try:
            addrs = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
            resolved[host] = addrs
        except Exception:
            resolved[host] = ["DNS_FAILED"]
    return resolved


def discover(seed_host, token):
    """Run the full APP plugin discovery chain for a seed host."""
    result = {"seed": seed_host, "plugin": None, "apps": [], "hosts": [], "candidates": []}

    # Step 1: app_hits -> plugin_name
    data = _api_get(f"{APP_HITS}?arg={seed_host}", token)
    items = data.get("data") or []
    if not items:
        return result
    result["plugin"] = items[0].get("plugin_name")
    result["app_hits"] = items

    if not result["plugin"]:
        return result

    # Step 2: app_analysis filtered by app_plugin_names[]
    plugin = result["plugin"]
    page = 1
    all_apps = []
    while True:
        url = f"{APP_ANALYSIS}?app_plugin_names[]={plugin}&page_size=100&page={page}"
        data = _api_get(url, token)
        batch = data.get("data") or []
        if not batch:
            break
        all_apps.extend(batch)
        if len(batch) < 100:
            break
        page += 1

    result["total_apps"] = len(all_apps)

    # Step 3: Get detail for each app, collect hosts
    host_set = set()
    app_summaries = []
    for app in all_apps:
        app_id = app.get("id")
        sha1 = app.get("sha1")
        summary = {
            "app_name": app.get("app_name", "?"),
            "sha1": sha1,
            "id": app_id,
            "package": app.get("package", "?"),
            "host_list": app.get("host_list") or [],
            "hosts": [],
        }
        # Get detail for full hosts
        if app_id:
            try:
                detail = _api_get(f"{APP_ANALYSIS}/{app_id}", token).get("data") or {}
                for h in detail.get("hosts") or []:
                    hostname = h.get("host")
                    if hostname:
                        host_set.add(hostname)
                        summary["hosts"].append({
                            "host": hostname,
                            "ip": h.get("ip", ""),
                            "domain": h.get("domain", ""),
                        })
            except Exception:
                pass
        # Also from host_list
        for hl in summary.get("host_list", []):
            hostname = hl.get("host")
            if hostname:
                host_set.add(hostname)

        app_summaries.append(summary)

    result["apps"] = app_summaries
    result["hosts"] = sorted(host_set)

    # Step 4: DNS-resolve all hosts, group by IP
    dns = resolve_hosts(result["hosts"])
    seed_dns = dns.get(seed_host, [])
    seed_ips = set(seed_dns)

    ip_groups = defaultdict(list)
    for host, ips in dns.items():
        for ip in ips:
            ip_groups[ip].append(host)

    # Find different-IP candidates (same plugin, different IP from seed)
    for ip, hosts in ip_groups.items():
        if ip == "DNS_FAILED":
            continue
        if seed_ips and ip in seed_ips:
            continue
        for host in hosts:
            if host == seed_host:
                continue
            result["candidates"].append({
                "host": host,
                "ip": ip,
                "different_from_seed": True,
            })

    return result


def main():
    parser = argparse.ArgumentParser(
        description="APP plugin discovery — find same-plugin sites on different IPs"
    )
    parser.add_argument("host", help="Seed host")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    token = _login()
    result = discover(args.host, token)

    if args.json:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2, default=str)
        print()
        return

    # Human-readable output
    print(f"\n{'='*60}")
    print(f"  APP Plugin Discovery: {args.host}")
    print(f"{'='*60}")

    if not result["plugin"]:
        print("\n  No APP plugin coverage detected for this host.")
        return

    print(f"\n  Plugin: {result['plugin']}")
    print(f"  Apps covered: {result['total_apps']}")
    hosts = result.get("hosts", [])
    print(f"  Unique hosts: {len(hosts)}")

    if hosts:
        dns = resolve_hosts(hosts)
        seed_ips = set(resolve_hosts([args.host]).get(args.host, []))
        print(f"\n  Seed IPs: {sorted(seed_ips) if seed_ips else 'unknown'}")
        print(f"\n  All hosts by IP:")
        groups = defaultdict(list)
        for h, ips in dns.items():
            for ip in ips:
                groups[ip].append(h)
        for ip, hs in sorted(groups.items()):
            marker = " *** DIFF IP ***" if seed_ips and ip not in seed_ips else ""
            print(f"    {ip}: {len(hs)} hosts{marker}")
            for h in hs[:5]:
                print(f"      {h}")
            if len(hs) > 5:
                print(f"      ... and {len(hs)-5} more")

    candidates = result.get("candidates", [])
    if candidates:
        print(f"\n  Different-IP candidates ({len(candidates)}):")
        for c in candidates[:20]:
            print(f"    {c['host']} -> {c['ip']}")


if __name__ == "__main__":
    main()
