#!/usr/bin/env python3
"""Site query — aggregate CMS/Blacklist/DNS/APP/Mainhost via the 106.75.114.125:23322 API.

Credentials are read from the encrypted config (init.py) or environment:
  FLINT_USERNAME / FLINT_PASSWORD      portal login (init.py --flint-user/--flint-pass)
  FLINT_BASIC_PASS                     gateway basic-auth password (config key flint_basic_pass)
"""
import argparse
import base64
import json
import os
import ssl
import sys
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import load_config  # noqa: E402

BASE = "https://106.75.114.125:23322"
CTX = ssl._create_unverified_context()


def _creds():
    cfg = load_config()
    username = os.environ.get("FLINT_USERNAME") or cfg.get("flint_username")
    password = os.environ.get("FLINT_PASSWORD") or cfg.get("flint_password")
    basic_user = os.environ.get("FLINT_BASIC_USER") or cfg.get("flint_basic_user") or "app"
    basic_pass = os.environ.get("FLINT_BASIC_PASS") or cfg.get("flint_basic_pass")
    return username, password, basic_user, basic_pass


def _basic(username, password):
    if not password:
        raise SystemExit("Missing gateway basic-auth password. "
                         "Set env FLINT_BASIC_PASS or config flint_basic_pass.")
    return base64.b64encode(f"{username}:{password}".encode()).decode()


def login():
    username, password, basic_user, basic_pass = _creds()
    if not username or not password:
        raise SystemExit("Missing Flint credentials. "
                         "Run: python scripts/init.py --flint-user U --flint-pass P")
    auth = _basic(basic_user, basic_pass)
    req = urllib.request.Request(
        f"{BASE}/api/v1/login",
        data=json.dumps({"username": username, "password": password}).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {auth}",
            "User-Agent": "Mozilla/5.0",
        },
    )
    with urllib.request.urlopen(req, timeout=15, context=CTX) as resp:
        data = json.loads(resp.read().decode())
    return data["data"]["access_token"], auth


def query(endpoint, host, token, auth):
    url = f"{BASE}/api/v1/commons/{endpoint}?arg={host}"
    req = urllib.request.Request(url, headers={
        "Access-Token": token,
        "Authorization": f"Basic {auth}",
        "User-Agent": "Mozilla/5.0",
    })
    with urllib.request.urlopen(req, timeout=30, context=CTX) as resp:
        return json.loads(resp.read().decode())


def main():
    parser = argparse.ArgumentParser(description="Site query — aggregate CMS/Blacklist/DNS/APP")
    parser.add_argument("host", help="Target host")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    token, auth = login()
    results = {}
    for endpoint in ["cms", "black_review", "flint", "app_hits", "mainhost_plugins"]:
        try:
            data = query(endpoint, args.host, token, auth)
            results[endpoint] = data.get("data") or {}
        except Exception as e:
            results[endpoint] = {"error": str(e)[:200]}

    if args.json:
        json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return

    print(f"\n{'='*60}")
    print(f"  Site Query: {args.host}")
    print(f"{'='*60}")

    cms = results.get("cms", {})
    print(f"\n  CMSModels: {len(cms.get('cms') or [])} direct, {len(cms.get('history') or [])} history")
    for h in (cms.get("history") or [])[:5]:
        print(f"    {h.get('cmsname','?')} | {h.get('host','?')} | {h.get('ip','?')}")

    blk = results.get("black_review", {})
    blk_list = blk.get("rows") or blk.get("data") or []
    print(f"\n  Blacklist: {len(blk_list) if isinstance(blk_list, list) else '?'} records")
    for b in (blk_list if isinstance(blk_list, list) else [])[:3]:
        print(f"    {b}")

    print(f"\n  DNS: {len(results.get('flint', {}))} records")
    print(f"\n  APP hits: {json.dumps(results.get('app_hits', {}), ensure_ascii=False)[:300]}")
    print(f"\n  Mainhost plugins: {json.dumps(results.get('mainhost_plugins', {}), ensure_ascii=False)[:300]}")


if __name__ == "__main__":
    main()
