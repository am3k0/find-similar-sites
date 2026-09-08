#!/usr/bin/env python3
"""Setup tool for find-similar-sites. Interactive + non-interactive modes."""
import argparse
import os
import socket
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from config import (  # noqa: E402
    load_config, save_config, CONFIG_FILE,
    validate_hunter_key, validate_quake_token, validate_flint_creds,
    get_proxy_rule, get_proxy_global, DEFAULT_PROXY_RULE, DEFAULT_PROXY_GLOBAL,
)


def check_network():
    results = []
    for host in ("hunter.qianxin.com", "quake.360.net"):
        try:
            socket.getaddrinfo(host, 443, socket.AF_INET)
            results.append((f"DNS {host}", True, "OK"))
        except Exception as e:
            results.append((f"DNS {host}", False, str(e)[:80]))
    try:
        s = socket.create_connection(("106.75.114.125", 23320), timeout=5)
        s.close()
        results.append(("TCP Flint:23320", True, "Reachable"))
    except Exception as e:
        results.append(("TCP Flint:23320", False, str(e)[:80]))
    return results


def check_proxies(rule, globe):
    out = []
    for name, url in (("proxy-rule 7897", rule), ("proxy-global 7898", globe)):
        host = url.split("//")[-1].split(":")[0]
        port = int(url.split(":")[-1])
        try:
            s = socket.create_connection((host, port), timeout=2)
            s.close()
            out.append((name, True, url))
        except Exception as e:
            out.append((name, False, f"{url} ({str(e)[:40]})"))
    return out


def main():
    parser = argparse.ArgumentParser(description="Configure find-similar-sites credentials & proxies")
    parser.add_argument("--hunter-key")
    parser.add_argument("--quake-token")
    parser.add_argument("--flint-user")
    parser.add_argument("--flint-pass")
    parser.add_argument("--proxy-rule", help=f"rule proxy, default {DEFAULT_PROXY_RULE}")
    parser.add_argument("--proxy-global", help=f"global proxy, default {DEFAULT_PROXY_GLOBAL}")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--validate", action="store_true")
    args = parser.parse_args()

    if args.status:
        cfg = load_config()
        if not cfg:
            print("No config found.")
            return
        for k, v in cfg.items():
            if k in ("proxy_rule", "proxy_global"):
                continue
            secret = any(t in k.lower() for t in ("key", "password", "token"))
            print(f"  {k}: {v[:4] + '****' if secret and v else v}")
        print(f"  proxy_rule: {get_proxy_rule()}")
        print(f"  proxy_global: {get_proxy_global()}")
        return

    if args.validate:
        cfg = load_config()
        print("=== Network ===")
        for name, ok, detail in check_network():
            print(f"  {name}: {'OK' if ok else 'FAIL'} - {detail}")
        print("=== Proxies (anti-fraud bypass) ===")
        for name, ok, detail in check_proxies(get_proxy_rule(), get_proxy_global()):
            print(f"  {name}: {'OK' if ok else 'DOWN'} - {detail}")
        print("=== Credentials ===")
        hk = cfg.get("hunter_api_key")
        print(f"  Hunter: {'OK' if hk and validate_hunter_key(hk)[0] else 'FAIL/missing'}"
              f" - {validate_hunter_key(hk)[1] if hk else '-'}")
        qt = cfg.get("quake_token")
        print(f"  Quake:  {'OK' if qt and validate_quake_token(qt)[0] else 'FAIL/missing'}"
              f" - {validate_quake_token(qt)[1] if qt else '-'}")
        fu, fp = cfg.get("flint_username"), cfg.get("flint_password")
        if fu and fp:
            ok, msg = validate_flint_creds(fu, fp, cfg.get("proxy"))
            print(f"  Flint:  {'OK' if ok else 'FAIL'} - {msg}")
        else:
            print("  Flint:  not configured (optional)")
        return

    wrote = False
    if any([args.hunter_key, args.quake_token, args.flint_user, args.flint_pass,
            args.proxy_rule, args.proxy_global]):
        cfg = load_config()
        if args.hunter_key:
            cfg["hunter_api_key"] = args.hunter_key
            ok, msg = validate_hunter_key(args.hunter_key)
            print(f"Hunter: {'OK' if ok else 'FAIL'} - {msg}")
        if args.quake_token:
            cfg["quake_token"] = args.quake_token
            ok, msg = validate_quake_token(args.quake_token)
            print(f"Quake:  {'OK' if ok else 'FAIL'} - {msg}")
        if args.flint_user:
            cfg["flint_username"] = args.flint_user
        if args.flint_pass:
            cfg["flint_password"] = args.flint_pass
        if args.flint_user and args.flint_pass:
            ok, msg = validate_flint_creds(cfg["flint_username"], cfg["flint_password"], cfg.get("proxy"))
            print(f"Flint:  {'OK' if ok else 'FAIL'} - {msg}")
        if args.proxy_rule:
            cfg["proxy_rule"] = args.proxy_rule
        if args.proxy_global:
            cfg["proxy_global"] = args.proxy_global
        save_config(cfg)
        print(f"Config saved to {CONFIG_FILE}")
        return

    print("=" * 60)
    print("  find-similar-sites - Setup Wizard")
    print("=" * 60)
    print(f"Config file: {CONFIG_FILE}")
    print("\nNon-interactive usage:")
    print("  python scripts/init.py --quake-token XXX --hunter-key XXX")
    print("  python scripts/init.py --proxy-rule http://127.0.0.1:7897 --proxy-global http://127.0.0.1:7898")
    print("  python scripts/init.py --validate")


if __name__ == "__main__":
    main()
