#!/usr/bin/env python3
"""Pivot from a domain through Certificate Transparency data.

Supports two sources:
  certspotter  Cert Spotter API (default)
  crtsh        crt.sh JSON API
  both         Merge results from both

Usage:
  python scripts/ct_pivot.py example.com --proxy http://127.0.0.1:7898
  python scripts/ct_pivot.py example.com --source crtsh
  python scripts/ct_pivot.py example.com --source both
"""
import argparse
import json
import ssl
import sys
import urllib.parse
import urllib.request


def _build_opener(proxy):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    return urllib.request.build_opener(*handlers)


def _query_certspotter(names, domain, timeout, opener):
    params = [
        ("domain", domain),
        ("include_subdomains", "true"),
        ("expand", "dns_names"),
        ("expand", "issuer"),
    ]
    request = urllib.request.Request(
        "https://api.certspotter.com/v1/issuances?" + urllib.parse.urlencode(params),
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with opener.open(request, timeout=timeout) as response:
        issuances = json.load(response)
    for issuance in issuances:
        for name in issuance.get("dns_names") or []:
            names.add(name)
    return issuances


def _query_crtsh(names, domain, timeout, opener):
    req = urllib.request.Request(
        f"https://crt.sh/?q=%.{domain}&output=json",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    try:
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            certs = json.load(resp)
    except Exception:
        return
    for cert in certs:
        name_value = cert.get("name_value") or ""
        for name in name_value.split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name:
                names.add(name)


def main():
    parser = argparse.ArgumentParser(description="Pivot from a domain through CT data.")
    parser.add_argument("domain")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    parser.add_argument("--timeout", type=float, default=40)
    parser.add_argument("--source", choices=["certspotter", "crtsh", "both"],
                        default="certspotter")
    args = parser.parse_args()

    opener = _build_opener(args.proxy)
    names = set()
    issuances = None

    if args.source in ("certspotter", "both"):
        issuances = _query_certspotter(names, args.domain, args.timeout, opener)

    if args.source in ("crtsh", "both"):
        _query_crtsh(names, args.domain, args.timeout, opener)

    output = {
        "domain": args.domain,
        "source": args.source,
        "name_count": len(names),
        "names": sorted(names),
    }
    if issuances is not None:
        output["issuances"] = issuances
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
