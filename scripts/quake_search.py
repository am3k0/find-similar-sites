#!/usr/bin/env python3
"""Quake (360) service search — API v3.

Quake is a cyberspace search engine similar to Hunter/FOFA.  This wrapper
enforces the quirks discovered during integration testing:

  * POST https://quake.360.net/api/v3/search/quake_service
  * Headers: X-QuakeToken + a NORMAL browser User-Agent (curl's default UA
    gets q5000 "internal server error" from the WAF).
  * Lucene-style DSL:  domain:"x"  ip:"1.2.3.4" AND service:"http"
    response:"marker"  cert:"x"  title:"x"  favicon:"md5"  html_hash:"md5"
    app:"nginx"  country_cn:"中国" — operators AND / OR / NOT.
  * Rate limit for basic accounts: about one query per 10 s.  The wrapper
    serialises calls and retries q3005 automatically.
  * Basic accounts: ip/port/domain/hostname/title/location/org/asn are
    returned in full; html_hash / favicon / body / status_code inside
    service.http show "暂无权限" (no permission).

Usage:
    python scripts/quake_search.py 'response:"zr_probe"' --size 10
    python scripts/quake_search.py 'domain:"example.com"' --size 5 --raw
"""
import argparse
import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

API = "https://quake.360.net/api/v3/search/quake_service"
MIN_INTERVAL = 11.0          # seconds between queries (basic account limit)
RETRY_WAIT = 13.0
MAX_RETRY = 3

_last_call = 0.0


def _throttle():
    global _last_call
    wait = MIN_INTERVAL - (time.time() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.time()


def search(query, size=10, start=0, start_time=None, end_time=None, timeout=40):
    """Run one Quake query.  Returns a normalized dict (see below) or raises.

    {'code', 'message', 'total', 'results': [{ip, port, domain, hostname,
     title, country, province, city, isp, org, asn, service, time}], 'credit'}
    """
    token = config.get_quake_token()
    if not token:
        return {"code": "no-token", "message": "Quake token not configured "
                "(run: python scripts/init.py --quake-token XXX)", "total": 0,
                "results": [], "query": query}

    body = {"query": query, "start": start, "size": max(1, min(size, 100)), "ignore_cache": False}
    if start_time:
        body["start_time"] = start_time
    if end_time:
        body["end_time"] = end_time

    last_error = None
    for attempt in range(1, MAX_RETRY + 1):
        _throttle()
        req = urllib.request.Request(
            API, data=json.dumps(body).encode(), method="POST",
            headers={
                "X-QuakeToken": token,
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                payload = json.loads(resp.read())
        except Exception as error:
            last_error = f"transport error: {error!r}"
            time.sleep(3)
            continue

        code = payload.get("code")
        if code == 0:
            return _normalize(payload, query)
        if code == "q3005":  # too frequent
            last_error = "q3005 rate limited"
            time.sleep(RETRY_WAIT)
            continue
        return {"code": code, "message": payload.get("message"), "total": 0,
                "results": [], "credit": None, "query": query}
    return {"code": "error", "message": last_error, "total": 0,
            "results": [], "credit": None, "query": query}


def _normalize(payload, query):
    rows = []
    for item in payload.get("data") or []:
        location = item.get("location") or {}
        service = item.get("service") or {}
        http = (service.get("http") or {})
        rows.append({
            "ip": item.get("ip"),
            "port": item.get("port"),
            "domain": item.get("domain"),
            "hostname": item.get("hostname"),
            "title": http.get("title") or "",
            "country": location.get("country_cn") or location.get("country_en"),
            "province": location.get("province_cn") or location.get("province_en"),
            "city": location.get("city_cn") or location.get("city_en"),
            "isp": location.get("isp"),
            "org": item.get("org"),
            "asn": item.get("asn"),
            "service": service.get("name"),
            "transport": item.get("transport"),
            "time": item.get("time"),
        })
    pagination = ((payload.get("meta") or {}).get("pagination") or {})
    return {
        "code": 0,
        "query": query,
        "total": pagination.get("total"),
        "count": pagination.get("count", len(rows)),
        "results": rows,
    }


def main():
    parser = argparse.ArgumentParser(description="Quake (360) service search, API v3")
    parser.add_argument("query", help='Quake DSL, e.g. \'response:"zr_probe"\'')
    parser.add_argument("--size", type=int, default=10)
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--start-time")
    parser.add_argument("--end-time")
    parser.add_argument("--raw", action="store_true", help="print raw API payload")
    args = parser.parse_args()

    result = search(args.query, args.size, args.start, args.start_time, args.end_time)
    if args.raw:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"[quake] query={result['query']!r} code={result.get('code')} total={result.get('total')}")
    for row in result.get("results") or []:
        location = "/".join(x for x in (row.get("country"), row.get("province")) if x)
        print(f"  {row.get('ip')}:{row.get('port')} {row.get('domain') or row.get('hostname') or ''} [{location}] {row.get('title','')[:38]}")


if __name__ == "__main__":
    main()
