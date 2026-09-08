#!/usr/bin/env python3
"""Hunter (鹰图) openApi search — v3.0.1 parameter set.

Verified against the live API during integration:

  * GET https://hunter.qianxin.com/openApi/search
  * Params: api-key, search (urlsafe-base64 DSL), page, page_size,
    is_web, start_time, end_time and the newer status_code / port_filter.
  * page_size must be one of 1 / 10 / 20 / 50 / 100 (anything else returns
    400 "页大小不合法"); values are snapped automatically.
  * status_code filters results server-side (verified: a baidu.com query
    went from 36415 to 30612 hits with status_code=200).
  * Response items expose 28 fields including the newer as_org, banner,
    component, ip_tag, is_risk_protocol, isp, os, base_protocol.

Usage:
    python scripts/hunter_search.py 'web.body="zr_probe"' --page-size 10
    python scripts/hunter_search.py 'ip="1.2.3.4"' --status-code 200
"""
import argparse
import base64
import datetime as dt
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402

VALID_PAGE_SIZES = (1, 10, 20, 50, 100)
FIELDS = [
    "url", "ip", "port", "domain", "web_title", "status_code", "protocol",
    "updated_at", "country", "province", "city", "header_server", "isp",
    "as_org", "company", "component", "os", "banner", "base_protocol",
    "cert_sha256", "ip_tag", "asset_tag", "is_risk_protocol", "is_web",
    "icp_exception", "number",
]


def _snap_page_size(value):
    return min(VALID_PAGE_SIZES, key=lambda allowed: abs(allowed - value))


def search(query, page=1, page_size=10, is_web=1, status_code=None,
           port_filter=None, start_date=None, end_date=None, timeout=30,
           retry=2):
    """Run one Hunter query, returns a normalized dict.

    {'code', 'message', 'total', 'rest_quota', 'results': [...]}
    """
    api_key = config.get_hunter_key()
    if not api_key:
        return {"code": "no-key", "message": "Hunter key not configured "
                "(run: python scripts/init.py --hunter-key XXX)", "total": 0,
                "results": [], "rest_quota": None}

    today = dt.date.today()
    params = {
        "api-key": api_key,
        "search": base64.urlsafe_b64encode(query.encode()).decode(),
        "page": page,
        "page_size": _snap_page_size(page_size),
        "is_web": is_web,
        "start_time": start_date or str(today - dt.timedelta(days=29)),
        "end_time": end_date or str(today),
    }
    if status_code:
        params["status_code"] = str(status_code)
    if port_filter is not None:
        params["port_filter"] = "true" if port_filter else "false"

    url = "https://hunter.qianxin.com/openApi/search?" + urllib.parse.urlencode(params)
    last_error = None
    for attempt in range(retry + 1):
        request = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.load(response)
            break
        except urllib.error.HTTPError as error:
            body_text = error.read().decode("utf-8", "replace")
            try:
                payload = json.loads(body_text)
            except Exception:
                payload = {"code": error.code, "message": body_text[:200]}
            if payload.get("code") == 429 and attempt < retry:  # too fast
                time.sleep(4)
                continue
            break
        except Exception as error:
            last_error = repr(error)
            payload = {"code": "error", "message": last_error}
            if attempt < retry:
                time.sleep(3)
                continue

    data = payload.get("data") or {}
    return {
        "code": payload.get("code"),
        "message": payload.get("message"),
        "total": data.get("total"),
        "consume_quota": data.get("consume_quota"),
        "rest_quota": data.get("rest_quota"),
        "results": [
            {field: item.get(field) for field in FIELDS if item.get(field) not in (None, "")}
            for item in data.get("arr") or []
        ],
    }


def main():
    parser = argparse.ArgumentParser(description="Hunter search (openApi v3.0.1 params)")
    parser.add_argument("query", help='Hunter DSL, e.g. \'web.body="marker"\'')
    parser.add_argument("--page", type=int, default=1)
    parser.add_argument("--page-size", type=int, default=10)
    parser.add_argument("--is-web", type=int, default=1, choices=[1, 2, 3],
                        help="1 web assets, 2 non-web, 3 all")
    parser.add_argument("--status-code", help="server-side status code filter, e.g. 200")
    parser.add_argument("--port-filter", choices=["true", "false"])
    parser.add_argument("--start-date")
    parser.add_argument("--end-date")
    parser.add_argument("--raw", action="store_true")
    args = parser.parse_args()

    result = search(
        args.query, page=args.page, page_size=args.page_size, is_web=args.is_web,
        status_code=args.status_code,
        port_filter=None if args.port_filter is None else args.port_filter == "true",
        start_date=args.start_date, end_date=args.end_date,
    )
    if args.raw:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return
    print(f"[hunter] code={result.get('code')} total={result.get('total')} {result.get('rest_quota') or ''}")
    for row in result.get("results") or []:
        location = "/".join(x for x in (row.get("country"), row.get("province")) if x)
        print(f"  {row.get('url')} [{location}] {row.get('web_title','')[:38]}")


if __name__ == "__main__":
    main()
