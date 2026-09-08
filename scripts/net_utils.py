#!/usr/bin/env python3
"""Network layer for find-similar-sites: proxy fallback, interception
detection, DNS and IP geo.

Direct connection is always tried first (fastest).  When the local network
intercepts the request (anti-fraud 302 to a bare IP / response.html, DNS
answers of 0.0.0.0 / 127.0.0.1, warning page titles) the request is retried
through the rule proxy (7897) and then the global proxy (7898).

Everything here is read-only GET/HEAD.  No files are written.
"""
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

CTX = ssl._create_unverified_context()
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

INTERCEPT_TITLES = ("反诈", "警告", "访问受限", "拦截", "违法", "网站拦截")
POISONED_DNS = {"0.0.0.0", "127.0.0.1", "::", "::1"}

_proxy_alive_cache = {}
_geo_cache = {}


# ---------------------------------------------------------------- proxies

def _proxy_alive(proxy_url, timeout=2.0, ttl=60.0):
    """TCP-check a local proxy, cached briefly."""
    now = time.time()
    hit = _proxy_alive_cache.get(proxy_url)
    if hit and now - hit[1] < ttl:
        return hit[0]
    try:
        parsed = urllib.parse.urlparse(proxy_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        ok = True
    except Exception:
        ok = False
    _proxy_alive_cache[proxy_url] = (ok, now)
    return ok


def _opener(proxy=None):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    handlers.append(urllib.request.HTTPSHandler(context=CTX))
    handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects: record Location and stop."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# ---------------------------------------------------------------- detection

def dns_poisoned(ips):
    """True when every resolved address is a sinkhole answer."""
    real = [ip for ip in ips if ip not in POISONED_DNS]
    return bool(ips) and not real


def looks_intercepted(status=None, headers=None, body_text="", dns_ips=None):
    """Heuristics for anti-fraud / ISP interception."""
    headers = headers or {}
    location = (headers.get("Location") or headers.get("location") or "").strip()
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", body_text or "", re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
    if location:
        if re.match(r"^https?://\d+\.\d+\.\d+\.\d+(/|$)", location):
            return True, f"30x -> bare IP {location}"
        if "response.html" in location:
            return True, "30x -> response.html"
    if title and any(word in title for word in INTERCEPT_TITLES):
        return True, f"interception title {title!r}"
    if dns_ips and dns_poisoned(dns_ips):
        return True, f"poisoned DNS {dns_ips}"
    return False, ""


# ---------------------------------------------------------------- fetching

def resolve(host, timeout=4.0):
    """Local DNS resolution -> sorted unique IPs (raw answers, may be poisoned)."""
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except Exception:
        return []


def _attempt(opener, url, timeout, max_bytes):
    """Single fetch without redirect-following. Returns (status, headers, body)."""
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(max_bytes)
        return resp.status, dict(resp.headers), body


def _safe_attempt(opener, url, timeout, max_bytes):
    try:
        return _attempt(opener, url, timeout, max_bytes)
    except urllib.error.HTTPError as error:
        try:
            body = error.read(max_bytes)
        except Exception:
            body = b""
        return error.code, dict(error.headers or {}), body
    except Exception:
        return None, {}, b""


def fetch(url, timeout=10, max_bytes=1_500_000, proxies=("rule", "global")):
    """Fetch a URL with automatic interception bypass.

    Order: direct -> rule proxy -> global proxy (each retried once on
    transport failure or 5xx).  Stops at the first response that is both
    successful and NOT an interception page.

    Returns dict with keys:
        path        'direct' | 'rule' | 'global' | 'none'
        status      int | None
        headers     dict
        body        bytes
        final_url   str (url after inline redirects, best effort)
        redirects   [location, ...] observed redirect chain
        intercepted bool  (True when the best response still looks blocked)
        note        short human explanation
    """
    import config as _config

    rule_proxy = _config.get_proxy_rule() if proxies and "rule" in proxies else None
    global_proxy = _config.get_proxy_global() if proxies and "global" in proxies else None

    attempts = [("direct", None)]
    if rule_proxy:
        attempts.append(("rule", rule_proxy))
    if global_proxy:
        attempts.append(("global", global_proxy))

    best = {"path": "none", "status": None, "headers": {}, "body": b"",
            "final_url": url, "redirects": [], "intercepted": True, "note": "no attempt"}

    def try_path(name, proxy):
        """One attempt down a path (following same-origin redirects).

        Returns (candidate, usable) where usable means 2xx-4xx and not
        intercepted.
        """
        opener = _opener(proxy)
        current = url
        redirects = []
        status = None
        headers = {}
        body = b""
        for _hop in range(5):
            status, headers, body = _safe_attempt(opener, current, timeout, max_bytes)
            if status is None or status >= 500:
                return ({"path": name, "status": status, "headers": headers, "body": b"",
                         "final_url": current, "redirects": redirects,
                         "intercepted": True, "note": f"{status or 'no response'}"}, False)
            location = (headers.get("Location") or headers.get("location") or "").strip()
            if status in (301, 302, 303, 307, 308) and location:
                redirects.append(location)
                nxt = urllib.parse.urljoin(current, location)
                if re.match(r"^https?://\d+\.\d+\.\d+\.\d+(/|:|$)", nxt):
                    # bare-IP redirect = interception; stop following
                    current = nxt
                    break
                current = nxt
                continue
            break

        text = body.decode("utf-8", "replace") if body else ""
        host = urllib.parse.urlparse(current).hostname or ""
        intercepted, why = looks_intercepted(
            status, headers, text, resolve(host) if host else None)
        candidate = {"path": name, "status": status, "headers": headers, "body": body,
                     "final_url": current, "redirects": redirects,
                     "intercepted": intercepted, "note": why}
        return candidate, not intercepted

    for name, proxy in attempts:
        if proxy and not _proxy_alive(proxy):
            continue
        for retry in range(2):  # one retry per path
            candidate, usable = try_path(name, proxy)
            if usable:
                return candidate
            if candidate["status"] is not None and candidate["status"] < 500 \
                    and best["status"] is None:
                best = candidate  # e.g. a real 404 — keep as best effort
            if retry == 0:
                time.sleep(1.0)

    return best


# ---------------------------------------------------------------- geo

CN_OFFLINE_PREFIXES = (
    "1.", "14.", "27.", "36.", "39.", "42.", "47.", "49.", "58.", "59.", "60.",
    "61.", "101.", "103.", "106.", "110.", "111.", "112.", "113.", "114.",
    "115.", "116.", "117.", "118.", "119.", "120.", "121.", "122.", "123.",
    "124.", "125.", "150.", "153.", "171.", "175.", "180.", "182.", "183.",
    "202.", "203.", "210.", "211.", "218.", "219.", "220.", "221.", "222.", "223.",
)
HKMO_TW_PROVINCES = ("香港", "澳门", "澳門", "台湾", "臺灣", "hong", "maca", "taiw", "taipei")


def _normalize_region(country=None, province=None):
    """-> (country_key, is_hmt).  country/province may be Chinese or English."""
    country = (country or "").strip()
    province = (province or "").strip()
    c = country.lower()
    is_cn = c in ("cn", "china", "中国", "中國")
    is_hmt = any(tag in province.lower() for tag in HKMO_TW_PROVINCES)
    return is_cn, is_hmt


def ip_geo(ip):
    """Geo lookup for one IP via ip-api.com (free, batch endpoint fallback).

    Returns (country, province) strings; ('', '') on failure.
    """
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "", ""
    if ip in _geo_cache:
        return _geo_cache[ip]
    result = ("", "")
    try:
        req = urllib.request.Request(
            "http://ip-api.com/json/" + ip + "?fields=country,regionName",
            headers={"User-Agent": UA},
        )
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        result = (data.get("country") or "", data.get("regionName") or "")
    except Exception:
        pass
    _geo_cache[ip] = result
    return result


def ip_geo_batch(ips):
    """Batch geo lookup (max 100). Returns {ip: (country, province)}."""
    mapping = {}
    todo = [ip for ip in ips if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip or "") and ip not in _geo_cache]
    for chunk_start in range(0, len(todo), 100):
        chunk = todo[chunk_start:chunk_start + 100]
        try:
            body = json.dumps(chunk).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=country,regionName,query",
                data=body, headers={"Content-Type": "application/json", "User-Agent": UA},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                for item in json.loads(resp.read().decode("utf-8", "replace")):
                    mapping[item.get("query")] = (item.get("country") or "", item.get("regionName") or "")
                    _geo_cache[item.get("query")] = mapping[item.get("query")]
        except Exception:
            pass
    for ip in ips:
        if ip not in mapping and ip in _geo_cache:
            mapping[ip] = _geo_cache[ip]
    return mapping


def is_china_ip(ip, country=None, province=None):
    """CN judgement.  API-provided country wins; HK/MO/TW count as NOT mainland.

    Returns (is_mainland_cn: bool, known: bool).
    """
    if country or province:
        is_cn, is_hmt = _normalize_region(country, province)
        if country:
            return (is_cn and not is_hmt), True
    if ip.startswith(("10.", "127.", "192.168.", "169.254.")) or ip.startswith("172."):
        return False, False
    if country is None and not ip:
        return False, False
    cn, _ = ip_geo(ip)
    if cn:
        is_cn, is_hmt = _normalize_region(cn, _geo_cache.get(ip, ("", ""))[1])
        return (is_cn and not is_hmt), True
    return (ip.startswith(CN_OFFLINE_PREFIXES), False)


def prefer_overseas(seed_ips, seed_country=None, seed_province=None):
    """Whether candidates should be ranked overseas-first (user rule #2)."""
    for ip in seed_ips or []:
        mainland, known = is_china_ip(ip, seed_country, seed_province)
        if known:
            return mainland
    if seed_country:
        is_cn, _ = _normalize_region(seed_country, seed_province)
        return is_cn
    return False


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://example.com/"
    result = fetch(target, timeout=8)
    text = result["body"][:400].decode("utf-8", "replace").replace("\n", " ")
    print(f"path={result['path']} status={result['status']} intercepted={result['intercepted']} note={result['note']}")
    print(f"final={result['final_url']} redirects={result['redirects']}")
    print(f"body[:400]={text}")
