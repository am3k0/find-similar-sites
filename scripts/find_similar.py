#!/usr/bin/env python3
"""find_similar.py — 快速查找同类站点（默认入口，一条命令出结果）。

用法:
    python scripts/find_similar.py 77x22.cc
    python scripts/find_similar.py http://target.example/ --all --budget 240

流程（找到即停，全程受 --budget 秒数约束）:
  1. 种子采集: 直连 -> 拦截识别 -> 规则代理(7897) -> 全局代理(7898) -> 浏览器渲染
     提取真实页面指纹 + HTTP/JS/meta 跳转链, 汇总种子资产集(全部环节的 IP 与 CNAME)
  2. 并行检索: Quake response:"标记" 内容检索 + Hunter web.body + Flint 同CNAME
  3. 候选过滤: 与种子资产集(含跳转链)同 IP/CNAME 的直接剔除 (用户规则 R1)
  4. 逐个验证: 真实页面抓取(必要时浏览器) + 内容比对 (R3) + 境外优先 (R2)
  5. 第一个合格候选 -> 打印结果退出; --all 才继续

本脚本不写任何文件（浏览器临时目录也会自动删除），结果只打印到 stdout。
"""
import argparse
import concurrent.futures as futures
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config  # noqa: E402
import net_utils  # noqa: E402
import quake_search  # noqa: E402
import hunter_search  # noqa: E402
from validate_candidate import validate, css_similarity, dom_similarity  # noqa: E402

UA = net_utils.UA
STOP_JS_WORDS = {
    # generic web APIs / keywords that appear on millions of pages
    "document", "window", "navigator", "location", "function", "prototype",
    "addEventListener", "getElementById", "querySelector", "querySelectorAll",
    "createElement", "setTimeout", "setInterval", "requestAnimationFrame",
    "innerHTML", "textContent", "userAgent", "length", "toString", "console",
    "localStorage", "sessionStorage", "getParameter", "getContext",
    "getExtension", "getChannelData", "toDataURL", "sendBeacon",
    "removeEventListener", "application", "javascript", "undefined",
    "callback", "options", "params", "request", "response", "storageenabled",
    "webgldebugrendererinfo", "webgl_debug_renderer_info",
    "unmasked_vendor_webgl", "unmasked_renderer_webgl", "experimental-webgl",
    "maxtouchpoints", "devicepixelratio", "hardwareconcurrency",
    "devicememory", "colordepth", "visibilitystate", "cookieenabled",
    "keepalive", "content-type", "application/json", "text/plain",
    "characterset", "charset", "encoding", "viewport", "stylesheet",
    "user-scalable", "maximum-scale", "initial-scale",
    "innerwidth", "innerheight", "screenwidth", "screenheight",
}


# ------------------------------------------------------------------ helpers

def log(msg, verbose=False):
    if verbose:
        print(f"  · {msg}", file=sys.stderr, flush=True)


def normalize_url(target):
    if "://" not in target:
        target = "http://" + target
    return target


def host_of(url):
    return (urllib.parse.urlparse(url).hostname or "").lower()


def registrable(host):
    return host[4:] if host.startswith("www.") else host


def page_fingerprint(html, url=None):
    """In-memory page fingerprint (no files)."""
    if not html:
        return None
    data = html.encode("utf-8", "replace") if isinstance(html, str) else html
    text = data.decode("utf-8", "replace")
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if m:
        title = re.sub(r"\s+", " ", m.group(1)).strip()
    css_classes = sorted({
        cls for match in re.findall(r'\bclass=["\']([^"\']+)', text, re.I)
        for cls in match.split()
    })
    dom_top = re.findall(r"<(\w+)", text)[:60]
    js_globals = sorted(set(re.findall(r"(?:var|let|const)\s+(\w+)\s*=", text)))[:40]
    return {
        "url": url,
        "title": title,
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "css_classes": css_classes,
        "dom_top": dom_top,
        "js_globals": js_globals,
    }


def _marker_score(ident, occurrences, in_script):
    """Heuristic rarity score for a pivot marker (higher = rarer)."""
    lower = ident.lower().strip("_")
    squashed = lower.replace("_", "")
    if lower in STOP_JS_WORDS or squashed in STOP_JS_WORDS:
        return 0
    if lower in ("var", "let", "const", "function", "return", "if", "for", "while", "new", "typeof"):
        return 0
    score = 1.0
    if ident.startswith("__") and ident.endswith("__"):
        score += 8                      # dunder keys are almost always custom
    elif "_" in ident.strip("_"):
        score += 3                      # snake_case inside JS is often custom
    if any(ch.isdigit() for ch in ident):
        score += 2
    if len(ident) >= 14:
        score += 2
    elif len(ident) <= 8:
        score -= 2
    if occurrences == 1:
        score += 1                      # appears once -> likely a literal key
    if not in_script:
        score -= 1
    return score


def extract_markers(html, limit=4):
    """Rare, query-friendly strings for engine pivots (Quake response: / Hunter web.body)."""
    text = html or ""
    if not text:
        return []
    scripts = " ".join(re.findall(r"<script[^>]*>(.*?)</script>", text, re.I | re.S))
    counter = {}

    def bump(value, in_script):
        value = value.strip()
        if not value or any(ch.isspace() for ch in value):
            return
        entry = counter.setdefault(value, {"n": 0, "s": False})
        entry["n"] += 1
        entry["s"] = entry["s"] or in_script

    # hashed asset names:  app.2370c4bd.js / chunk-vendors.19e904fa.css
    hashed = re.compile(r"[A-Za-z0-9_.\-]{3,40}\.[0-9a-f]{6,10}\.(?:js|css|png|woff2?)")
    for name in hashed.findall(text):
        counter.setdefault(name, {"n": 1, "s": False, "bonus": 9})

    # identifiers inside script blocks
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]{5,45}", scripts):
        bump(ident, True)

    # custom-looking string literals (quote chars via chr to avoid escaping mess)
    q = chr(39) + chr(34)
    literal_re = "[" + q + "]([A-Za-z0-9_\-/.]{10,60})[" + q + "]"
    for literal in re.findall(literal_re, scripts):
        if not re.match(r"^(?:https?:)?//", literal):
            counter.setdefault(literal, {"n": 1, "s": True, "bonus": 3})

    scored = []
    for value, entry in counter.items():
        bonus = entry.get("bonus")
        if bonus:
            score = bonus + entry["n"]
        else:
            score = _marker_score(value, entry["n"], entry["s"])
        if score >= 4:
            scored.append((value, score))
    scored.sort(key=lambda kv: (-kv[1], kv[0]))

    markers = []
    for value, _score in scored:
        if value not in markers:
            markers.append(value)
        stripped = value.strip("_")
        if stripped != value and len(stripped) >= 5 and stripped not in markers:
            markers.append(stripped)    # keep the bare form too (zr_probe)
        if len(markers) >= limit * 2:    # headroom for over-broad pivots
            break
    return markers[:limit * 2]


def extract_redirect_targets(html):
    """JS redirect targets + meta refresh URLs from a page."""
    targets = []
    for value in re.findall(r'(?:target|url)\s*=\s*["\'](https?://[^"\']+)', html or ""):
        targets.append(value)
    for value in re.findall(r'http-equiv=["\']refresh["\'][^>]*url=([^"\'>\s]+)', html or "", re.I):
        targets.append(value)
    for value in re.findall(r'location\.(?:href|replace)\(\s*["\'](https?://[^"\']+)', html or ""):
        targets.append(value)
    return targets


def query_cname(host, timeout=3):
    """Best-effort CNAME lookup via nslookup (Windows & Linux compatible-ish)."""
    try:
        proc = subprocess.run(
            ["nslookup", "-type=cname", host], capture_output=True, timeout=timeout,
            stdin=subprocess.DEVNULL)
        out = proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")
        for pattern in (r"canonical name\s*=\s*(\S+)", r"\bCNAME\s+(\S+)"):
            m = re.findall(pattern, out, re.I)
            if m:
                return m[-1].rstrip(".").lower()
    except Exception:
        pass
    return None


def favicon_fingerprint(host, scheme="http"):
    """Fetch /favicon.ico through the fallback chain; return sha256 or None."""
    result = net_utils.fetch(f"{scheme}://{host}/favicon.ico", timeout=6, max_bytes=200_000)
    body = result.get("body") or b""
    if result.get("status") == 200 and len(body) > 100:
        return hashlib.sha256(body).hexdigest()
    return None


# ------------------------------------------------------------------ seed

def collect_seed(url, verbose=False):
    """Fetch the seed through the fallback chain, build fingerprint + assets."""
    seed = {"url": url, "host": host_of(url), "asset_hosts": set(), "asset_ips": set(),
            "asset_cnames": set(), "fp": None, "rendered": None, "fetch_path": "none"}

    result = net_utils.fetch(url, timeout=12)
    body = result.get("body") or b""
    text = body.decode("utf-8", "replace")
    seed["fetch_path"] = result["path"]
    seed["fetch_status"] = result.get("status")
    seed["intercepted"] = result["intercepted"]
    seed["http_redirects"] = result.get("redirects") or []

    needs_browser = (
        result["intercepted"]
        or not body
        or (len(body) < 700 and re.search(r"<script", text, re.I))
    )
    if needs_browser:
        import browser_fetch
        proxy_mode = "auto"
        probe = browser_fetch.pick_proxy("auto", url)
        rendered = browser_fetch.render(url, proxy=probe, timeout=30)
        if rendered.get("dom"):
            seed["rendered"] = rendered["dom"]
            seed["fetch_path"] = f"browser({rendered.get('proxy')})"
            text = rendered["dom"]
            body = rendered["dom"].encode("utf-8", "replace")

    seed["fp"] = page_fingerprint(text, url)
    seed["markers"] = extract_markers(text)
    if seed["fp"]:
        seed["fp"]["markers"] = seed["markers"][:4]
    seed["js_targets"] = extract_redirect_targets(text)

    # Asset hosts: seed + HTTP redirect hops + JS/meta redirect targets.
    hosts = {seed["host"]}
    for location in seed["http_redirects"]:
        h = host_of(location)
        if h:
            hosts.add(h)
    for target in seed["js_targets"]:
        h = host_of(target)
        if h and not re.match(r"^\d+\.\d+\.\d+\.\d+$", h):
            hosts.add(h)
    seed["asset_hosts"] = hosts

    for h in hosts:
        for ip in net_utils.resolve(h):
            if ip not in net_utils.POISONED_DNS:
                seed["asset_ips"].add(ip)
        cname = query_cname(h)
        if cname:
            seed["asset_cnames"].add(cname)

    # Historical IPs from Flint DNS (if configured) make R1 stricter/safer.
    try:
        if config.get_flint_creds()[0]:
            import dns_history
            records = dns_history.query_dns_history(seed["host"])
            for r in records or []:
                if r.get("rrtype") == "A":
                    seed["asset_ips"].add(r["rdata"])
                if r.get("rrtype") == "CNAME":
                    seed["asset_cnames"].add(r["rdata"].lower().rstrip("."))
    except Exception as error:
        log(f"flint dns_history skipped: {error!r}", verbose)

    seed_ips = sorted(seed["asset_ips"])
    seed["geo"] = net_utils.ip_geo_batch(seed_ips[:20]) if seed_ips else {}
    seed["prefer_overseas"] = net_utils.prefer_overseas(seed_ips)
    seed["favicon_sha256"] = favicon_fingerprint(seed["host"]) if seed["fp"] else None
    if seed["fp"] and seed["favicon_sha256"]:
        seed["fp"]["favicon_sha256"] = seed["favicon_sha256"]
    return seed


# ------------------------------------------------------------------ discovery

def discover_candidates(seed, deadline, verbose=False):
    """Parallel pivot queries. Returns {registrable_host: candidate_dict}."""
    candidates = {}

    def add(host, source, hint=None):
        if not host:
            return
        host = host.lower().strip().rstrip(".")
        if not host or host == seed["host"]:
            return
        key = registrable(host)
        entry = candidates.setdefault(key, {
            "host": host, "sources": [], "hints": [], "content_pivot": False,
            "infra_evidence": None,
        })
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if hint:
            entry["hints"].append(hint)

    markers = seed.get("markers") or []
    title = (seed.get("fp") or {}).get("title") or ""
    quake_ready = bool(config.get_quake_token())

    def run_quake():
        # Exclude the seed's own IPs (incl. redirect chain) server-side so
        # candidates violating user rule R1 never enter the pool.
        not_ips = ""
        seed_ips = sorted(seed.get("asset_ips") or [])[:6]
        if seed_ips:
            not_ips = " AND NOT (" + " OR ".join(f'ip:"{ip}"' for ip in seed_ips) + ")"
        queries = []
        if markers:
            queries.append(("marker", f'response:"{markers[0]}"' + not_ips))
            if len(markers) > 1:
                queries.append(("marker2", f'response:"{markers[1]}"' + not_ips))
        if title:
            queries.append(("title", f'title:"{title}"'))
        for kind, query in queries:
            if time.time() > deadline:
                return
            result = quake_search.search(query, size=100)
            total = result.get("total") or 0
            log(f"quake {kind} total={total}", verbose)
            if 0 < total <= 5000:
                for row in result.get("results") or []:
                    host = row.get("domain") or row.get("hostname") or ""
                    add(host, "quake:" + kind, {
                        "ip": row.get("ip"), "title": row.get("title"),
                        "country": row.get("country"), "province": row.get("province"),
                    })
                    if kind in ("marker", "marker2") and host:
                        entry = candidates.get(registrable(host))
                        if entry:
                            entry["content_pivot"] = True
                return  # precise pivot found, stop burning quota
            if total == 0:
                continue  # try the next marker

    def run_hunter():
        queries = []
        if markers:
            queries.append(("marker", f'web.body="{markers[0]}"'))
            if len(markers) > 1:
                queries.append(("marker2", f'web.body="{markers[1]}"'))
        if title:
            queries.append(("title", f'web.title="{title}"'))
        for kind, query in queries:
            if time.time() > deadline:
                return
            result = hunter_search.search(query, page_size=20, is_web=3)
            total = result.get("total") or 0
            log(f"hunter {kind} total={total}", verbose)
            if 0 < total <= 5000:
                for row in result.get("results") or []:
                    h = row.get("domain") or host_of(row.get("url") or "")
                    add(h, "hunter:" + kind, {
                        "ip": row.get("ip"), "title": row.get("web_title"),
                        "country": row.get("country"), "province": row.get("province"),
                    })
                    if kind in ("marker", "marker2") and h:
                        entry = candidates.get(registrable(h))
                        if entry:
                            entry["content_pivot"] = True
                return
            if total == 0:
                continue

    def run_flint():
        try:
            user, _ = config.get_flint_creds()
            if not user:
                return
            from flint_auth import post_json
            payload = post_json("/api/v1/flint_cms/query", {"hosts": [seed["host"]]})
            data = (payload.get("data") or {}).get("hosts", {}).get(seed["host"]) or {}
            summary = data.get("master_summary") or {}
            for cname in (summary.get("CDN") or "").replace(",", " ").split():
                seed["asset_cnames"].add(cname.lower().rstrip("."))
            for item in data.get("CDN_cms") or []:
                add(item.get("host"), "flint:cdn", {"cname": item.get("CDN"), "cms": item.get("cms_value")})
                entry = candidates.get(registrable(item.get("host") or ""))
                if entry:
                    entry["infra_evidence"] = f"共享分发CNAME {item.get('CDN')}"
            for item in data.get("IP_cms") or []:
                add(item.get("host"), "flint:ip", {"ip": item.get("IP"), "cms": item.get("cms_value")})
        except Exception as error:
            log(f"flint skipped: {error!r}", verbose)

    with futures.ThreadPoolExecutor(max_workers=3) as pool:
        jobs = []
        if quake_ready:
            jobs.append(pool.submit(run_quake))
        jobs.append(pool.submit(run_hunter))
        jobs.append(pool.submit(run_flint))
        for job in jobs:
            job.result()
    return candidates


# ------------------------------------------------------------------ verify

def resolve_candidate(entry):
    ips = [ip for ip in net_utils.resolve(entry["host"]) if ip not in net_utils.POISONED_DNS]
    entry["ips"] = ips
    entry["ip_source"] = "dns"
    hint = next((h for h in entry.get("hints", []) if h.get("ip")), {})
    if not ips and hint.get("ip") and hint["ip"] not in net_utils.POISONED_DNS:
        # local DNS failed/poisoned — trust the search engine's IP
        entry["ips"] = [hint["ip"]]
        entry["ip_source"] = "engine"
    entry["cnames"] = {c for c in [query_cname(entry["host"])] if c}
    entry["hint_ip"] = hint.get("ip")
    entry["country"] = hint.get("country")
    entry["province"] = hint.get("province")
    entry["hint_title"] = hint.get("title")
    return entry


def score_candidate(seed, entry):
    score = 0
    if entry.get("content_pivot"):
        score += 4
    if entry.get("infra_evidence"):
        score += 3
    title = (seed.get("fp") or {}).get("title")
    if title and entry.get("hint_title") and title == entry["hint_title"]:
        score += 1.5
    if "flint:ip" in entry.get("sources", []):
        score += 0.5
    return score


def verify_candidate(seed, entry, use_browser="auto", verbose=False):
    """Fetch the candidate's real page and run the full validation."""
    url = f"http://{entry['host']}/"
    result = net_utils.fetch(url, timeout=12)
    body = result.get("body") or b""
    text = body.decode("utf-8", "replace")
    path = result["path"]

    if (result["intercepted"] or not body or (len(body) < 700 and re.search(r"<script", text, re.I))):
        if use_browser != "off":
            import browser_fetch
            proxy = browser_fetch.pick_proxy("auto", url)
            rendered = browser_fetch.render(url, proxy=proxy, timeout=28)
            if rendered.get("dom"):
                text = rendered["dom"]
                body = text.encode("utf-8", "replace")
                path = f"browser({rendered.get('proxy')})"

    fp = page_fingerprint(text, url)
    if fp:
        fp["marker_hits"] = {m: text.count(m) for m in (seed.get("markers") or [])[:4] if text.count(m)}
    entry["fp"] = fp
    entry["fetch_path"] = path
    entry["favicon_sha256"] = favicon_fingerprint(entry["host"]) if fp else None
    if fp and entry["favicon_sha256"]:
        fp["favicon_sha256"] = entry["favicon_sha256"]
    return validate(seed, entry)


# ------------------------------------------------------------------ main

def main():
    parser = argparse.ArgumentParser(description="快速查找同类站点（结果直接打印，不生成文件）")
    parser.add_argument("target", help="URL 或域名")
    parser.add_argument("--all", action="store_true", help="列出全部合格候选而非找到即停")
    parser.add_argument("--budget", type=float, default=240, help="总时间预算（秒），默认 240")
    parser.add_argument("--browser", default="auto", choices=["auto", "off"])
    parser.add_argument("--max-verify", type=int, default=8)
    parser.add_argument("--max-resolve", type=int, default=24,
                        help="只对得分前 N 的候选做 DNS/CNAME 解析（省时间）")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    started = time.time()
    deadline = started + args.budget
    url = normalize_url(args.target)

    print(f"◎ 种子: {url}", flush=True)
    seed = collect_seed(url, verbose=args.verbose)
    fp = seed.get("fp") or {}
    print(f"  采集: {seed['fetch_path']} status={seed.get('fetch_status')} "
          f"标题={fp.get('title', '')[:30]!r} 拦截={bool(seed.get('intercepted'))}", flush=True)
    print(f"  标记: {', '.join(seed.get('markers') or [])[:100] or '（无）'}", flush=True)
    print(f"  种子资产: {len(seed['asset_ips'])} IP / {len(seed['asset_cnames'])} CNAME "
          f"/ 跳转链 {sorted(seed['asset_hosts'])}", flush=True)
    if seed.get("prefer_overseas"):
        print("  规则R2: 种子为国内IP → 候选优先境外(含港澳台)", flush=True)

    discovery_deadline = min(deadline, started + args.budget * 0.45)
    candidates = discover_candidates(seed, discovery_deadline, verbose=args.verbose)
    print(f"◎ 检索: {len(candidates)} 个候选域名", flush=True)
    if not candidates:
        print("❌ 未找到候选。可尝试 --budget 300 重试或检查凭据（init.py --validate）。")
        return 1

    # Resolve + R1 filter + score, in batches of max_resolve.  When the
    # highest-scoring batch turns out to live on the seed's own IP pool
    # (common for fast-flux operators), keep draining the next batch until
    # independent candidates appear.
    entries = list(candidates.values())
    hint_order = sorted(entries, key=lambda e: -score_candidate(seed, e))

    rejected = []
    qualified_pool = []
    resolved_total = 0
    with futures.ThreadPoolExecutor(max_workers=8) as pool:
        while resolved_total < len(hint_order) and len(qualified_pool) < args.max_verify:
            if time.time() > deadline:
                print("⏱ 达到时间预算，提前结束解析。", flush=True)
                break
            batch = hint_order[resolved_total:resolved_total + args.max_resolve]
            resolved_total += len(batch)
            list(pool.map(resolve_candidate, batch))
            for entry in batch:
                overlap_ip = set(entry.get("ips") or []) & set(seed["asset_ips"])
                overlap_cname = set(entry.get("cnames") or []) & set(seed["asset_cnames"])
                if overlap_ip or overlap_cname:
                    rejected.append((entry["host"], f"共享{'IP' if overlap_ip else 'CNAME'}: "
                                    f"{','.join(sorted(overlap_ip or overlap_cname))}"))
                    continue
                if not entry.get("ips"):
                    continue  # dead domain
                entry["_score"] = score_candidate(seed, entry)
                qualified_pool.append(entry)

    qualified_pool.sort(key=lambda e: -e["_score"])
    print(f"◎ 过滤: 已解析 {resolved_total} 个，{len(qualified_pool)} 个通过R1(IP/CNAME独立)，"
          f"{len(rejected)} 个因同IP/CNAME剔除", flush=True)
    if args.verbose and rejected:
        for host, why in rejected[:6]:
            log(f"剔除 {host}: {why}", True)

    if not qualified_pool:
        print("❌ 候选全部与种子同IP/CNAME，无合格同类站点。")
        return 1

    # Verify in batches, first hit wins
    passed_list = []
    near_misses = []
    to_verify = qualified_pool[:args.max_verify]
    print(f"◎ 验证: 依次核验前 {len(to_verify)} 个候选（真实页面比对）", flush=True)
    for batch_start in range(0, len(to_verify), 4):
        if time.time() > deadline:
            print("⏱ 达到时间预算，提前结束验证。", flush=True)
            break
        batch = to_verify[batch_start:batch_start + 4]
        with futures.ThreadPoolExecutor(max_workers=len(batch)) as pool:
            results = list(pool.map(lambda e: (e, verify_candidate(seed, e, args.browser, args.verbose)), batch))
        for entry, verdict in results:
            where = "/".join(x for x in (entry.get("country"), entry.get("province")) if x) or ""
            geo = net_utils.ip_geo_batch(entry.get("ips") or [])
            seen_where = []
            for ip, (c, p) in list(geo.items())[:2]:
                label = f"{c}/{p}" if c else ip
                if label not in seen_where:
                    seen_where.append(label)
            where = "、".join(seen_where) or where
            mark = ""
            if seed.get("prefer_overseas"):
                mainland = False
                for ip in entry.get("ips") or []:
                    is_cn, _ = net_utils.is_china_ip(ip)
                    mainland = mainland or is_cn
                mark = "" if not mainland else " [国内IP]"
            if verdict["passed"]:
                passed_list.append((entry, verdict, where, mark))
                if not args.all:
                    entry_idx = passed_list[-1]
                    print_result(seed, *entry_idx)
                    return 0
            else:
                near_misses.append((entry, verdict, where))

    if passed_list:
        print(f"◎ 共 {len(passed_list)} 个合格同类站点:", flush=True)
        for entry, verdict, where, mark in passed_list:
            print_result(seed, entry, verdict, where, mark, prefix="  -")
        return 0

    print("❌ 未找到完全合格的同类站点。最接近的候选:", flush=True)
    for entry, verdict, where in near_misses[:5]:
        top = "; ".join(verdict["reasons"][:3])
        print(f"  - {entry['host']} ({where}) — {verdict['level']}: {top}", flush=True)
    return 1


def print_result(seed, entry, verdict, where, mark="", prefix=""):
    lines = [
        f"{prefix}✅ 同类站点: http://{entry['host']}{mark}",
        f"{prefix}   IP: {', '.join(entry.get('ips') or [])} ({where or '未知归属'}) | 采集: {entry.get('fetch_path')}",
        f"{prefix}   证据: {'; '.join(r for r in verdict['reasons'] if r.startswith('R3')) or '基础设施关联'}",
        f"{prefix}   合规: IP/CNAME 与种子及跳转链无交集 | 级别: {verdict['level']} | 分数 {verdict['score']}",
    ]
    print("\n".join(lines), flush=True)


if __name__ == "__main__":
    sys.exit(main())
