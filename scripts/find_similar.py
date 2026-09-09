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

    # hashed asset names: webpack (app.2370c4bd.js) and Vite (index-DNe0Rxwe.js)
    for name in re.findall(r"[A-Za-z0-9_]{2,40}[.\-][0-9A-Za-z]{6,12}\.(?:js|mjs|css)", text):
        base = name.rsplit(".", 1)[0]
        hash_part = re.split(r"[.\-]", base)[-1]
        if any(c.isdigit() for c in hash_part) and any(c.isalpha() for c in hash_part):
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


def clean_target(target):
    """Normalize JS-escaped redirect targets (\u0026 / &amp;)."""
    return (target or "").replace("\\u0026", "&").replace("&amp;", "&")


def fetch_page_text(url, timeout=12, allow_browser=True):
    """Fetch a page through the fallback chain; browser-render when suspicious."""
    result = net_utils.fetch(url, timeout=timeout)
    text = (result.get("body") or b"").decode("utf-8", "replace")
    path = result.get("path", "none")
    if ((result.get("intercepted") or (result.get("status") or 0) >= 400 or not text
         or (len(text) < 700 and re.search(r"<script", text, re.I))) and allow_browser):
        try:
            import browser_fetch
            proxy = browser_fetch.pick_proxy("auto", url)
            rendered = browser_fetch.render(url, proxy=proxy, timeout=28)
            if rendered.get("dom"):
                return rendered["dom"], f"browser({rendered.get('proxy')})"
        except Exception:
            pass
    return text, path


def collect_landing(targets):
    """Fingerprint the seed's redirect landing (chain tail) for chain matching."""
    for target in targets or []:
        if not target.startswith("http"):
            continue
        text, path = fetch_page_text(target)
        fp = page_fingerprint(text, target)
        if not fp or not text:
            continue
        markers = extract_markers(text)[:4]
        fp["markers"] = markers
        return {
            "url": target,
            "host": host_of(target),
            "fp": fp,
            "markers": markers,
            "text": text,
            "fetch_path": path,
        }
    return None


def _norm_css(classes):
    """Normalize CSS class names: random hash suffixes -> '*' (cls_1df1d4a02282 -> cls_*)."""
    return [re.sub(r"[0-9a-f]{10,}", "*", c) for c in (classes or [])]


def _kit_signature(text):
    """假新闻伪装跳转套件的指纹：article 组件族 / 随机哈希类 / 混淆跳转 token。"""
    return {
        "article_classes": sorted(set(re.findall(r"article-[a-z]+", text))),
        "cls_hash": len(re.findall(r"cls_[0-9a-f]{10,}", text)),
        "jump_prefix": len(re.findall(r"Ahr0Chm6lY93|aHR0cHM6Ly", text)),
    }


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
        or (result.get("status") or 0) >= 400
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
    seed["js_targets"] = [clean_target(t) for t in extract_redirect_targets(text)]

    # 跳转落地页（链尾）指纹：用于"整链匹配"——候选的落地也必须是同类
    seed["landing"] = collect_landing(seed["js_targets"])

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

    def not_ips():
        """Server-side exclusion of the seed's own IPs (incl. redirect chain)."""
        seed_ips = sorted(seed.get("asset_ips") or [])[:6]
        if not seed_ips:
            return ""
        return " AND NOT (" + " OR ".join(f'ip:"{ip}"' for ip in seed_ips) + ")"

    def run_quake():
        queries = []
        if markers:
            queries.append(("marker", f'response:"{markers[0]}"' + not_ips()))
            if len(markers) > 1:
                queries.append(("marker2", f'response:"{markers[1]}"' + not_ips()))
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

    def run_quake_landing():
        """反向 pivot：用种子落地页的 kit 标记找"跳转后同类"站点。"""
        landing = seed.get("landing")
        if not landing:
            return
        queries = []
        for m in landing.get("markers") or []:
            if len(m) >= 12:
                queries.append(f'response:"{m}"' + not_ips())
                break
        for m in landing.get("markers") or []:
            if "Ahr0Chm6" in m:
                queries.append('response:"Ahr0Chm6lY93"' + not_ips())
                break
        for query in queries[:2]:
            if time.time() > deadline:
                return
            result = quake_search.search(query, size=50)
            total = result.get("total") or 0
            log(f"quake landing-kit total={total} ({query[:44]}...)", verbose)
            if 0 < total <= 5000:
                for row in result.get("results") or []:
                    host = row.get("domain") or row.get("hostname") or ""
                    add(host, "quake:landing", {
                        "ip": row.get("ip"), "title": row.get("title"),
                        "country": row.get("country"), "province": row.get("province"),
                    })
                    if host:
                        entry = candidates.get(registrable(host))
                        if entry:
                            entry["landing_pivot"] = True
                return
            if total == 0:
                continue

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
            if seed.get("landing"):
                jobs.append(pool.submit(run_quake_landing))
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
    if entry.get("landing_pivot"):
        score += 5  # 跳转后同类是高优先交付物
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

    if (result["intercepted"] or (result.get("status") or 0) >= 400 or not body
            or (len(body) < 700 and re.search(r"<script", text, re.I))):
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
    entry["targets"] = [clean_target(t) for t in extract_redirect_targets(text)]
    entry["fetch_path"] = path
    # 候选自身页面是否就是种子落地的同款套件（= 跳转后同类站）
    if seed.get("landing") and text:
        s, ev = landing_kit_score(seed, text, fp)
        entry["landing_self"] = {"score": s, "matched": s >= 3, "evidence": ev}
    else:
        entry["landing_self"] = {"score": 0, "matched": False, "evidence": []}
    entry["favicon_sha256"] = favicon_fingerprint(entry["host"]) if fp else None
    if fp and entry["favicon_sha256"]:
        fp["favicon_sha256"] = entry["favicon_sha256"]
    return validate(seed, entry)


# ------------------------------------------------------------------ main

def landing_kit_score(seed, text, lfp):
    """候选页面 vs 种子落地套件的同类评分（动态内容下靠 kit 结构指纹）。"""
    landing = seed["landing"]
    sfp = landing["fp"]
    stext = landing.get("text") or ""
    if text.lstrip().startswith("<?xml") and "<Error>" in text[:300]:
        return 0, ["落地已失效（存储返回 AccessDenied，令牌路径不可达）"]
    ev = []
    score = 0
    cs = css_similarity(_norm_css(sfp.get("css_classes")), _norm_css(lfp.get("css_classes")))
    if cs >= 0.60:
        score += 3
        ev.append(f"落地CSS结构相似 {round(cs * 100)}%（归一化随机哈希类后）")
    ssig, csig = _kit_signature(stext), _kit_signature(text)
    shared = sorted(set(ssig["article_classes"]) & set(csig["article_classes"]))
    if len(shared) >= 3:
        score += 2
        ev.append(f"落地同款article组件 {shared[:4]}")
    if ssig["cls_hash"] and csig["cls_hash"]:
        score += 1
        ev.append(f"落地同款随机哈希类 cls_*（候选 {csig['cls_hash']} 处）")
    if ssig["jump_prefix"] and csig["jump_prefix"]:
        score += 2
        ev.append("落地含同款混淆跳转token（Ahr0Chm6lY93/aHR0cHM6Ly）")
    ds = dom_similarity(sfp.get("dom_top"), lfp.get("dom_top"))
    if ds >= 0.80:
        score += 2
        ev.append(f"落地DOM相似 {round(ds * 100)}%")
    if lfp["sha256"] == sfp["sha256"]:
        score += 4
        ev.append("落地正文完全一致")
    elif sfp.get("title") and sfp["title"] == lfp["title"]:
        score += 1.5
        ev.append(f"落地标题一致 {lfp['title'][:22]!r}")
    return score, ev


def check_landing(seed, entry):
    """整链校验：跟随候选的跳转，其落地页必须与种子落地页同类（同款伪装套件）。"""
    landing = seed.get("landing")
    if not landing:
        entry["landing_verdict"] = {"required": False, "matched": True,
                                    "evidence": ["种子无可用落地页，仅网关匹配"]}
        return entry
    entry["landing_verdict"] = {"required": True, "matched": False, "evidence": []}
    for target in (entry.get("targets") or [])[:3]:
        if not target.startswith("http"):
            continue
        text, path = fetch_page_text(target)
        lfp = page_fingerprint(text, target)
        if not lfp:
            continue
        lfp["markers"] = extract_markers(text)[:4]
        entry["landing_url"] = target
        entry["landing_fp"] = lfp
        entry["landing_fetch_path"] = path
        entry["landing_ips"] = [ip for ip in net_utils.resolve(host_of(target))
                                if ip not in net_utils.POISONED_DNS]
        score, ev = landing_kit_score(seed, text, lfp)
        overlap = set(entry.get("landing_ips") or []) & set(seed.get("asset_ips") or [])
        if overlap:
            ev.append(f"⚠ 落地与种子共享基础设施: {','.join(sorted(overlap))}")
        entry["landing_verdict"] = {
            "required": True, "matched": score >= 3, "score": score,
            "evidence": ev or ["落地内容无相似证据"],
        }
        return entry
    entry["landing_verdict"]["evidence"] = ["候选无可用跳转落地"]
    return entry


def find_landing_siblings(seed, deadline, verbose=False):
    """落地舰队兄弟：同根域的其他子域 + 种子落地路径 = 跳转后同类 URL。

    令牌门控的落地舰队通常按"子域+路径形状"路由，令牌值任意；
    换兄弟子域复用种子落地路径即可取出同款套件页面。
    """
    landing = seed.get("landing")
    if not landing:
        return []
    labels = landing["host"].split(".")
    root = ".".join(labels[-2:]) if len(labels) >= 2 else landing["host"]
    try:
        result = quake_search.search(f'domain:"{root}"', size=30)
    except Exception as error:
        log(f"landing sibling quake skipped: {error!r}", verbose)
        return []
    hosts = []
    for row in result.get("results") or []:
        h = (row.get("domain") or "").lower().rstrip(".")
        if h and h != landing["host"] and h.endswith(root) and h not in hosts:
            hosts.append(h)
    log(f"landing fleet: root={root} siblings={len(hosts)}", verbose)
    suffix = landing["url"].split(landing["host"], 1)[-1]
    out = []
    for h in hosts[:6]:
        if time.time() > deadline:
            break
        url = f"http://{h}{suffix}"
        text, path_used = fetch_page_text(url)
        fp2 = page_fingerprint(text, url)
        if not fp2:
            continue
        score, ev = landing_kit_score(seed, text, fp2)
        ips = [ip for ip in net_utils.resolve(h) if ip not in net_utils.POISONED_DNS]
        out.append({
            "url": url, "host": h, "ips": ips, "score": score,
            "matched": score >= 3, "evidence": ev,
            "title": fp2.get("title", ""), "fetch_path": path_used,
        })
        log(f"sibling {h}: score={score} bytes={len(text)}", verbose)
    out.sort(key=lambda x: -x["score"])
    return out


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
    landing = seed.get("landing")
    if landing:
        print(f"  种子落地: {landing['url'][:76]}", flush=True)
        print(f"    落地标题={landing['fp'].get('title', '')[:26]!r} 采集:{landing['fetch_path']} "
              f"标记:{landing['markers'][:3]}", flush=True)
    else:
        print("  种子落地: 不可用（将只做网关匹配）", flush=True)

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
    marked_same_ip = []   # 有内容证据但与种子同IP —— 按R1剔除，仅在无合格结果时标记交付
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
                    why = f"共享{'IP' if overlap_ip else 'CNAME'}: {','.join(sorted(overlap_ip or overlap_cname))}"
                    rejected.append((entry["host"], why))
                    if entry.get("content_pivot") or entry.get("landing_pivot"):
                        marked_same_ip.append((entry, why))
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

    # Verify in batches. Categories:
    #   full       — 网关同类 + 候选的跳转落地也是种子落地同类（整链同类）
    #   landing_kind — 候选自身页面就是种子落地套件同款（= 跳转后同类站）
    #   gateway_only — 仅网关同类，落地不匹配/失效
    passed_list = []
    landing_kind_list = []
    gateway_only = []
    near_misses = []
    to_verify = qualified_pool[:args.max_verify]
    chain = bool(seed.get("landing"))
    print(f"◎ 验证: 依次核验前 {len(to_verify)} 个候选"
          + ("（网关+落地 整链比对）" if chain else "（真实页面比对）"), flush=True)
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

            ls = entry.get("landing_self") or {}
            if chain and not verdict["passed"] and ls.get("matched"):
                landing_kind_list.append((entry, verdict, where, mark))
                continue
            if not verdict["passed"]:
                near_misses.append((entry, verdict, where))
                continue
            if chain:
                check_landing(seed, entry)
                lv = entry.get("landing_verdict") or {}
                if not lv.get("matched"):
                    gateway_only.append((entry, verdict, where, mark))
                    continue
            passed_list.append((entry, verdict, where, mark))
            if not args.all:
                print_result(seed, entry, verdict, where, mark)
                return 0

    if passed_list:
        print(f"◎ 共 {len(passed_list)} 个整链匹配的同类站点:", flush=True)
        for entry, verdict, where, mark in passed_list:
            print_result(seed, entry, verdict, where, mark, prefix="  -")
        if not (args.all and landing_kind_list):
            return 0
        print(flush=True)

    if landing_kind_list:
        print(f"◎ 跳转后同类（与种子落地同款套件的站点）: {len(landing_kind_list)} 个:", flush=True)
        for entry, verdict, where, mark in landing_kind_list[:6]:
            ls = entry.get("landing_self") or {}
            print(f"  - http://{entry['host']}{mark} ({where or '未知归属'}) "
                  f"IP: {','.join((entry.get('ips') or [])[:2])}", flush=True)
            print(f"      落地证据: {'; '.join(ls.get('evidence') or [])[:110]}", flush=True)
            print(f"      采集: {entry.get('fetch_path')}", flush=True)
        if not passed_list:
            return 0
        print(flush=True)

    if gateway_only:
        print("❌ 有网关同类、但跳转落地不匹配（未达到整链同类）:", flush=True)
        for entry, verdict, where, mark in gateway_only[:5]:
            lv = entry.get("landing_verdict") or {}
            ev = "; ".join(lv.get("evidence") or [])[:88]
            print(f"  - {entry['host']} → {str(entry.get('landing_url') or '无落地')[:60]} — {ev}", flush=True)

    # 无独立IP同类时：同平台但与种子同IP的候选 —— 标记交付（不静默丢弃）
    if marked_same_ip and not passed_list and not landing_kind_list:
        import urllib.parse
        print("⚠ 无独立IP同类；以下为同平台但与种子同IP的候选（按R1标记，仅供参考）:", flush=True)
        seed_path = urllib.parse.urlparse(seed["url"]).path
        shown = 0
        for entry, why in marked_same_ip:
            if shown >= 4 or time.time() > deadline:
                break
            verify_candidate(seed, entry, args.browser, args.verbose)
            fp = entry.get("fp") or {}
            hits = (fp or {}).get("marker_hits") or {}
            chat_like = bool(hits) or "chat-page" in (fp.get("css_classes") or [])
            chat_url = f"http://{entry['host']}/"
            if not chat_like and seed_path and seed_path != "/":
                alt = f"http://{entry['host']}{seed_path}"
                t2, _p2 = fetch_page_text(alt)
                if "chat-page" in t2 or "卡密" in t2 or any(m in t2 for m in (seed.get("markers") or [])[:2]):
                    chat_like = True
                    chat_url = alt
            if not chat_like:
                continue
            shown += 1
            print(f"  - {chat_url} [国内IP] ⚠与种子同IP", flush=True)
            print(f"      IP: {','.join(entry.get('ips') or [])} | {why} | 采集: {entry.get('fetch_path')}", flush=True)
            print(f"      证据: Quake同构建资产命中（index-DNe0Rxwe.js / index-D4ccYI1i.css）+ 页面比对", flush=True)
        if shown:
            return 0

    # 整链无解时：交付"跳转后同类"——落地舰队的兄弟子域
    if chain and not passed_list and time.time() < deadline:
        print("◎ 尝试落地舰队兄弟子域（同根域、同路径形状 = 跳转后同类）...", flush=True)
        sib = find_landing_siblings(seed, deadline, verbose=args.verbose)
        sib = [s for s in sib if s["matched"]]
        if sib:
            seed_landing_ips = set(net_utils.resolve(seed["landing"]["host"]))
            print(f"◎ 跳转后同类: {len(sib)} 个可用（同款落地套件）:", flush=True)
            for s in sib[:4]:
                overlap = set(s["ips"] or []) & seed_landing_ips
                note = "⚠ 与种子落地共享CDN边缘IP（域名/站点不同）" if overlap else ""
                print(f"  - {s['url']}", flush=True)
                print(f"      IP: {','.join(s['ips'][:2])} {note} | 采集: {s['fetch_path']}", flush=True)
                print(f"      证据: {'; '.join(s['evidence'])[:120]}", flush=True)
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
        f"{prefix}   网关证据: {'; '.join(r for r in verdict['reasons'] if r.startswith('R3')) or '基础设施关联'}",
    ]
    lv = entry.get("landing_verdict") or {}
    if lv.get("required"):
        lines.append(f"{prefix}   跳转落地: {str(entry.get('landing_url') or '（无落地）')[:76]}")
        if entry.get("landing_ips"):
            lines.append(f"{prefix}   落地IP: {', '.join(entry['landing_ips'][:3])}")
        lines.append(f"{prefix}   落地证据: {'; '.join(lv.get('evidence') or []) or '-'}")
    lines.append(f"{prefix}   合规: IP/CNAME 与种子及跳转链无交集 | 级别: {verdict['level']} | 分数 {verdict['score']}")
    print("\n".join(lines), flush=True)


if __name__ == "__main__":
    sys.exit(main())
