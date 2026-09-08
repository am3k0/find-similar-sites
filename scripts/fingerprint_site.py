#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import re
import socket
import ssl
import struct
import sys
import urllib.parse
import urllib.request


def mmh3_32(data, seed=0):
    if isinstance(data, str):
        data = data.encode()
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    value = seed & 0xFFFFFFFF
    rounded = len(data) & ~3
    for offset in range(0, rounded, 4):
        chunk = struct.unpack_from("<I", data, offset)[0]
        chunk = (chunk * c1) & 0xFFFFFFFF
        chunk = ((chunk << 15) | (chunk >> 17)) & 0xFFFFFFFF
        chunk = (chunk * c2) & 0xFFFFFFFF
        value ^= chunk
        value = ((value << 13) | (value >> 19)) & 0xFFFFFFFF
        value = (value * 5 + 0xE6546B64) & 0xFFFFFFFF
    chunk = 0
    tail = data[rounded:]
    if len(tail) == 3:
        chunk ^= tail[2] << 16
    if len(tail) >= 2:
        chunk ^= tail[1] << 8
    if tail:
        chunk ^= tail[0]
        chunk = (chunk * c1) & 0xFFFFFFFF
        chunk = ((chunk << 15) | (chunk >> 17)) & 0xFFFFFFFF
        chunk = (chunk * c2) & 0xFFFFFFFF
        value ^= chunk
    value ^= len(data)
    value ^= value >> 16
    value = (value * 0x85EBCA6B) & 0xFFFFFFFF
    value ^= value >> 13
    value = (value * 0xC2B2AE35) & 0xFFFFFFFF
    value ^= value >> 16
    return value if value < 0x80000000 else value - 0x100000000


def build_opener(proxy, insecure):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    if insecure:
        handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url, timeout, max_bytes):
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(request, timeout=timeout) as response:
        body = response.read(max_bytes)
        return {
            "status": response.status,
            "final_url": response.geturl(),
            "headers": dict(response.headers),
            "body": body,
        }


def title_and_assets(text):
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    assets = sorted(set(re.findall(r"(?:src|href)=[\"']([^\"']+)", text, re.I)))
    return title, assets[:200]


def hashes(body):
    return {
        "bytes": len(body),
        "md5": hashlib.md5(body).hexdigest(),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def structured_signature(text):
    """Extract CSS classes, DOM skeleton, and top-level JS globals.

    These markers survive dynamic content changes better than body hash
    because they come from the template layer rather than data.
    """
    # CSS class names
    css_classes = sorted(set(
        cls
        for match in re.findall(r'\bclass=["\']([^"\']+)', text, re.I)
        for cls in match.split()
    ))

    # DOM skeleton: sequence of opening tag names in document order
    dom_skeleton = re.findall(r'<(\w+)', text)

    # JS globals: top-level var/let/const and window.* assignments
    script_texts = re.findall(r'<script[^>]*>(.*?)</script>', text, re.I | re.S)
    js_globals = sorted(set(
        name
        for st in script_texts
        for name in re.findall(r'(?:var|let|const)\s+(\w+)\s*=', st, re.I)
    ))
    js_globals += sorted(set(
        name
        for st in script_texts
        for name in re.findall(r'window\.(\w+)\s*=', st, re.I)
    ))

    return {
        "css_class_count": len(css_classes),
        "css_classes": css_classes,
        "dom_skeleton_len": len(dom_skeleton),
        "dom_skeleton_top": dom_skeleton[:80],
        "js_global_count": len(js_globals),
        "js_globals": js_globals,
    }


def inspect_url(opener, url, timeout, max_bytes):
    try:
        response = fetch(opener, url, timeout, max_bytes)
        text = response["body"].decode("utf-8", "replace")
        title, assets = title_and_assets(text)
        result = {
            "requested_url": url,
            "status": response["status"],
            "final_url": response["final_url"],
            "server": response["headers"].get("Server"),
            "content_type": response["headers"].get("Content-Type"),
            "location": response["headers"].get("Location"),
            "title": title,
            "assets": assets,
            "body": hashes(response["body"]),
            "structured": structured_signature(text),
        }
        icon_path = next(
            (asset for asset in assets if re.search(r"(?:favicon|icon).*(?:ico|png|svg)", asset, re.I)),
            "/favicon.ico",
        )
        icon_url = urllib.parse.urljoin(response["final_url"], icon_path)
        try:
            icon = fetch(opener, icon_url, timeout, max_bytes)["body"]
            result["favicon"] = {
                "url": icon_url,
                **hashes(icon),
                "mmh3": mmh3_32(base64.encodebytes(icon)),
            }
        except Exception as error:
            result["favicon_error"] = repr(error)
        return result
    except Exception as error:
        return {"requested_url": url, "error": repr(error)}


def fingerprint_from_browser(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    target = data.get("target", "")
    dns = data.get("dns", [])
    attempts = []
    html = data.get("rendered_html", "")
    if html:
        text = html
        title, assets = title_and_assets(text)
        entry = {
            "requested_url": data.get("final_url", target),
            "status": 200,
            "final_url": data.get("final_url", target),
            "server": data.get("server"),
            "content_type": "text/html",
            "title": title,
            "assets": assets,
            "body": hashes(text.encode("utf-8")),
            "structured": structured_signature(text),
        }
        # Add network-discovered assets
        net_assets = set()
        net_domains = set()
        for req in data.get("network_requests", []):
            url = req.get("url", "")
            if url and not url.startswith("data:"):
                net_assets.add(url)
                parsed = urllib.parse.urlparse(url)
                if parsed.hostname:
                    net_domains.add(parsed.hostname)
        entry["network_assets"] = sorted(net_assets)
        entry["network_domains"] = sorted(net_domains)
        # Favicon from browser data
        fav_b64 = data.get("favicon_data")
        if fav_b64:
            try:
                import base64
                fav_bytes = base64.b64decode(fav_b64)
                entry["favicon"] = {"url": "", **hashes(fav_bytes), "mmh3": mmh3_32(base64.encodebytes(fav_bytes))}
            except Exception:
                pass
        attempts.append(entry)
    return {"target": target, "dns": dns, "attempts": attempts, "source": "browser"}


def fingerprint_from_har(path):
    with open(path, "r", encoding="utf-8") as f:
        har = json.load(f)
    log = har.get("log", {})
    entries = log.get("entries", [])
    target = ""
    dns = []
    attempts = []
    # Find main HTML entry
    html_entries = [e for e in entries if e.get("response", {}).get("content", {}).get("mimeType", "").startswith("text/html")]
    for e in html_entries:
        req = e.get("request", {})
        resp = e.get("response", {})
        content = resp.get("content", {})
        text = content.get("text", "")
        if not text and content.get("encoding") == "base64":
            try:
                import base64
                text = base64.b64decode(content.get("text", "")).decode("utf-8", "replace")
            except Exception:
                pass
        if not text:
            continue
        target = target or req.get("url", "")
        title, assets = title_and_assets(text)
        entry = {
            "requested_url": req.get("url", ""),
            "status": resp.get("status", 200),
            "final_url": req.get("url", ""),
            "title": title,
            "assets": assets,
            "body": hashes(text.encode("utf-8")),
            "structured": structured_signature(text),
        }
        # All URLs as network assets
        all_urls = sorted(set(e.get("request", {}).get("url", "") for e in entries if e.get("request", {}).get("url")))
        all_domains = sorted(set(urllib.parse.urlparse(u).hostname for u in all_urls if urllib.parse.urlparse(u).hostname))
        entry["network_assets"] = all_urls
        entry["network_domains"] = all_domains
        attempts.append(entry)
    return {"target": target, "dns": dns, "attempts": attempts, "source": "har"}


def main():
    parser = argparse.ArgumentParser(description="Fingerprint a website without submitting data.")
    parser.add_argument("target", nargs="?", help="Domain or URL (omit with --from-browser/--from-har)")
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    parser.add_argument("--timeout", type=float, default=20)
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--from-browser", help="JSON file from browser fingerprint collection")
    parser.add_argument("--from-har", help="HAR file from browser DevTools export")
    args = parser.parse_args()

    if args.from_browser:
        output = fingerprint_from_browser(args.from_browser)
        json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return
    if args.from_har:
        output = fingerprint_from_har(args.from_har)
        json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return

    parsed = urllib.parse.urlparse(args.target if "://" in args.target else "//" + args.target)
    host = parsed.hostname or args.target
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None)})
    except Exception as error:
        addresses = [f"DNS error: {error!r}"]

    urls = [args.target] if "://" in args.target else [f"http://{args.target}/", f"https://{args.target}/"]
    opener = build_opener(args.proxy, args.insecure)
    output = {
        "target": args.target,
        "dns": addresses,
        "attempts": [inspect_url(opener, url, args.timeout, args.max_bytes) for url in urls],
    }
    json.dump(output, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()
