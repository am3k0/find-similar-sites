#!/usr/bin/env python3
import argparse
import hashlib
import json
import re
import socket
import ssl
import sys


def decode_chunked(body):
    output = bytearray()
    remaining = body
    while remaining:
        line, separator, remaining = remaining.partition(b"\r\n")
        if not separator:
            break
        try:
            size = int(line.split(b";", 1)[0], 16)
        except ValueError:
            break
        if size == 0:
            break
        output.extend(remaining[:size])
        remaining = remaining[size + 2 :]
    return bytes(output)


def probe(ip, host, port, path, timeout, max_bytes, plain_http, markers):
    raw = socket.create_connection((ip, port), timeout=timeout)
    connection = raw
    certificate = None
    if not plain_http:
        context = ssl._create_unverified_context()
        connection = context.wrap_socket(raw, server_hostname=host)
        certificate = connection.getpeercert(binary_form=True)
    connection.settimeout(timeout)
    request = (
        f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n"
        "Accept: text/html,*/*\r\nConnection: close\r\n\r\n"
    ).encode()
    connection.sendall(request)
    chunks = []
    total = 0
    while total < max_bytes:
        chunk = connection.recv(min(65536, max_bytes - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    connection.close()
    data = b"".join(chunks)
    head, _, body = data.partition(b"\r\n\r\n")
    header_text = head.decode("iso-8859-1", "replace")
    if "transfer-encoding: chunked" in header_text.lower():
        body = decode_chunked(body)
    text = body.decode("utf-8", "replace")
    title_match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
    assets = sorted(set(re.findall(r"(?:src|href)=[\"']([^\"']+)", text, re.I)))[:200]
    result = {
        "ip": ip,
        "host": host,
        "port": port,
        "path": path,
        "status_line": header_text.split("\r\n", 1)[0] if header_text else "",
        "headers": header_text.split("\r\n")[1:],
        "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
        "title": title,
        "assets": assets,
        "markers": {marker: text.count(marker) for marker in markers},
    }
    if certificate:
        result["certificate_sha256"] = hashlib.sha256(certificate).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description="Probe a known origin using custom SNI and Host.")
    parser.add_argument("--ip", required=True)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--path", action="append", default=[])
    parser.add_argument("--marker", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--max-bytes", type=int, default=2_000_000)
    parser.add_argument("--plain-http", action="store_true")
    args = parser.parse_args()
    paths = args.path or ["/"]
    results = []
    for path in paths:
        try:
            results.append(
                probe(
                    args.ip,
                    args.host,
                    args.port,
                    path,
                    args.timeout,
                    args.max_bytes,
                    args.plain_http,
                    args.marker,
                )
            )
        except Exception as error:
            results.append({"ip": args.ip, "host": args.host, "path": path, "error": repr(error)})
    json.dump(results, sys.stdout, ensure_ascii=False, indent=2)
    print()


if __name__ == "__main__":
    main()

