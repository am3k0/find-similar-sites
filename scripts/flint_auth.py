#!/usr/bin/env python3
"""Shared auth for 106.75.114.125 platform APIs.

Usage from other scripts:

    from flint_auth import get_token
    token = get_token(proxy="http://127.0.0.1:7898")

Credentials come from env vars FLINT_USERNAME and FLINT_PASSWORD.
Token is cached in memory for the lifetime of the process.
"""
import json
import os
import ssl
import sys
import urllib.request

_API_BASE = "https://106.75.114.125:23320"
_cached_token = None


def _build_opener(proxy):
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    handlers.append(urllib.request.HTTPSHandler(context=ssl._create_unverified_context()))
    return urllib.request.build_opener(*handlers)


def get_token(proxy=None):
    global _cached_token
    if _cached_token:
        return _cached_token
    try: from config import get_flint_creds; username, password = get_flint_creds()
    except ImportError: username = password = None
    if not username: username = os.environ.get("FLINT_USERNAME")
    if not password: password = os.environ.get("FLINT_PASSWORD")
    if not username or not password:
        print("Set FLINT_USERNAME and FLINT_PASSWORD in the environment.", file=sys.stderr)
        raise SystemExit(1)
    opener = _build_opener(proxy)
    login_url = f"{_API_BASE}/api/v1/login"
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        login_url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    with opener.open(req, timeout=15) as resp:
        payload = json.load(resp)
    if payload.get("code") != 200:
        print(f"Login failed: {payload.get('msg')}", file=sys.stderr)
        raise SystemExit(1)
    _cached_token = payload["data"]["access_token"]
    return _cached_token


def post_json(endpoint, body, proxy=None, timeout=60):
    token = get_token(proxy)
    opener = _build_opener(proxy)
    url = f"{_API_BASE}{endpoint}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={
            "Content-Type": "application/json",
            "Access-Token": token,
            "User-Agent": "Mozilla/5.0",
        },
    )
    with opener.open(req, timeout=timeout) as resp:
        return json.load(resp)
