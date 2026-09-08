#!/usr/bin/env python3
"""Credential & settings manager for find-similar-sites skill.

Stores Hunter / Quake / Flint credentials and proxy settings in an encrypted
local file.  All scripts import from here instead of reading env vars.

Encryption: AES-256-GCM (cryptography package) with a key derived from the
machine GUID via PBKDF2.  Falls back to XOR obfuscation when the package is
missing.  No external dependencies required for reading config.
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import subprocess

_HOME = os.path.expanduser("~")
CONFIG_DIR = os.path.join(_HOME, ".codex", "find-similar-sites")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.enc")
if not os.path.isdir(CONFIG_DIR):
    CONFIG_DIR = os.path.join(_HOME, "Documents", "Codex_works")
    CONFIG_FILE = os.path.join(CONFIG_DIR, ".fss-config.enc")

# Default local proxies (rule / global).  Overridable via init.py.
DEFAULT_PROXY_RULE = "http://127.0.0.1:7897"
DEFAULT_PROXY_GLOBAL = "http://127.0.0.1:7898"


# --- Key derivation ---

def _get_machine_id():
    """Return a stable machine identifier."""
    if sys.platform == "win32":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Cryptography",
            )
            val, _ = winreg.QueryValueEx(key, "MachineGuid")
            winreg.CloseKey(key)
            return val
        except Exception:
            pass
    import socket
    return socket.gethostname()


def _derive_key():
    """Derive a 32-byte AES key from the machine ID."""
    machine = _get_machine_id()
    salt = b"find-similar-sites-v1"
    return hashlib.pbkdf2_hmac("sha256", machine.encode(), salt, 100_000, dklen=32)


# --- AES-256-GCM helpers (pure stdlib fallback) ---

def _encrypt(plaintext: str) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        key = _derive_key()
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
        return base64.b64encode(nonce + ct).decode()
    except ImportError:
        key = _derive_key()
        data = plaintext.encode()
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        return "x:" + base64.b64encode(encrypted).decode()


def _decrypt(encoded: str) -> str:
    if encoded.startswith("x:"):
        key = _derive_key()
        encrypted = base64.b64decode(encoded[2:])
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
        return decrypted.decode()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _derive_key()
    raw = base64.b64decode(encoded)
    nonce, ct = raw[:12], raw[12:]
    return AESGCM.decrypt(AESGCM(key), nonce, ct, None).decode()


# --- Public API ---

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return {}
    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
        encrypted = f.read().strip()
    if not encrypted:
        return {}
    return json.loads(_decrypt(encrypted))


def save_config(data):
    plain = json.dumps(data, ensure_ascii=False)
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        f.write(_encrypt(plain))


def get_hunter_key():
    return load_config().get("hunter_api_key") or None


def get_quake_token():
    return load_config().get("quake_token") or None


def get_flint_creds():
    cfg = load_config()
    return cfg.get("flint_username"), cfg.get("flint_password")


def get_proxy():
    return load_config().get("proxy") or None


def get_proxy_rule():
    cfg = load_config()
    return cfg.get("proxy_rule") or DEFAULT_PROXY_RULE


def get_proxy_global():
    cfg = load_config()
    return cfg.get("proxy_global") or DEFAULT_PROXY_GLOBAL


def set_credential(key, value):
    cfg = load_config()
    cfg[key] = value
    save_config(cfg)


# --- Validators ---

def validate_hunter_key(api_key):
    """Test a Hunter API key against the search endpoint (page_size=1)."""
    import urllib.request
    import urllib.parse
    url = "https://hunter.qianxin.com/openApi/search?" + urllib.parse.urlencode({
        "api-key": api_key,
        "search": base64.urlsafe_b64encode("domain=baidu.com".encode()).decode(),
        "page": 1,
        "page_size": 1,
        "is_web": 1,
    })
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if data.get("code") == 200:
            rest = (data.get("data") or {}).get("rest_quota", "unknown")
            return True, f"Valid (remaining quota: {rest})"
        return False, f"API error: {data.get('message', 'unknown')}"
    except Exception as e:
        return False, str(e)


def validate_quake_token(token):
    """Test a Quake token via GET /api/v3/user/info (must send browser UA)."""
    import urllib.request
    req = urllib.request.Request(
        "https://quake.360.net/api/v3/user/info",
        headers={"X-QuakeToken": token, "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        if data.get("code") == 0:
            user = ((data.get("data") or {}).get("user") or {})
            credit = (data.get("data") or {}).get("month_remaining_credit")
            return True, f"Valid (user: {user.get('username')}, credit: {credit})"
        return False, f"API error: {data.get('message', 'unknown')}"
    except Exception as e:
        return False, str(e)


def validate_flint_creds(username, password, proxy=None):
    from flint_auth import _build_opener
    import urllib.request
    opener = _build_opener(proxy)
    login_url = "https://106.75.114.125:23320/api/v1/login"
    data = json.dumps({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        login_url, data=data,
        headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with opener.open(req, timeout=15) as resp:
            payload = json.load(resp)
        if payload.get("code") == 200:
            return True, "Valid"
        return False, f"Login failed: {payload.get('msg', 'unknown')}"
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    cfg = load_config()
    if not cfg:
        print("No config found. Run: python scripts/init.py")
        sys.exit(0)
    print("Config status:")
    for k, v in cfg.items():
        if "key" in k.lower() or "password" in k.lower() or "token" in k.lower():
            v = v[:4] + "****" if v else "(empty)"
        print(f"  {k}: {v}")
