#!/usr/bin/env python3
"""
DNS resolution history via Flint platform /api/v1/commons/flint.

Returns structured DNS records with timestamps, counts, record types,
and resolved addresses. Parses TSV response into JSON.

Usage:
    python scripts/dns_history.py m.ijbuhy.top
    python scripts/dns_history.py m.ijbuhy.top --json
    python scripts/dns_history.py hosts.txt
"""
import argparse, json, os, ssl, sys, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flint_auth import get_token, _build_opener, _API_BASE


def parse_tsv(tsv_text):
    """Parse Flint DNS history TSV into structured records."""
    lines = tsv_text.strip().split("\n")
    if len(lines) < 2:
        return []
    records = []
    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) >= 6:
            records.append({
                "time_first": parts[0].strip(),
                "time_last": parts[1].strip(),
                "count": int(parts[2].strip()) if parts[2].strip().isdigit() else parts[2].strip(),
                "rrname": parts[3].strip(),
                "rrtype": parts[4].strip(),
                "rdata": parts[5].strip().rstrip(";"),
            })
    return records


def query_dns_history(host):
    """Query /api/v1/commons/flint for a single host."""
    token = get_token()
    opener = _build_opener(None)
    url = f"{_API_BASE}/api/v1/commons/flint?arg={host}"
    req = urllib.request.Request(
        url,
        headers={"Access-Token": token, "User-Agent": "Mozilla/5.0"},
    )
    with opener.open(req, timeout=30) as resp:
        payload = json.loads(resp.read())
    if payload.get("code") != 200:
        raise RuntimeError(f"API error: {payload.get('msg')}")
    return parse_tsv(payload.get("data", ""))


def main():
    parser = argparse.ArgumentParser(description="Query Flint DNS resolution history")
    parser.add_argument("target", help="Hostname or file with one host per line")
    parser.add_argument("--json", action="store_true", help="Output structured JSON")
    args = parser.parse_args()

    hosts = []
    if os.path.isfile(args.target):
        with open(args.target) as f:
            hosts = [line.strip() for line in f if line.strip()]
    else:
        hosts = [args.target]

    all_results = {}
    for host in hosts:
        try:
            records = query_dns_history(host)
            all_results[host] = records
        except Exception as e:
            all_results[host] = {"error": str(e)}

    if args.json:
        json.dump(all_results, sys.stdout, ensure_ascii=False, indent=2)
        print()
    else:
        for host, records in all_results.items():
            print(f"=== {host} ===")
            if isinstance(records, dict) and "error" in records:
                print(f"  Error: {records['error']}")
                continue
            if not records:
                print("  No records")
                continue
            # Summary
            ips = sorted(set(r["rdata"] for r in records if r["rrtype"] == "A"))
            ipv6s = sorted(set(r["rdata"] for r in records if r["rrtype"] == "AAAA"))
            all_times = [r["time_first"] for r in records] + [r["time_last"] for r in records]
            print(f"  First seen: {min(all_times)}  Last seen: {max(all_times)}")
            print(f"  IPv4: {', '.join(ips) if ips else 'none'}")
            print(f"  IPv6: {', '.join(ipv6s) if ipv6s else 'none'}")
            print(f"  Total records: {len(records)}")
            for r in records:
                print(f"    {r['time_first']} ~ {r['time_last']}  {r['rrtype']:5s}  {r['rdata']}  (x{r['count']})")
            print()


if __name__ == "__main__":
    main()
