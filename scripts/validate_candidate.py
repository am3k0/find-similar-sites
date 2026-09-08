#!/usr/bin/env python3
"""Candidate validation for find-similar-sites — user rules edition.

Rules (as required by the skill owner):

  R1  IP/CNAME independence — the candidate must share NO IP and NO CNAME
      with the seed, *including every host in the seed's redirect chain*
      (HTTP Location hops and the JS/meta redirect target).
  R2  Overseas preference — when the seed resolves to mainland-China IPs,
      candidates on non-mainland IPs (including HK / MO / TW) rank first;
      mainland-only candidates are still allowed but must be flagged.
  R3  Real page evidence — validation must be based on actually fetched
      page content (body hash / CSS / DOM / favicon / title), collected
      through the proxy-fallback chain so interception pages never count
      as content.

Usage (library):
    from validate_candidate import validate
    verdict = validate(seed, candidate)

Usage (CLI):
    python scripts/validate_candidate.py --seed-json seed.json --cand-json cand.json
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import net_utils  # noqa: E402


def css_similarity(a, b):
    if not a or not b:
        return 0.0
    sa, sb = set(a), set(b)
    if not sa or not sb:
        return 0.0
    return len(sa & sb) / len(sa | sb)


def dom_similarity(a, b):
    if not a or not b:
        return 0.0
    n = min(len(a), len(b))
    return sum(1 for i in range(n) if a[i] == b[i]) / n


def content_evidence(seed_fp, cand_fp):
    """Return (score, [evidence strings]) comparing two real page fingerprints."""
    evidence = []
    score = 0
    if not seed_fp or not cand_fp:
        return 0, ["无内容指纹（需真实页面）"]

    sb, cb = seed_fp.get("sha256"), cand_fp.get("sha256")
    if sb and sb == cb:
        score += 4
        evidence.append("正文哈希完全一致")
    st, ct = seed_fp.get("title"), cand_fp.get("title")
    if st and st == ct:
        score += 1
        evidence.append(f"标题一致 {st!r}")
    cs = css_similarity(seed_fp.get("css_classes"), cand_fp.get("css_classes"))
    if cs >= 0.70:
        score += 2
        evidence.append(f"CSS 相似 {round(cs * 100)}%")
    ds = dom_similarity(seed_fp.get("dom_top"), cand_fp.get("dom_top"))
    if ds >= 0.80:
        score += 2
        evidence.append(f"DOM 相似 {round(ds * 100)}%")
    sf, cf = seed_fp.get("favicon_sha256"), cand_fp.get("favicon_sha256")
    if sf and sf == cf:
        score += 1
        evidence.append("favicon 一致")
    for marker in seed_fp.get("markers") or []:
        if marker in (cand_fp.get("marker_hits") or {}):
            score += 2
            evidence.append(f"含种子特有标记 {marker!r}")
    return score, evidence


def geo_note(seed, cand):
    """R2: overseas preference note. Returns (ok, note, priority_bonus)."""
    prefer = seed.get("prefer_overseas")
    cand_ips = cand.get("ips") or []
    mainland, known = False, False
    countries = []
    for ip in cand_ips:
        is_cn, kn = net_utils.is_china_ip(ip, cand.get("country"), cand.get("province"))
        mainland = mainland or is_cn
        known = known or kn
        country, province = net_utils.ip_geo(ip)
        countries.append(f"{country}/{province}" if country else ip)
    overseas_ok = not mainland
    if not prefer:
        return True, "、".join(countries[:2]) or "未知归属", 0
    if overseas_ok:
        return True, "、".join(countries[:2]) + "（境外 ✓）", 2
    return True, "、".join(countries[:2]) + "（⚠ 国内 IP，已按要求标记）", -1


def validate(seed, cand):
    """Full validation. seed/cand are dicts (see find_similar.collect_seed).

    Returns {'passed', 'level', 'reasons', 'geo_note', 'score'}
    level: same_content > same_template > infra_related > rejected
    """
    reasons = []
    seed_ips = set(seed.get("asset_ips") or [])
    seed_cnames = set((seed.get("asset_cnames") or []))
    cand_ips = set(cand.get("ips") or [])
    cand_cnames = set(cand.get("cnames") or [])

    # R1 — hard independence check
    ip_overlap = cand_ips & seed_ips
    cname_overlap = cand_cnames & seed_cnames
    if ip_overlap or cname_overlap:
        reasons.append(
            f"R1 拒绝：与种子（含跳转链）共享 {'IP ' + ','.join(sorted(ip_overlap)) if ip_overlap else ''}"
            f"{'CNAME ' + ','.join(sorted(cname_overlap)) if cname_overlap else ''}".strip())
        return {"passed": False, "level": "rejected", "reasons": reasons,
                "geo_note": "", "score": 0}
    reasons.append(f"R1 通过：IP/CNAME 与种子资产集无交集（种子 {len(seed_ips)} IP/{len(seed_cnames)} CNAME）")

    # R3 — content evidence
    score, evidence = content_evidence(seed.get("fp"), cand.get("fp"))
    if evidence:
        reasons.extend(f"R3 {line}" for line in evidence)
    else:
        reasons.append("R3 警告：无内容证据")

    # R2 — geo preference
    ok_geo, note, bonus = geo_note(seed, cand)
    reasons.append(f"R2 {note}")
    score += bonus

    if score >= 4:
        level = "same_content"
    elif score >= 2:
        level = "same_template"
    elif cand.get("infra_evidence"):
        level = "infra_related"
        reasons.append(f"基础设施证据：{cand.get('infra_evidence')}")
    else:
        level = "unverified"
    return {"passed": score >= 2, "level": level, "reasons": reasons,
            "geo_note": note, "score": score}


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-json", required=True, help="JSON file or '-' for stdin")
    parser.add_argument("--cand-json", required=True)
    args = parser.parse_args()

    def load(src):
        if src == "-":
            return json.load(sys.stdin)
        with open(src, encoding="utf-8") as handle:
            return json.load(handle)

    verdict = validate(load(args.seed_json), load(args.cand_json))
    print(json.dumps(verdict, ensure_ascii=False, indent=2))
