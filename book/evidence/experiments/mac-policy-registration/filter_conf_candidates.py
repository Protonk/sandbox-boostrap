"""Offline filter/ranker for mac_policy_conf candidate JSON.

Usage:
  python book/evidence/experiments/mac-policy-registration/filter_conf_candidates.py \
    --in book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-conf-scan/mac_policy_conf_candidates.json \
    --out book/evidence/dumps/ghidra/out/14.4.1-23E224/sandbox-kext-conf-scan/mac_policy_conf_candidates_ranked.json

This is intentionally lightweight: it preserves the raw candidates from the
Ghidra scan and emits a sorted shortlist with heuristic scores (string hints,
flags, ops pointer presence). All paths are repo-relative.
"""

import argparse
import json
import pathlib
import sys
from typing import Dict, List

STR_HINTS = ("sand", "seat", "policy", "sandbox")
FLAG_HINTS = {0x2, 0x4, 0x6}


def load_candidates(path: pathlib.Path) -> Dict:
    with path.open() as f:
        return json.load(f)


def score_candidate(cand: Dict) -> Dict:
    slots = cand.get("slots", {})
    strings = cand.get("string_values", {}) or {}
    score = 0
    reasons: List[str] = []

    name = (strings.get("name") or "").lower()
    fullname = (strings.get("fullname") or "").lower()
    if name:
        score += 1
        reasons.append("name_str")
    if fullname:
        score += 1
        reasons.append("fullname_str")
    for hint in STR_HINTS:
        if hint in name or hint in fullname:
            score += 1
            reasons.append(f"hint:{hint}")
            break

    if slots.get("labelnames") not in ("0x0", None):
        score += 1
        reasons.append("labelnames_present")

    if slots.get("ops") not in ("0x0", None):
        score += 1
        reasons.append("ops_present")

    loadtime_flags = slots.get("loadtime_flags")
    try:
        flags_val = int(loadtime_flags, 16)
    except Exception:
        flags_val = None
    if flags_val in FLAG_HINTS:
        score += 1
        reasons.append(f"flag_hint:0x{flags_val:x}")

    labelname_count = slots.get("labelname_count")
    if isinstance(labelname_count, int) and 0 <= labelname_count <= 4:
        score += 1
        reasons.append("labelname_count_small")

    runtime_flags = slots.get("runtime_flags")
    try:
        runtime_val = int(runtime_flags, 16)
    except Exception:
        runtime_val = None
    if runtime_val == 0:
        score += 1
        reasons.append("runtime_flags_zero")

    ranked = dict(cand)
    ranked["rank_score"] = score
    ranked["rank_reasons"] = reasons
    return ranked


def rank_candidates(data: Dict) -> Dict:
    cands = [score_candidate(c) for c in data.get("candidates", [])]
    cands.sort(key=lambda c: (-c.get("rank_score", 0), c.get("address", "")))
    return {"meta": data.get("meta", {}), "candidates": cands}


def main():
    parser = argparse.ArgumentParser(description="Rank mac_policy_conf candidates")
    parser.add_argument("--in", dest="in_path", required=True, help="Input candidates JSON")
    parser.add_argument(
        "--out",
        dest="out_path",
        required=True,
        help="Output ranked JSON (will be overwritten)",
    )
    args = parser.parse_args()

    in_path = pathlib.Path(args.in_path)
    out_path = pathlib.Path(args.out_path)
    data = load_candidates(in_path)
    ranked = rank_candidates(data)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(ranked, f, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
