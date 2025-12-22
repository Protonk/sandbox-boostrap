#!/usr/bin/env python3
"""
Derive mac_policy_register call sites from string-anchored call-site scan output.

Inputs:
- string_call_sites.json (from kernel-collection-string-call-sites)
- kc_fileset_index.json (fileset entries + vmaddr spans)

Outputs:
- mac_policy_register_call_sites.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from book.api import path_utils


def _parse_hex(text: str) -> Optional[int]:
    text = str(text).strip().lower()
    if not text:
        return None
    if text.startswith("0x-"):
        return -int(text[3:], 16)
    if text.startswith("-0x"):
        return -int(text[3:], 16)
    if text.startswith("0x"):
        value = int(text, 16)
        if value & (1 << 63):
            return value - (1 << 64)
        return value
    value = int(text, 0)
    if value & (1 << 63):
        return value - (1 << 64)
    return value


def _s64(value: int) -> int:
    value &= (1 << 64) - 1
    if value & (1 << 63):
        return value - (1 << 64)
    return value


def _load_entries(index_path: Path) -> List[Tuple[int, int, str]]:
    data = json.loads(index_path.read_text())
    entries = []
    for entry in data.get("entries", []):
        span = entry.get("vmaddr_span") or {}
        start = span.get("start")
        end = span.get("end")
        if start is None or end is None:
            continue
        entries.append((_s64(int(start)), _s64(int(end)), entry.get("entry_id")))
    return sorted(entries, key=lambda item: item[0])


def _find_entry(entries: List[Tuple[int, int, str]], vmaddr: int) -> Optional[str]:
    lo = 0
    hi = len(entries) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end, entry_id = entries[mid]
        if vmaddr < start:
            hi = mid - 1
        elif vmaddr >= end:
            lo = mid + 1
        else:
            return entry_id
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Derive mac_policy_register call sites from string scan.")
    parser.add_argument(
        "--string-calls",
        default="dumps/ghidra/out/14.4.1-23E224/kernel-collection-string-call-sites/string_call_sites.json",
        help="Path to string_call_sites.json",
    )
    parser.add_argument(
        "--fileset-index",
        default="book/experiments/mac-policy-registration/out/kc_fileset_index.json",
        help="Path to kc_fileset_index.json",
    )
    parser.add_argument(
        "--out",
        default="book/experiments/mac-policy-registration/out/mac_policy_register_call_sites.json",
        help="Output path",
    )
    parser.add_argument(
        "--string-filter",
        default="Security policy loaded",
        help="Substring to select the target function",
    )
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    calls_path = path_utils.ensure_absolute(args.string_calls, repo_root)
    index_path = path_utils.ensure_absolute(args.fileset_index, repo_root)
    out_path = path_utils.ensure_absolute(args.out, repo_root)

    data = json.loads(calls_path.read_text())
    entries = _load_entries(index_path)
    target_entries = []
    for func in data.get("functions", []):
        if any(args.string_filter in s for s in func.get("strings", [])):
            target_entries.append(func.get("entry"))
    target_entries = [e for e in target_entries if e]

    call_sites = []
    for call in data.get("call_sites", []):
        if call.get("target_entry") not in target_entries:
            continue
        call_addr = _parse_hex(call.get("call_address"))
        if call_addr is None:
            continue
        owner = _find_entry(entries, call_addr)
        call_sites.append(
            {
                "call_address": call.get("call_address"),
                "call_mnemonic": call.get("call_mnemonic"),
                "target_entry": call.get("target_entry"),
                "target_name": call.get("target_name"),
                "owner_entry": owner,
            }
        )

    out = {
        "meta": {
            "string_call_sites": path_utils.to_repo_relative(calls_path, repo_root),
            "fileset_index": path_utils.to_repo_relative(index_path, repo_root),
            "string_filter": args.string_filter,
            "target_function_count": len(target_entries),
            "call_site_count": len(call_sites),
        },
        "call_sites": call_sites,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True))
    print("Wrote", path_utils.to_repo_relative(out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
