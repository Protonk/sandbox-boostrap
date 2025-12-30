#!/usr/bin/env python3
"""
Join stub->GOT map output with otool indirect symbols to identify stub targets.

Outputs a JSON file suitable for mac_policy_register_scan.py (stub-targets=...).
"""

import argparse
import json
from pathlib import Path

from book.api import path_utils

DEFAULT_BUILD_ID = "14.4.1-23E224"
DEFAULT_STUB_MAP = "book/dumps/ghidra/out/{build}/sandbox-kext-stub-got-map/stub_got_map.json"
DEFAULT_OTOOL = "book/experiments/mac-policy-registration/out/otool_indirect_symbols.txt"
DEFAULT_OUT = "book/experiments/mac-policy-registration/out/stub_targets.json"
DEFAULT_SYMBOL_SUBSTRINGS = ["mac_policy_register", "amfi_register_mac_policy"]


def _parse_hex(text):
    text = str(text).strip().lower()
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


def _parse_otool(path: Path):
    symbols = {}
    with path.open("r") as fh:
        for line in fh:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            if not parts[0].startswith("0x"):
                continue
            try:
                addr = _parse_hex(parts[0])
            except Exception:
                continue
            try:
                index = int(parts[1])
            except Exception:
                index = None
            name = parts[2]
            symbols.setdefault(addr, []).append({"name": name, "index": index})
    return symbols


def _load_stub_map(path: Path):
    with path.open("r") as fh:
        data = json.load(fh)
    return data.get("stubs", [])


def _match_stubs(stubs, symbols_by_addr, filters):
    matches = []
    matched_stub_addresses = set()
    for stub in stubs:
        got_addr_text = stub.get("got_address")
        if not got_addr_text:
            continue
        try:
            got_addr = _parse_hex(got_addr_text)
        except Exception:
            continue
        symbols = symbols_by_addr.get(got_addr, [])
        if not symbols:
            continue
        matched_stub_addresses.add(stub.get("stub_address"))
        for sym in symbols:
            entry = {
                "name": sym.get("name"),
                "got_address": got_addr_text,
                "got_index": sym.get("index"),
                "stub_address": stub.get("stub_address"),
                "address": stub.get("stub_address"),
                "stub_block": stub.get("stub_block"),
                "stub_kind": stub.get("kind"),
                "stub_adrp": stub.get("adrp"),
                "stub_ldr": stub.get("ldr"),
                "stub_branch": stub.get("branch"),
                "stub_symbol_names": stub.get("stub_symbol_names"),
                "loaded_value": stub.get("loaded_value"),
            }
            matches.append(entry)
    if filters:
        filt_lower = [f.lower() for f in filters]
        targets = [m for m in matches if any(f in (m.get("name") or "").lower() for f in filt_lower)]
    else:
        targets = list(matches)
    return matches, targets, matched_stub_addresses


def main():
    parser = argparse.ArgumentParser(description="Join stub_got_map.json with otool indirect symbols.")
    parser.add_argument("--build-id", default=DEFAULT_BUILD_ID, help="aapl-restricted build ID.")
    parser.add_argument("--stub-map", default=None, help="Path to stub_got_map.json.")
    parser.add_argument("--otool", default=DEFAULT_OTOOL, help="Path to otool indirect symbols output.")
    parser.add_argument("--out", default=DEFAULT_OUT, help="Output JSON path.")
    parser.add_argument(
        "--symbol-substr",
        nargs="*",
        default=DEFAULT_SYMBOL_SUBSTRINGS,
        help="Symbol substrings to select as targets (default: mac_policy_register, amfi_register_mac_policy).",
    )
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    stub_map_path = Path(args.stub_map) if args.stub_map else Path(
        DEFAULT_STUB_MAP.format(build=args.build_id)
    )
    stub_map_path = path_utils.ensure_absolute(stub_map_path, repo_root)
    otool_path = path_utils.ensure_absolute(args.otool, repo_root)
    out_path = path_utils.ensure_absolute(args.out, repo_root)

    stubs = _load_stub_map(stub_map_path)
    symbols_by_addr = _parse_otool(otool_path)
    matches, targets, matched_stub_addresses = _match_stubs(stubs, symbols_by_addr, args.symbol_substr)

    meta = {
        "build_id": args.build_id,
        "stub_map": path_utils.to_repo_relative(stub_map_path, repo_root),
        "otool": path_utils.to_repo_relative(otool_path, repo_root),
        "symbol_filters": args.symbol_substr,
        "stub_count": len(stubs),
        "matched_stub_count": len(matched_stub_addresses),
        "match_count": len(matches),
        "target_count": len(targets),
    }
    out = {"meta": meta, "targets": targets, "matches": matches}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)
    print("Wrote", path_utils.to_repo_relative(out_path, repo_root))


if __name__ == "__main__":
    main()
