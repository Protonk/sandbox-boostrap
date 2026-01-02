"""
Filter the kernel import census for sandbox-related externals.

Usage:
    python filter_imports.py --input book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-imports/imports_all.json \\
        --output book/evidence/dumps/ghidra/out/14.4.1-23E224/kernel-imports/imports_filtered.json \\
        --substr applematch mac_policy sandbox seatbelt
    python filter_imports.py --input ... --output ... --regex 'apple.*match'

Inputs are repo-relative; outputs stay repo-relative and reuse the input format
with meta.query describing the filter.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Iterable, List, Mapping


def load_imports(path: Path) -> Mapping:
    return json.loads(path.read_text())


def write_imports(path: Path, data: Mapping) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


def filter_symbols(symbols: Iterable[Mapping], substrings: List[str], regex: str | None) -> List[Mapping]:
    lowered = [s.lower() for s in substrings]
    pattern = re.compile(regex, re.IGNORECASE) if regex else None
    out: List[Mapping] = []
    for sym in symbols:
        name = sym.get("name", "")
        lib = sym.get("library", "")
        text = f"{name} {lib}".lower()
        if lowered and not any(sub in text for sub in lowered):
            continue
        if pattern and not pattern.search(f"{name} {lib}"):
            continue
        out.append(sym)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Filter kernel import census JSON.")
    parser.add_argument("--input", required=True, help="Path to imports_all.json (repo-relative or absolute).")
    parser.add_argument("--output", required=True, help="Where to write the filtered JSON.")
    parser.add_argument("--substr", nargs="*", default=[], help="Case-insensitive substrings to match in name/library.")
    parser.add_argument("--regex", help="Optional regex to match against name/library.")
    args = parser.parse_args()

    src = Path(args.input)
    dst = Path(args.output)
    data = load_imports(src)
    symbols = data.get("symbols", [])
    filtered = filter_symbols(symbols, args.substr, args.regex)
    meta = dict(data.get("meta", {}))
    meta["filter_substrings"] = [s.lower() for s in args.substr]
    meta["filter_regex"] = args.regex
    meta["filtered_count"] = len(filtered)
    meta["source"] = str(src)
    write_imports(dst, {"meta": meta, "symbols": filtered})
    print(f"wrote {len(filtered)} symbols to {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
