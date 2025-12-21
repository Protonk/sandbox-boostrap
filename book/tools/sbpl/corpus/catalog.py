#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence


CORPUS_DIR = Path(__file__).resolve().parent


def _count_by(items: Iterable[Dict[str, str]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for item in items:
        raw = item.get(key)
        k = raw if isinstance(raw, str) else "null"
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def _iter_entries() -> Dict[str, Dict[str, str]]:
    entries: Dict[str, Dict[str, str]] = {}
    if not CORPUS_DIR.exists():
        return entries
    for path in sorted(CORPUS_DIR.rglob("*.sb")):
        if not path.is_file():
            continue
        rel = path.relative_to(CORPUS_DIR).as_posix()
        family = rel.split("/", 1)[0]
        entries[rel] = {"path": rel, "family": family}
    return entries


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="sbpl-catalog")
    ap.add_argument("--json", action="store_true", help="Emit a JSON listing of corpus entries.")
    args = ap.parse_args(argv)

    entries = list(_iter_entries().values())
    if args.json:
        print(json.dumps({"entries": entries}, indent=2, sort_keys=True))
        return 0

    by_family = _count_by(entries, "family")
    total = sum(by_family.values())

    print(f"entries: {total}")
    for family, count in by_family.items():
        print(f"- {family}: {count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
