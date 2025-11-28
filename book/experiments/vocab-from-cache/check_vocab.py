#!/usr/bin/env python3
"""
Quick sanity check for harvested vocab artifacts.

This is a lightweight guardrail: it asserts status=ok and expected counts for
ops/filters vocab files produced on this host.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys


def load_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        raise SystemExit(f"failed to read {path}: {exc}")


def main() -> None:
    root = Path("book/graph/concepts/validation/out/vocab")
    ops_path = root / "ops.json"
    filters_path = root / "filters.json"
    ops = load_json(ops_path)
    filters = load_json(filters_path)

    if ops.get("status") != "ok":
        raise SystemExit(f"ops.json status is {ops.get('status')}, expected ok")
    if filters.get("status") != "ok":
        raise SystemExit(f"filters.json status is {filters.get('status')}, expected ok")

    ops_len = len(ops.get("ops") or [])
    filt_len = len(filters.get("filters") or [])
    if ops_len != 196:
        raise SystemExit(f"unexpected ops count {ops_len}, expected 196")
    if filt_len != 93:
        raise SystemExit(f"unexpected filters count {filt_len}, expected 93")

    print("vocab sanity ok: ops=196, filters=93, status ok")


if __name__ == "__main__":
    main()
