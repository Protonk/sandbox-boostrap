#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


def parse_trace(text: str) -> dict:
    ops = set()
    paths = set()
    total = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        total += 1
        for op in re.findall(r"\bfile-[A-Za-z0-9_-]+\b", line):
            ops.add(op)
        for tok in line.split():
            if tok.startswith("/"):
                paths.add(tok)
    return {
        "total_lines": total,
        "ops": sorted(ops),
        "paths": sorted(paths),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trace-path", required=True, help="Path to sandbox trace file")
    ap.add_argument("--out", required=True, help="Output JSON path")
    args = ap.parse_args()

    trace_path = Path(args.trace_path)
    if not trace_path.exists():
        payload = {
            "trace_path": str(trace_path),
            "trace_exists": False,
            "total_lines": 0,
            "ops": [],
            "paths": [],
        }
        Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    data = parse_trace(trace_path.read_text(errors="replace"))
    payload = {
        "trace_path": str(trace_path),
        "trace_exists": True,
        **data,
    }
    Path(args.out).write_text(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
