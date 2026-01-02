#!/usr/bin/env python3
# Legacy: prefer EntitlementJail observer reports for deny evidence parsing.
import argparse
import json
import re
from collections import Counter
from pathlib import Path


DENY_RE = re.compile(r"deny\\(\\d+\\)\\s+([A-Za-z0-9_-]+)")
PATH_RE = re.compile(r"(/[^\\s]+)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True, help="NDJSON log stream path")
    ap.add_argument("--out", required=True, help="Summary JSON path")
    args = ap.parse_args()

    log_path = Path(args.log)
    total = 0
    parsed = 0
    deny_events = 0
    ops = Counter()
    paths = Counter()
    pids = Counter()

    if log_path.exists():
        for line in log_path.read_text(errors="replace").splitlines():
            total += 1
            try:
                obj = json.loads(line)
            except Exception:
                continue
            parsed += 1
            pid = obj.get("processID")
            if pid is not None:
                pids[str(pid)] += 1
            msg = obj.get("eventMessage") or ""
            m = DENY_RE.search(msg)
            if m:
                deny_events += 1
                ops[m.group(1)] += 1
                pm = PATH_RE.search(msg)
                if pm:
                    paths[pm.group(1)] += 1

    summary = {
        "log_path": str(log_path),
        "total_lines": total,
        "parsed_lines": parsed,
        "deny_events": deny_events,
        "op_counts": dict(ops.most_common()),
        "path_counts": dict(paths.most_common(20)),
        "pid_counts": dict(pids.most_common()),
    }
    Path(args.out).write_text(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
