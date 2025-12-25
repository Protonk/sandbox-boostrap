#!/usr/bin/env python3
import re
import sys

def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: extract_denies.py <log_path> <pid>", file=sys.stderr)
        return 2
    log_path = sys.argv[1]
    pid = sys.argv[2]
    pid_re = re.compile(r"\(" + re.escape(pid) + r"\)")
    event_re = re.compile(r'"eventMessage"\s*:\s*"([^"]*)"')

    with open(log_path, "r", errors="ignore") as fh:
        for raw in fh:
            m = event_re.search(raw)
            if not m:
                continue
            msg = m.group(1)
            msg = msg.replace("\\/", "/").replace("\\\"", '"')
            if "deny" not in msg:
                continue
            if pid_re.search(msg):
                print(msg)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
