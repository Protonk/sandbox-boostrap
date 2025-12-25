#!/usr/bin/env python3
import re
import sys

NEEDLES = [
    "Sandbox:",
    "file system sandbox blocked",
    "blocked open(",
    "blocked mmap(",
]

def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: extract_sandbox_messages.py <log_path>", file=sys.stderr)
        return 2
    log_path = sys.argv[1]
    event_re = re.compile(r'"eventMessage"\s*:\s*"([^"]*)"')

    with open(log_path, "r", errors="ignore") as fh:
        for raw in fh:
            m = event_re.search(raw)
            if not m:
                continue
            msg = m.group(1)
            msg = msg.replace("\\/", "/").replace("\\\"", '"')
            if any(n in msg for n in NEEDLES):
                print(msg)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
