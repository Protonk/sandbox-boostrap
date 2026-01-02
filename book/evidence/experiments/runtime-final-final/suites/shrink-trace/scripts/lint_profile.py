#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path


IP_RE = re.compile(r"\((remote|local)\s+ip\s+\"([^\"]+)\"\)")
UNIX_RE = re.compile(r"\((remote|local)\s+unix-socket\b")


def split_host_port(value: str) -> tuple[str, str | None]:
    if ":" not in value:
        return value, None
    host, port = value.rsplit(":", 1)
    return host, port


def lint_line(line: str, lineno: int, issues: list[str]) -> None:
    for match in IP_RE.finditer(line):
        raw = match.group(2)
        host, port = split_host_port(raw)
        if host not in {"*", "localhost"}:
            issues.append(f"{lineno}: ip host must be '*' or 'localhost', got '{host}'")
        if port is None or (port != "*" and not port.isdigit()):
            issues.append(f"{lineno}: ip port must be '*' or digits, got '{port}'")

    if "unix-socket" in line and UNIX_RE.search(line):
        if "path-literal" not in line:
            issues.append(f"{lineno}: unix-socket must use path-literal")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: lint_profile.py <profile.sb>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"missing profile: {path}", file=sys.stderr)
        return 2

    issues: list[str] = []
    for lineno, line in enumerate(path.read_text(errors="ignore").splitlines(), start=1):
        lint_line(line, lineno, issues)

    if issues:
        for issue in issues:
            print(issue)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
