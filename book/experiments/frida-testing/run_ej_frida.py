#!/usr/bin/env python3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.frida import entitlementjail as ej_frida  # noqa: E402


def main() -> int:
    argv = sys.argv[1:]
    if "--out-dir" not in argv:
        argv = ["--out-dir", "book/experiments/frida-testing/out", *argv]
    return ej_frida.main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
