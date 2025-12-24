#!/usr/bin/env python3
import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.frida import runner  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--spawn",
        nargs="+",
        help=(
            "Spawn argv (preferred for bootstrap), e.g. --spawn ./targets/open_loop /etc/hosts"
        ),
    )
    ap.add_argument("--attach-pid", type=int, help="Attach to an existing pid")
    ap.add_argument("--script", required=True, help="Path to frida agent JS")
    ap.add_argument(
        "--out-dir",
        default="book/experiments/frida-testing/out",
        help="Output directory",
    )
    ap.add_argument(
        "--duration-s",
        type=float,
        default=None,
        help="How long to run before detach (spawn mode; also used for attach when set)",
    )
    args = ap.parse_args()

    return runner.run(
        spawn=args.spawn,
        attach_pid=args.attach_pid,
        script=args.script,
        out_dir=args.out_dir,
        duration_s=args.duration_s,
    )


if __name__ == "__main__":
    raise SystemExit(main())
