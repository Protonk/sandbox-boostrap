"""CLI entrypoints for Frida helpers."""

from __future__ import annotations

import argparse
from typing import Optional, Sequence

from book.api.frida import runner


def _add_runner_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--spawn",
        nargs="+",
        help="Spawn argv (preferred for bootstrap), e.g. --spawn ./targets/open_loop /etc/hosts",
    )
    ap.add_argument("--attach-pid", type=int, help="Attach to an existing pid")
    ap.add_argument("--script", required=True, help="Path to frida agent JS")
    ap.add_argument(
        "--out-dir",
        default="book/api/frida/out",
        help="Output directory",
    )
    ap.add_argument(
        "--duration-s",
        type=float,
        default=None,
        help="How long to run before detach (spawn mode; also used for attach when set)",
    )


def _run_runner(args: argparse.Namespace) -> int:
    return runner.run(
        spawn=args.spawn,
        attach_pid=args.attach_pid,
        script=args.script,
        out_dir=args.out_dir,
        duration_s=args.duration_s,
    )


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Spawn/attach a process and run a Frida script")
    _add_runner_args(run_parser)
    run_parser.set_defaults(func=_run_runner)

    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_arg_parser()
    args = ap.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        raise SystemExit("missing subcommand")
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
