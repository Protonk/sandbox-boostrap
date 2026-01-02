#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.frida import runner  # noqa: E402


def _find_run_dir(out_dir: Path, before: set[str]) -> Path | None:
    out_dir.mkdir(parents=True, exist_ok=True)
    after = {p.name for p in out_dir.iterdir() if p.is_dir()}
    created = sorted(after - before)
    if len(created) == 1:
        return out_dir / created[0]
    # Fallback: newest meta.json mtime.
    candidates: list[tuple[float, Path]] = []
    for p in out_dir.iterdir():
        if not p.is_dir():
            continue
        meta = p / "meta.json"
        if meta.exists():
            candidates.append((meta.stat().st_mtime, p))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


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
    ap.add_argument("--frida-config", default=None, help="JSON object for script configure()")
    ap.add_argument("--frida-config-path", default=None, help="Path to JSON file for script configure()")
    ap.add_argument(
        "--out-dir",
        default="book/evidence/experiments/runtime-final-final/suites/frida-testing/out",
        help="Output directory",
    )
    ap.add_argument(
        "--duration-s",
        type=float,
        default=None,
        help="How long to run before detach (spawn mode; also used for attach when set)",
    )
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    before = {p.name for p in out_dir.iterdir() if p.is_dir()} if out_dir.exists() else set()

    runner_rc = runner.run(
        spawn=args.spawn,
        attach_pid=args.attach_pid,
        script=args.script,
        config_json=args.frida_config,
        config_path=args.frida_config_path,
        out_dir=args.out_dir,
        duration_s=args.duration_s,
    )

    run_dir = _find_run_dir(out_dir, before)
    validate_report = None
    validate_error = None
    validate_rc = None
    if run_dir is not None and (run_dir / "meta.json").exists() and (run_dir / "events.jsonl").exists():
        try:
            from book.api.frida.validate import validate_run_dir

            validate_report = validate_run_dir(run_dir)
            validate_rc = 0 if validate_report.get("ok") else 1
        except Exception as exc:
            validate_error = f"{type(exc).__name__}: {exc}"
            validate_rc = 1
    else:
        validate_error = "missing run_dir/meta.json/events.jsonl (cannot validate)"
        validate_rc = 1

    report = {
        "ok": bool(runner_rc == 0 and validate_rc == 0),
        "runner": {"exit_code": runner_rc},
        "run_dir": str(run_dir) if run_dir is not None else None,
        "validate": validate_report,
        "validate_error": validate_error,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
