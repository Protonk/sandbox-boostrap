#!/usr/bin/env python3
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.witness import frida as witness_frida  # noqa: E402


def _argv_out_dir(argv: list[str], *, default: str) -> tuple[list[str], str]:
    if "--out-dir" in argv:
        idx = argv.index("--out-dir")
        if idx + 1 < len(argv):
            return argv, argv[idx + 1]
    return ["--out-dir", default, *argv], default


def _find_run_root(out_dir: Path, before: set[str]) -> Path | None:
    out_dir.mkdir(parents=True, exist_ok=True)
    after = {p.name for p in out_dir.iterdir() if p.is_dir()}
    created = sorted(after - before)
    if len(created) == 1:
        return out_dir / created[0]
    candidates: list[tuple[float, Path]] = []
    for p in out_dir.iterdir():
        if not p.is_dir():
            continue
        manifest = p / "manifest.json"
        if manifest.exists():
            candidates.append((manifest.stat().st_mtime, p))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


def main() -> int:
    argv, out_dir_str = _argv_out_dir(list(sys.argv[1:]), default="book/experiments/runtime-final-final/suites/frida-testing/out")
    out_dir = Path(out_dir_str)
    before = {p.name for p in out_dir.iterdir() if p.is_dir()} if out_dir.exists() else set()

    witness_rc = witness_frida.main(argv)

    run_root = _find_run_root(out_dir, before)
    frida_dir = (run_root / "frida") if run_root is not None else None
    validate_report = None
    validate_error = None
    validate_rc = None
    if frida_dir is not None and (frida_dir / "meta.json").exists() and (frida_dir / "events.jsonl").exists():
        try:
            from book.api.frida.validate import validate_run_dir

            validate_report = validate_run_dir(frida_dir)
            validate_rc = 0 if validate_report.get("ok") else 1
        except Exception as exc:
            validate_error = f"{type(exc).__name__}: {exc}"
            validate_rc = 1
    else:
        validate_error = "missing frida/meta.json/events.jsonl (cannot validate)"
        validate_rc = 1

    report = {
        "ok": bool(witness_rc == 0 and validate_rc == 0),
        "witness": {"exit_code": witness_rc},
        "run_root": str(run_root) if run_root is not None else None,
        "frida_dir": str(frida_dir) if frida_dir is not None else None,
        "validate": validate_report,
        "validate_error": validate_error,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
