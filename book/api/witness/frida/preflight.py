"""Preflight checks for Frida attach workflows (PolicyWitness-focused)."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

from book.api import path_utils
from book.api.profile.identity import baseline_world_id


def _run_cmd(cmd: list[str]) -> Dict[str, object]:
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).strip()
        return {"ok": True, "output": out}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _codesign_entitlements(path: Path) -> Dict[str, object]:
    # codesign prints entitlements to stderr; capture stdout+stderr together.
    cmd = ["codesign", "-d", "--entitlements", ":-", str(path)]
    return _run_cmd(cmd)


def _frida_version() -> Dict[str, object]:
    try:
        import frida  # type: ignore
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "version": getattr(frida, "__version__", None)}


def _try_attach(pid: int) -> Dict[str, object]:
    try:
        import frida  # type: ignore
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    try:
        device = frida.get_local_device()
        session = device.attach(pid)
        session.detach()
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, help="Optional PID to test Frida attach")
    ap.add_argument("--json", action="store_true", help="Emit JSON only (default)")
    return ap


def main(argv: Optional[list[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    repo_root = path_utils.find_repo_root()
    world_id = baseline_world_id(repo_root)
    python_exec = Path(sys.executable)
    report: Dict[str, object] = {
        "schema_version": 1,
        "world_id": world_id,
        "python_executable": path_utils.to_repo_relative(python_exec, repo_root),
        "frida_import": _frida_version(),
        "codesign_entitlements": _codesign_entitlements(python_exec),
        "xcode_select": _run_cmd(["xcode-select", "-p"]),
    }
    if args.pid:
        report["attach_test"] = {"pid": args.pid, **_try_attach(args.pid)}

    print(json.dumps(report, indent=2, sort_keys=True))
    if args.pid and isinstance(report.get("attach_test"), dict):
        if not report["attach_test"].get("ok"):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
