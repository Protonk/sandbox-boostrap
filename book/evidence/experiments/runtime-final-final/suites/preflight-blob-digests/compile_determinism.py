#!/usr/bin/env python3
"""
Check whether compiled blob digests are:
- deterministic across repeated compiles on this world, and
- consistent across compilation surfaces (Python `book.api.profile` vs SBPL-wrapper).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile import compile as pt_compile  # type: ignore
from book.api.profile import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1

WRAPPER = REPO_ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run_wrapper_compile(sbpl_path: Path, out_blob: Path) -> Dict[str, Any]:
    sbpl_abs = sbpl_path.resolve()
    cmd = [str(WRAPPER), "--compile", str(sbpl_abs), "--out", str(out_blob)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    stderr = proc.stderr or ""
    # Keep this script static-ish: do not interpret full marker streams here.
    return {"cmd": [cmd[0], cmd[1], _rel(sbpl_abs), cmd[3], _rel(out_blob)], "rc": proc.returncode, "stderr": stderr}


def _compile_with_python(sbpl_path: Path) -> Dict[str, Any]:
    result = pt_compile.compile_sbpl_file(sbpl_path)
    return {
        "profile_type": int(result.profile_type),
        "bytecode_length": int(result.length),
        "sha256": _sha256_bytes(result.blob),
    }


def _compile_with_wrapper(sbpl_path: Path) -> Dict[str, Any]:
    with tempfile.TemporaryDirectory() as td:
        out_blob = Path(td) / "out.sb.bin"
        run = _run_wrapper_compile(sbpl_path, out_blob)
        sha = _sha256_bytes(out_blob.read_bytes()) if out_blob.exists() else None
        return {
            "compile_run": run,
            "sha256": sha,
        }


def _all_equal(values: List[Optional[str]]) -> bool:
    concrete = [v for v in values if v is not None]
    return bool(concrete) and all(v == concrete[0] for v in concrete)


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="compile_determinism")
    ap.add_argument("--sbpl", action="append", default=[], help="SBPL .sb path (repeatable)")
    ap.add_argument("--runs", type=int, default=5, help="repeated compiles per surface")
    ap.add_argument("--out", type=Path, required=True, help="output JSON path")
    args = ap.parse_args(argv)

    if not args.sbpl:
        raise SystemExit("provide at least one --sbpl input")
    if not WRAPPER.exists():
        raise SystemExit(f"missing wrapper binary: {WRAPPER}")

    world_id = identity_mod.baseline_world_id()

    cases: List[Dict[str, Any]] = []
    for sbpl_str in args.sbpl:
        sbpl_path = Path(sbpl_str)
        if not sbpl_path.exists():
            raise FileNotFoundError(sbpl_path)

        python_runs = [_compile_with_python(sbpl_path) for _ in range(args.runs)]
        wrapper_runs = [_compile_with_wrapper(sbpl_path) for _ in range(args.runs)]

        python_digests = [r["sha256"] for r in python_runs]
        wrapper_digests = [r.get("sha256") for r in wrapper_runs]
        python_det = _all_equal(python_digests)
        wrapper_det = _all_equal(wrapper_digests)

        parity_ok = python_det and wrapper_det and python_digests[0] == wrapper_digests[0]

        cases.append(
            {
                "sbpl": _rel(sbpl_path),
                "runs": args.runs,
                "python": {
                    "deterministic": python_det,
                    "sha256": python_digests,
                    "profile_type": [r["profile_type"] for r in python_runs],
                    "bytecode_length": [r["bytecode_length"] for r in python_runs],
                },
                "wrapper": {
                    "deterministic": wrapper_det,
                    "sha256": wrapper_digests,
                    "compile_runs": [r["compile_run"] for r in wrapper_runs],
                },
                "parity": {"sha256_equal": parity_ok},
            }
        )

    payload = {
        "tool": "book/evidence/experiments/runtime-final-final/suites/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {"sbpl": [c["sbpl"] for c in cases]},
        "cases": cases,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
