#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, relativize_command, to_repo_relative  # type: ignore
from book.api.profile_tools.identity import baseline_world_id  # type: ignore


def _load_inputs(path: Path) -> Mapping[str, Any]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, Mapping):
        raise ValueError("inputs.json must be a JSON object")
    return raw


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _run_compile(
    repo_root: Path,
    interposer: Path,
    compile_script: Path,
    sbpl_path: Path,
    trace_path: Path,
    out_blob: Path,
) -> Dict[str, Any]:
    env = dict(os.environ)
    env["DYLD_INSERT_LIBRARIES"] = str(interposer)
    env["DYLD_FORCE_FLAT_NAMESPACE"] = "1"
    env["SBPL_TRACE_OUT"] = str(trace_path)
    env["SBPL_TRACE_INPUT"] = to_repo_relative(sbpl_path, repo_root)

    cmd = [sys.executable, str(compile_script), "--input", str(sbpl_path), "--out-blob", str(out_blob)]
    try:
        result = subprocess.run(cmd, env=env, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as exc:
        stderr = (exc.stderr or "").strip()
        detail = f": {stderr}" if stderr else ""
        raise RuntimeError(f"compile failed for {to_repo_relative(sbpl_path, repo_root)}{detail}") from exc
    stdout = result.stdout.strip()
    if not stdout:
        raise RuntimeError("compile script produced no JSON output")
    return json.loads(stdout)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="encoder-write-trace")
    ap.add_argument(
        "--inputs",
        type=Path,
        default=Path("book/experiments/encoder-write-trace/inputs.json"),
        help="Input list (repo-relative)",
    )
    ap.add_argument(
        "--out-dir",
        type=Path,
        default=Path("book/experiments/encoder-write-trace/out"),
        help="Output directory (repo-relative)",
    )
    ap.add_argument("--skip-build", action="store_true", help="Skip interposer build")
    args = ap.parse_args(argv)

    repo_root = find_repo_root()
    inputs_path = ensure_absolute(args.inputs, repo_root)
    out_dir = ensure_absolute(args.out_dir, repo_root)

    inputs = _load_inputs(inputs_path)
    expected_world = baseline_world_id(repo_root)
    if inputs.get("world_id") != expected_world:
        raise ValueError(f"inputs.json world_id mismatch: {inputs.get('world_id')} != {expected_world}")

    build_script = ensure_absolute(Path("book/experiments/encoder-write-trace/harness/build_interposer.sh"), repo_root)
    interposer = ensure_absolute(Path("book/experiments/encoder-write-trace/out/interposer/sbpl_trace_interpose.dylib"), repo_root)
    if not args.skip_build:
        subprocess.check_call([str(build_script)], cwd=repo_root)

    compile_script = ensure_absolute(Path("book/experiments/encoder-write-trace/compile_one.py"), repo_root)

    traces_dir = out_dir / "traces"
    blobs_dir = out_dir / "blobs"
    traces_dir.mkdir(parents=True, exist_ok=True)
    blobs_dir.mkdir(parents=True, exist_ok=True)

    entries: List[Dict[str, Any]] = []
    for entry in inputs.get("inputs", []):
        if not isinstance(entry, Mapping):
            continue
        entry_id = entry.get("id")
        sbpl_rel = entry.get("sbpl")
        if not isinstance(entry_id, str) or not isinstance(sbpl_rel, str):
            continue

        sbpl_path = ensure_absolute(Path(sbpl_rel), repo_root)
        trace_path = traces_dir / f"{entry_id}.jsonl"
        out_blob = blobs_dir / f"{entry_id}.sb.bin"

        if trace_path.exists():
            trace_path.unlink()

        compile_result = _run_compile(repo_root, interposer, compile_script, sbpl_path, trace_path, out_blob)

        entries.append(
            {
                "id": entry_id,
                "sbpl": to_repo_relative(sbpl_path, repo_root),
                "trace": to_repo_relative(trace_path, repo_root),
                "blob": to_repo_relative(out_blob, repo_root),
                "compile": compile_result,
            }
        )

    manifest = {
        "world_id": expected_world,
        "inputs": entries,
        "inputs_file": to_repo_relative(inputs_path, repo_root),
        "trace_harness": {
            "interposer": to_repo_relative(interposer, repo_root),
            "compile_command": relativize_command(
                [sys.executable, compile_script, "--input", "<sbpl>", "--out-blob", "<blob>"],
                repo_root,
            ),
            "env": {
                "DYLD_INSERT_LIBRARIES": to_repo_relative(interposer, repo_root),
                "DYLD_FORCE_FLAT_NAMESPACE": "1",
            },
        },
    }

    summary = {
        "world_id": expected_world,
        "counts": {
            "inputs": len(entries),
            "traces": len(entries),
            "blobs": len(entries),
        },
    }

    _write_json(out_dir / "manifest.json", manifest)
    _write_json(out_dir / "summary.json", summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
