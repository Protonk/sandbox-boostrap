#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional
import ctypes

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative  # type: ignore
from book.api.profile import compile as compile_mod  # type: ignore
from book.api.profile.compile import libsandbox  # type: ignore

DEFAULT_SANDBOX_PATH = "/usr/lib/libsandbox.1.dylib"


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _write_json(payload: object, *, stream: Optional[object] = None) -> None:
    out = json.dumps(payload, sort_keys=True)
    if stream is None:
        sys.stdout.write(out + "\n")
    else:
        stream.write(out + "\n")


def _parse_params(raw: Optional[str]) -> Optional[dict]:
    if not raw:
        return None
    value = json.loads(raw)
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    raise ValueError("params must be a JSON object mapping string keys to string values")


def _emit_error(
    *,
    input_path: Path,
    out_blob: Path,
    mode: str,
    params: Optional[dict],
    error_stage: str,
    error: str,
) -> int:
    payload = {
        "status": "error",
        "input": to_repo_relative(input_path, find_repo_root()),
        "out_blob": to_repo_relative(out_blob, find_repo_root()),
        "mode": mode,
        "params": params,
        "error_stage": error_stage,
        "error": error,
    }
    _write_json(payload)
    if out_blob.exists():
        out_blob.unlink()
    return 2


def main() -> int:
    ap = argparse.ArgumentParser(prog="compile-one")
    ap.add_argument("--input", required=True, help="SBPL source path (repo-relative or absolute)")
    ap.add_argument("--out-blob", required=True, help="Output compiled blob path")
    ap.add_argument(
        "--compile-mode",
        choices=("file", "string"),
        default="file",
        help="Compile via sandbox_compile_file or sandbox_compile_string",
    )
    ap.add_argument(
        "--params",
        default=None,
        help="Compile params as a JSON object (e.g. '{\"ROOT\":\"/private/tmp\"}')",
    )
    args = ap.parse_args()

    repo_root = find_repo_root()
    input_path = ensure_absolute(args.input, repo_root)
    out_blob = ensure_absolute(args.out_blob, repo_root)
    try:
        params = _parse_params(args.params)
    except Exception as exc:
        return _emit_error(
            input_path=input_path,
            out_blob=out_blob,
            mode=args.compile_mode,
            params=None,
            error_stage="parse_params",
            error=str(exc),
        )

    sandbox_path = os.environ.get("SBPL_SANDBOX_PATH")
    lib = None
    if sandbox_path and sandbox_path != DEFAULT_SANDBOX_PATH:
        sandbox_abs = ensure_absolute(Path(sandbox_path), repo_root)
        if not sandbox_abs.exists():
            return _emit_error(
                input_path=input_path,
                out_blob=out_blob,
                mode=args.compile_mode,
                params=params,
                error_stage="sandbox_path",
                error=f"SBPL_SANDBOX_PATH does not exist: {sandbox_path}",
            )
        try:
            lib = ctypes.CDLL(str(sandbox_abs))
        except OSError as exc:
            return _emit_error(
                input_path=input_path,
                out_blob=out_blob,
                mode=args.compile_mode,
                params=params,
                error_stage="load_libsandbox",
                error=f"failed to load libsandbox from {sandbox_path}: {exc}",
            )
    else:
        try:
            lib = libsandbox.load_libsandbox()
        except Exception as exc:
            return _emit_error(
                input_path=input_path,
                out_blob=out_blob,
                mode=args.compile_mode,
                params=params,
                error_stage="load_libsandbox",
                error=str(exc),
            )

    try:
        if args.compile_mode == "string":
            try:
                sbpl_text = input_path.read_text()
            except Exception as exc:
                return _emit_error(
                    input_path=input_path,
                    out_blob=out_blob,
                    mode=args.compile_mode,
                    params=params,
                    error_stage="read_input",
                    error=str(exc),
                )
            result = compile_mod.compile_sbpl_string(sbpl_text, lib=lib, params=params)
            out_blob.parent.mkdir(parents=True, exist_ok=True)
            out_blob.write_bytes(result.blob)
        else:
            result = compile_mod.compile_sbpl_file(input_path, out_blob, lib=lib, params=params)
    except Exception as exc:
        return _emit_error(
            input_path=input_path,
            out_blob=out_blob,
            mode=args.compile_mode,
            params=params,
            error_stage="compile",
            error=str(exc),
        )

    payload = {
        "status": "ok",
        "input": to_repo_relative(input_path, repo_root),
        "out_blob": to_repo_relative(out_blob, repo_root),
        "mode": args.compile_mode,
        "params": params,
        "length": result.length,
        "profile_type": result.profile_type,
        "blob_sha256": _sha256_bytes(result.blob),
    }
    _write_json(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
