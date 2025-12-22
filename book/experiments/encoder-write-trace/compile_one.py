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
from book.api.profile_tools import compile as compile_mod  # type: ignore

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


def main() -> int:
    ap = argparse.ArgumentParser(prog="compile-one")
    ap.add_argument("--input", required=True, help="SBPL source path (repo-relative or absolute)")
    ap.add_argument("--out-blob", required=True, help="Output compiled blob path")
    args = ap.parse_args()

    repo_root = find_repo_root()
    input_path = ensure_absolute(args.input, repo_root)
    out_blob = ensure_absolute(args.out_blob, repo_root)

    sandbox_path = os.environ.get("SBPL_SANDBOX_PATH")
    lib = None
    if sandbox_path and sandbox_path != DEFAULT_SANDBOX_PATH:
        sandbox_abs = ensure_absolute(Path(sandbox_path), repo_root)
        if not sandbox_abs.exists():
            raise RuntimeError(f"SBPL_SANDBOX_PATH does not exist: {sandbox_path}")
        try:
            lib = ctypes.CDLL(str(sandbox_abs))
        except OSError as exc:
            raise RuntimeError(f"failed to load libsandbox from {sandbox_path}: {exc}") from exc

    result = compile_mod.compile_sbpl_file(input_path, out_blob, lib=lib)
    payload = {
        "input": to_repo_relative(input_path, repo_root),
        "out_blob": to_repo_relative(out_blob, repo_root),
        "length": result.length,
        "profile_type": result.profile_type,
        "blob_sha256": _sha256_bytes(result.blob),
    }
    _write_json(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
