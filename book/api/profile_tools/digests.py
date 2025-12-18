"""
Decoder-backed digest helpers for compiled sandbox blobs (Sonoma baseline).

This module provides a reusable home for the digest logic originally implemented
in the experiment:
- `book/experiments/system-profile-digest/run.py`
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from book.api.path_utils import find_repo_root, to_repo_relative

from . import decoder

_DEFAULT_DIGEST_KEYS = {
    "format_variant",
    "op_count",
    "op_table_offset",
    "op_table",
    "node_count",
    "tag_counts",
    "literal_strings",
    "literal_strings_with_offsets",
    "sections",
    "validation",
}


def canonical_system_profile_blobs(repo_root: Path | None = None) -> dict[str, Path]:
    """
    Return the curated canonical system profile blob paths for this world.

    Keys match the historical experiment output (`airlock`, `bsd`, `sample`) so
    the validation job can normalize them to `sys:<name>` without changing shape.
    """
    root = repo_root or find_repo_root()
    return {
        "airlock": root / "book/examples/extract_sbs/build/profiles/airlock.sb.bin",
        "bsd": root / "book/examples/extract_sbs/build/profiles/bsd.sb.bin",
        "sample": root / "book/examples/sb/build/sample.sb.bin",
    }


def digest_compiled_blob_bytes(blob: bytes, *, source: str | None = None) -> dict[str, Any]:
    """
    Return a stable, JSON-serializable digest for a compiled profile blob.

    Digest content is derived from `book.api.profile_tools.decoder` and is meant
    to be stable across callers (experiments, validation, ad-hoc tooling).
    """
    decoded = decoder.decode_profile_dict(blob)
    body = {k: decoded[k] for k in sorted(_DEFAULT_DIGEST_KEYS) if k in decoded}
    if source is not None:
        body["source"] = source
    return body


def digest_compiled_blob_path(path: Path, *, repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or find_repo_root()
    if not path.exists():
        raise FileNotFoundError(f"missing compiled blob: {path}")
    return digest_compiled_blob_bytes(path.read_bytes(), source=to_repo_relative(path, root))


def digest_named_blobs(blobs: Mapping[str, Path], *, repo_root: Path | None = None) -> dict[str, Any]:
    root = repo_root or find_repo_root()
    payload: dict[str, Any] = {}
    for name, path in blobs.items():
        payload[str(name)] = digest_compiled_blob_path(path, repo_root=root)
    return payload


def write_digests_json(payload: Mapping[str, Any], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True))

