"""
Decoder-backed digest helpers for compiled sandbox blobs (Sonoma baseline).

This module provides a reusable home for the digest logic originally implemented
in the experiment:
- `book/evidence/experiments/archive/system-profile-digest/`

Digests are meant to be:
- **stable** (shape and field meanings) on a fixed world baseline,
- **structural** (byte-derived facts + decoder annotations),
- **portable** across callers (experiments, validation, ad-hoc tooling).

If a digest changes on the same baseline, treat that as a signal:
either the decoder/ingestion heuristics changed or a canonical blob changed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from book.api.path_utils import find_repo_root, to_repo_relative

from .. import decoder

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
        "airlock": root / "book/evidence/syncretic/validation/fixtures/blobs/airlock.sb.bin",
        "bsd": root / "book/evidence/syncretic/validation/fixtures/blobs/bsd.sb.bin",
        "sample": root / "book/evidence/syncretic/validation/fixtures/blobs/sample.sb.bin",
    }


def digest_compiled_blob_bytes(blob: bytes, *, source: str | None = None) -> dict[str, Any]:
    """
    Return a stable, JSON-serializable digest for a compiled profile blob.

    Digest content is derived from `book.api.profile.decoder` and is meant
    to be stable across callers (experiments, validation, ad-hoc tooling).
    """
    # Decode once and then filter down to the stable key set. We keep the key
    # set small on purpose; callers needing more should use the decoder
    # directly (and accept that the output is more heuristic-heavy).
    decoded = decoder.decode_profile_dict(blob)
    body = {k: decoded[k] for k in sorted(_DEFAULT_DIGEST_KEYS) if k in decoded}
    if source is not None:
        body["source"] = source
    return body


def digest_compiled_blob_path(path: Path, *, repo_root: Path | None = None) -> dict[str, Any]:
    """
    Digest a compiled blob at `path` and include a repo-relative source label.

    The `source` field is a repo-relative path to keep digests stable across
    machines with different absolute checkout paths.
    """
    root = repo_root or find_repo_root()
    if not path.exists():
        raise FileNotFoundError(f"missing compiled blob: {path}")
    return digest_compiled_blob_bytes(path.read_bytes(), source=to_repo_relative(path, root))


def digest_named_blobs(blobs: Mapping[str, Path], *, repo_root: Path | None = None) -> dict[str, Any]:
    """
    Digest a named mapping of blobs.

    This helper preserves keys (names) so downstream jobs can normalize them to
    canonical ids (e.g. `sys:bsd`) without changing shape.
    """
    root = repo_root or find_repo_root()
    payload: dict[str, Any] = {}
    for name, path in blobs.items():
        payload[str(name)] = digest_compiled_blob_path(path, repo_root=root)
    return payload


def write_digests_json(payload: Mapping[str, Any], out_path: Path) -> None:
    """Write digests payload to disk as pretty-printed, stable JSON."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True))
