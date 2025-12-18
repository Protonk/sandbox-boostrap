#!/usr/bin/env python3
"""
Generate profile attestations for canonical blobs on this host.

Attestations tie together:
- blob metadata (sha256, lengths, format variant)
- op-table entries and tag counts
- literal strings and anchor coverage
- tag-layout/vocab/runtime linkage

Inputs:
- `book/graph/mappings/system_profiles/digests.json` (to discover system blobs)
- `book/graph/concepts/validation/out/semantic/runtime_results.json` (optional link)
- `book/graph/mappings/runtime/expectations.json` (optional link)
- `book/graph/mappings/anchors/anchor_filter_map.json`
- `book/graph/mappings/tag_layouts/tag_layouts.json`
- `book/graph/mappings/vocab/{ops,filters}.json`

Outputs:
- `book/graph/mappings/system_profiles/attestations.json`
- `book/graph/mappings/system_profiles/attestations/*.jsonl` (per-profile rows)
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.profile_tools import decoder
from book.api.op_table import op_entries
from book.graph.concepts.validation import profile_ingestion as pi


OUT_JSON = REPO_ROOT / "book/graph/mappings/system_profiles/attestations.json"
OUT_DIR = REPO_ROOT / "book/graph/mappings/system_profiles/attestations"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"


def load_baseline() -> Dict[str, Any]:
    baseline_path = REPO_ROOT / BASELINE_REF
    if not baseline_path.exists():
        raise FileNotFoundError(f"missing baseline: {baseline_path}")
    return json.loads(baseline_path.read_text())


def baseline_world_id() -> str:
    data = load_baseline()
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def ascii_strings(buf: bytes, min_len: int = 4, limit: int = 64) -> List[str]:
    runs: List[str] = []
    start: Optional[int] = None
    current: List[str] = []
    for byte in buf:
        if 0x20 <= byte < 0x7F:
            if start is None:
                start = 0  # placeholder; not used further
            current.append(chr(byte))
        else:
            if current and len(current) >= min_len:
                runs.append("".join(current))
                if len(runs) >= limit:
                    return runs
            start = None
            current = []
    if current and len(current) >= min_len:
        runs.append("".join(current))
    return runs[:limit]


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def gather_profile_paths() -> Set[Path]:
    paths: Set[Path] = set()
    digests = load_json(REPO_ROOT / "book/graph/mappings/system_profiles/digests.json")
    for rec in digests.values():
        if not isinstance(rec, dict):
            continue
        src = rec.get("source")
        if src:
            p = (REPO_ROOT / src).resolve()
            if p.exists():
                paths.add(p)
    runtime_exp = load_json(REPO_ROOT / "book/graph/mappings/runtime/expectations.json")
    for rec in runtime_exp.get("profiles", []):
        p = rec.get("profile_path")
        if p:
            path = (REPO_ROOT / p).resolve()
            if path.exists():
                paths.add(path)
    return paths


@dataclass
class Attestation:
    profile_id: str
    source: str
    sha256: str
    length: int
    format_variant: Optional[str]
    op_count: Optional[int]
    op_entries: List[int]
    tag_counts: Dict[str, int]
    sections: Dict[str, int]
    literal_strings: List[str]
    anchors: List[Dict[str, Any]]
    tag_layout_version: str
    vocab_versions: Dict[str, Any]
    runtime_link: Optional[Dict[str, Any]]


def match_runtime_link(profile_sha: str, runtime_manifest: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    for rec in runtime_manifest.get("profiles", []):
        if rec.get("profile_sha256") == profile_sha:
            return {
                "profile_id": rec.get("profile_id"),
                "status": rec.get("status"),
                "trace_path": rec.get("trace_path"),
            }
    return None


def anchor_hits(strings: List[str], anchor_map: Dict[str, Any]) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    literals = strings
    for anchor, meta in anchor_map.items():
        if anchor == "metadata":
            continue
        if any(anchor in lit for lit in literals):
            hits.append(
                {
                    "anchor": anchor,
                    "filter_id": meta.get("filter_id"),
                    "filter_name": meta.get("filter_name"),
                    "status": meta.get("status"),
                }
            )
    return hits


def make_attestation(
    path: Path,
    anchor_map: Dict[str, Any],
    tag_layout_hash: str,
    vocab_versions: Dict[str, Any],
    runtime_manifest: Dict[str, Any],
) -> Attestation:
    blob = path.read_bytes()
    header = pi.parse_header(pi.ProfileBlob(bytes=blob, source=path.name))
    sections = pi.slice_sections(pi.ProfileBlob(bytes=blob, source=path.name), header)
    op_entries_list: List[int] = []
    if header.operation_count:
        op_entries_list = op_entries(blob, header.operation_count)
    decoded = decoder.decode_profile_dict(blob)
    tags = decoded.get("tag_counts") or {}
    literals = ascii_strings(sections.regex_literals or b"")
    anchor_list = anchor_hits(literals, anchor_map)
    runtime_link = match_runtime_link(sha256(path), runtime_manifest)
    return Attestation(
        profile_id=path.stem,
        source=str(path.relative_to(REPO_ROOT)),
        sha256=sha256(path),
        length=len(blob),
        format_variant=header.format_variant,
        op_count=header.operation_count,
        op_entries=op_entries_list,
        tag_counts={str(k): v for k, v in tags.items()},
        sections={
            "op_table": len(sections.op_table),
            "nodes": len(sections.nodes),
            "literals": len(sections.regex_literals),
        },
        literal_strings=literals,
        anchors=anchor_list,
        tag_layout_version=tag_layout_hash,
        vocab_versions=vocab_versions,
        runtime_link=runtime_link,
    )


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    world_id = baseline_world_id()
    anchor_map = load_json(REPO_ROOT / "book/graph/mappings/anchors/anchor_filter_map.json")
    tag_layout_hash = sha256(REPO_ROOT / "book/graph/mappings/tag_layouts/tag_layouts.json")
    vocab_ops = load_json(REPO_ROOT / "book/graph/mappings/vocab/ops.json")
    vocab_filters = load_json(REPO_ROOT / "book/graph/mappings/vocab/filters.json")
    runtime_manifest = load_json(REPO_ROOT / "book/graph/mappings/runtime/expectations.json")

    def vocab_version(entries: Any) -> Optional[str]:
        if not entries:
            return None
        payload = json.dumps(entries, sort_keys=True).encode()
        return hashlib.sha256(payload).hexdigest()

    vocab_versions = {
        "ops_version": vocab_version(vocab_ops.get("ops")),
        "filters_version": vocab_version(vocab_filters.get("filters")),
    }

    attestations: List[Dict[str, Any]] = []
    profiles_seen = sorted(gather_profile_paths())

    for path in profiles_seen:
        att = make_attestation(
            path=path,
            anchor_map=anchor_map,
            tag_layout_hash=tag_layout_hash,
            vocab_versions=vocab_versions,
            runtime_manifest=runtime_manifest,
        )
        attestations.append(asdict(att))
        out_trace = OUT_DIR / f"{path.stem}.jsonl"
        out_trace.write_text(json.dumps(asdict(att), indent=2, sort_keys=True))

    metadata = {
        "world_id": world_id,
        "tag_layout_hash": tag_layout_hash,
        "vocab_versions": vocab_versions,
        "runtime_manifest": str(Path("book/graph/mappings/runtime/expectations.json")) if runtime_manifest else None,
        "attestation_count": len(attestations),
        "inputs": [
            str(Path(BASELINE_REF)),
            str(Path("book/graph/mappings/system_profiles/digests.json")),
            str(Path("book/graph/mappings/anchors/anchor_filter_map.json")),
            str(Path("book/graph/mappings/tag_layouts/tag_layouts.json")),
            str(Path("book/graph/mappings/vocab/ops.json")),
            str(Path("book/graph/mappings/vocab/filters.json")),
            str(Path("book/graph/mappings/runtime/expectations.json")),
        ],
        "source_jobs": ["generator:system_profiles:attestations"],
        "status": "ok",
    }

    OUT_JSON.write_text(
        json.dumps(
            {
                "metadata": metadata,
                "attestations": attestations,
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(f"[+] wrote {OUT_JSON} ({len(attestations)} records)")


if __name__ == "__main__":
    main()
