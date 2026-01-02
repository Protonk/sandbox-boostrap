#!/usr/bin/env python3
"""
Generate profile attestations for canonical blobs on this host.

Attestations tie together:
- blob metadata (sha256, lengths, format variant)
- op-table entries and tag counts
- literal strings and anchor coverage
- tag-layout/vocab/runtime linkage

Inputs:
- `book/evidence/graph/mappings/system_profiles/digests.json` (to discover system blobs)
- `book/evidence/graph/concepts/validation/out/semantic/runtime_results.json` (optional link)
- `book/evidence/graph/mappings/runtime/expectations.json` (optional link)
- `book/evidence/graph/mappings/anchors/anchor_filter_map.json`
- `book/evidence/graph/mappings/tag_layouts/tag_layouts.json`
- `book/evidence/graph/mappings/vocab/{ops,filters}.json`

Outputs:
- `book/evidence/graph/mappings/system_profiles/attestations.json`
- `book/evidence/graph/mappings/system_profiles/attestations/*.jsonl` (per-profile rows)
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

from book.api.profile import decoder
from book.api.profile.op_table import op_entries
from book.api import evidence_tiers
from book.api import world as world_mod
from book.graph.concepts.validation import profile_ingestion as pi


OUT_JSON = REPO_ROOT / "book/evidence/graph/mappings/system_profiles/attestations.json"
OUT_DIR = REPO_ROOT / "book/evidence/graph/mappings/system_profiles/attestations"
TAG_LAYOUTS_PATH = REPO_ROOT / "book/evidence/graph/mappings/tag_layouts/tag_layouts.json"
GOLDEN_TRIPLE_BLOBS_DIR = REPO_ROOT / "book/profiles/golden-triple"


def load_baseline() -> Dict[str, Any]:
    data, _resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return data


def baseline_world_info() -> tuple[str, str]:
    data, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    world_path = world_mod.world_path_for_metadata(resolution, repo_root=REPO_ROOT)
    return world_id, world_path


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


def tag_layout_tag_set_hash(path: Path) -> str:
    payload = json.loads(path.read_text())
    tags = {"tags": payload.get("tags")}
    return hashlib.sha256(json.dumps(tags, sort_keys=True).encode()).hexdigest()


def gather_profile_paths() -> Set[Path]:
    paths: Set[Path] = set()
    digests = load_json(REPO_ROOT / "book/evidence/graph/mappings/system_profiles/digests.json")
    profiles = digests.get("profiles") if isinstance(digests, dict) else None
    if isinstance(profiles, dict):
        for rec in profiles.values():
            if not isinstance(rec, dict):
                continue
            src = rec.get("source")
            if not src:
                continue
            p = (REPO_ROOT / src).resolve()
            if p.exists():
                paths.add(p)
    for p in sorted(GOLDEN_TRIPLE_BLOBS_DIR.glob("*.sb.bin")):
        if p.exists():
            paths.add(p.resolve())
    return paths


@dataclass
class Attestation:
    profile_id: str
    canonical_profile_id: Optional[str]
    role: str
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
    canonical_profile_id: Optional[str],
    role: str,
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
        canonical_profile_id=canonical_profile_id,
        role=role,
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
    world_id, world_path = baseline_world_info()
    # Reporting-only: this generator records which known anchor literals appear in
    # a profile's literal table. The literal-keyed anchor filter map is a derived,
    # lossy compatibility view; do not treat it as a unique binding when making
    # decisions (use the ctx-indexed canonical mapping instead).
    anchor_map = load_json(REPO_ROOT / "book/evidence/graph/mappings/anchors/anchor_filter_map.json")
    tag_layout_hash = tag_layout_tag_set_hash(TAG_LAYOUTS_PATH)
    tag_layouts_file_sha256 = sha256(TAG_LAYOUTS_PATH)
    vocab_ops = load_json(REPO_ROOT / "book/evidence/graph/mappings/vocab/ops.json")
    vocab_filters = load_json(REPO_ROOT / "book/evidence/graph/mappings/vocab/filters.json")
    runtime_manifest = load_json(REPO_ROOT / "book/evidence/graph/mappings/runtime/expectations.json")
    digests = load_json(REPO_ROOT / "book/evidence/graph/mappings/system_profiles/digests.json")
    canonical_by_source: Dict[str, str] = {}
    for pid, body in (digests.get("profiles") or {}).items():
        if not isinstance(body, dict):
            continue
        src = body.get("source")
        if isinstance(pid, str) and isinstance(src, str):
            canonical_by_source[src] = pid

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

    for existing in OUT_DIR.glob("*.jsonl"):
        existing.unlink()

    for path in profiles_seen:
        source_rel = str(path.relative_to(REPO_ROOT))
        canonical_profile_id = canonical_by_source.get(source_rel)
        role = "canonical-system-profile" if canonical_profile_id else "golden-profile"
        att = make_attestation(
            path=path,
            canonical_profile_id=canonical_profile_id,
            role=role,
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
        "tag_layout_hash_method": "tag_set",
        "tag_layouts_file_sha256": tag_layouts_file_sha256,
        "vocab_versions": vocab_versions,
        "runtime_manifest": str(Path("book/evidence/graph/mappings/runtime/expectations.json")) if runtime_manifest else None,
        "attestation_count": len(attestations),
        "inputs": [
            world_path,
            str(Path("book/evidence/graph/mappings/system_profiles/digests.json")),
            str(Path("book/evidence/graph/mappings/anchors/anchor_filter_map.json")),
            str(Path("book/evidence/graph/mappings/tag_layouts/tag_layouts.json")),
            str(Path("book/evidence/graph/mappings/vocab/ops.json")),
            str(Path("book/evidence/graph/mappings/vocab/filters.json")),
            str(Path("book/evidence/graph/mappings/runtime/expectations.json")),
        ]
        + [str(p.relative_to(REPO_ROOT)) for p in sorted(GOLDEN_TRIPLE_BLOBS_DIR.glob("*.sb.bin")) if p.exists()],
        "source_jobs": ["generator:system_profiles:attestations"],
        "status": "ok",
        "tier": evidence_tiers.evidence_tier_for_artifact(
            path=OUT_JSON,
        ),
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
