#!/usr/bin/env python3
"""
Anchor-based scan: map known anchor literals to nodes and field2 values.

Given:
- Probes/system profiles (.sb.bin)
- A map of anchor strings per profile (JSON)

This script:
- Decodes profiles with decoder
- Finds literal occurrences of anchor strings
- Collects node indices whose byte ranges overlap the anchor strings
- Reports field2/tag values for those nodes

Outputs:
- out/anchor_hits.json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List, Tuple

import sys

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
from book.api.profile import decoder  # type: ignore
from book.api.profile import digests as digests_mod  # type: ignore
from book.api.profile import ingestion as pi  # type: ignore
from book.api import path_utils, tooling

REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())

WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
SCHEMA_VERSION = "probe-op-structure.anchor_hits.v1"
RECEIPT_SCHEMA_VERSION = "probe-op-structure.anchor_hits.receipt.v1"

ANCHOR_MAP_PATH = REPO_ROOT / "book/evidence/experiments/field2-final-final/probe-op-structure/anchor_map.json"
FILTERS_PATH = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json"
PROFILES_DIR = REPO_ROOT / "book/evidence/experiments/field2-final-final/probe-op-structure/sb/build"
OUT_DIR = REPO_ROOT / "book/evidence/experiments/field2-final-final/probe-op-structure/out"
OUT_PATH = OUT_DIR / "anchor_hits.json"
RECEIPT_PATH = OUT_DIR / "anchor_hits_receipt.json"


def _rel(path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def load_filter_names() -> Dict[int, str]:
    filters = json.loads(FILTERS_PATH.read_text())
    return {e["id"]: e["name"] for e in filters.get("filters", [])}


def find_anchor_offsets(buf: bytes, anchor: bytes) -> List[int]:
    """Return all offsets where anchor appears in a buffer."""
    offsets: List[int] = []
    start = 0
    while True:
        idx = buf.find(anchor, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets


def nodes_touching_u16_offsets(nodes_bytes: bytes, anchor_offsets: List[int], literal_start: int, stride: int = 8) -> List[int]:
    """
    Search raw node bytes for u16 fields that match known literal offsets.

    This stays deliberately conservative:
    - only checks u16-aligned slots within each stride-sized record
    - skips relative offset 0 (too ambiguous; many records contain 0-valued u16s)
    """
    targets: set[int] = set()
    for off in anchor_offsets:
        if off != 0:
            targets.add(off)
        abs_off = literal_start + off
        if 0 < abs_off < 0x1_0000:
            targets.add(abs_off)

    if not targets:
        return []

    hits: List[int] = []
    full = len(nodes_bytes) // stride
    for idx in range(full):
        chunk = nodes_bytes[idx * stride : (idx + 1) * stride]
        # record prefix is tag/kind; u16 fields follow at offsets 2/4/6
        if len(chunk) < 8:
            continue
        f0 = int.from_bytes(chunk[2:4], "little")
        f1 = int.from_bytes(chunk[4:6], "little")
        f2 = int.from_bytes(chunk[6:8], "little")
        if f0 in targets or f1 in targets or f2 in targets:
            hits.append(idx)
    return hits


def extract_strings(buf: bytes, min_len: int = 4) -> List[Tuple[int, str]]:
    """Extract printable runs from a buffer with their offsets."""
    out: List[Tuple[int, str]] = []
    start = None
    cur: List[int] = []
    for idx, b in enumerate(buf):
        if 32 <= b <= 126:
            if start is None:
                start = idx
            cur.append(b)
        else:
            if cur and len(cur) >= min_len and start is not None:
                out.append((start, bytes(cur).decode("ascii", errors="ignore")))
            start = None
            cur = []
    if cur and len(cur) >= min_len and start is not None:
        out.append((start, bytes(cur).decode("ascii", errors="ignore")))
    return out


def _strip_prefix(s: str) -> str:
    """Drop leading non-path, non-alnum characters."""
    while s and not s[0].isalnum() and s[0] not in ("/", "."):
        s = s[1:]
    return s


def _strip_sbpl_literal_prefix(s: str) -> str:
    """
    SBPL literal strings in compiled blobs often carry a single leading tag byte
    rendered as an ASCII letter (e.g. `Ftmp/foo`, `Hetc/hosts`, `QIOUSB…`).

    Drop that single-letter prefix for matching, while keeping the original
    string available for debugging/output.
    """
    if len(s) >= 2 and s[0].isalpha() and s[0].isupper() and (s[1].isalnum() or s[1] in ("/", ".")):
        return s[1:]
    return s


def _matches_anchor(anchor: str, literal: str) -> bool:
    """Heuristic match between anchor (often absolute) and prefixed literal."""
    anchor_no_slash = anchor.lstrip("/")
    if anchor in literal:
        return True
    stripped = _strip_sbpl_literal_prefix(_strip_prefix(literal))
    if (anchor in stripped) or (anchor_no_slash and anchor_no_slash in stripped):
        return True
    # Some SBPL literal pools compress leading "IO" prefixes into control bytes,
    # yielding strings like "SurfaceRootUserClient" for "IOSurfaceRootUserClient".
    if anchor.startswith("IO") and anchor[2:] and anchor[2:] in stripped:
        return True
    # Path anchors are sometimes stored as segmented literals (e.g. `tmp/` + `foo`).
    if anchor.startswith("/") and anchor_no_slash and "/" in anchor_no_slash:
        parts = [p for p in anchor_no_slash.split("/") if p]
        tokens = set(parts)
        tokens.update(f"{p}/" for p in parts)
        if stripped in tokens:
            return True
    return False


def summarize(profile_path: Path, anchors: List[str], filter_names: Dict[int, str]) -> Dict[str, Any]:
    blob = profile_path.read_bytes()
    # Decode for high-level counts/strings
    dec = decoder.decode_profile_dict(blob)
    literal_strings = dec.get("literal_strings") or []
    literal_strings_with_offsets = dec.get("literal_strings_with_offsets") or []
    nodes_decoded = dec.get("nodes") or []

    # Slice raw sections for byte-level scans
    pb = pi.ProfileBlob(bytes=blob, source=profile_path.name)
    header = pi.parse_header(pb)
    sections = pi.slice_sections(pb, header)
    literal_pool = sections.regex_literals
    literal_start = len(blob) - len(literal_pool)
    nodes_bytes = sections.nodes
    literal_strings = extract_strings(literal_pool)

    anchor_hits = []
    for anchor in sorted({a for a in anchors if isinstance(a, str)}):
        a_bytes = anchor.encode()
        offsets_lit = find_anchor_offsets(literal_pool, a_bytes)
        # Also match offsets from decoder literal_strings_with_offsets for substring anchors.
        for off, s in literal_strings_with_offsets:
            if _matches_anchor(anchor, s):
                if off not in offsets_lit:
                    offsets_lit.append(off)
        byte_hits = nodes_touching_u16_offsets(nodes_bytes, offsets_lit, literal_start, stride=8)
        # also try matching by string index in literal_strings list
        string_index = None
        for idx, (off, s) in enumerate(literal_strings):
            if anchor in s or s in anchor:
                string_index = idx
                break
        # literal_refs-based hits from decoded nodes (preferred)
        ref_hits: List[int] = []
        for idx, node in enumerate(nodes_decoded):
            for ref in node.get("literal_refs", []):
                if _matches_anchor(anchor, ref):
                    ref_hits.append(idx)
                    break
        # Prefer decoded literal_refs when the anchor has non-zero offsets; fall back
        # to byte-level u16 offset scans for offset-0 (ambiguous) anchors.
        if ref_hits and (0 not in offsets_lit):
            node_idxs = sorted(set(ref_hits))
        elif ref_hits and byte_hits:
            node_idxs = sorted(set(ref_hits) & set(byte_hits))
        elif byte_hits:
            node_idxs = sorted(set(byte_hits))
        else:
            node_idxs = sorted(set(ref_hits))
        field2_vals = []
        node_u16_roles: List[str | None] = []
        for idx in node_idxs:
            if idx < len(nodes_decoded):
                fields = nodes_decoded[idx].get("fields", [])
                if len(fields) > 2:
                    field2_vals.append(fields[2])
                node_u16_roles.append(nodes_decoded[idx].get("u16_role"))
            else:
                node_u16_roles.append(None)
        field2_vals = sorted({int(val) for val in field2_vals if isinstance(val, int)})
        anchor_hits.append(
            {
                "anchor": anchor,
                "offsets": offsets_lit,
                "literal_offsets": offsets_lit,
                "literal_string_index": string_index,
                "node_indices": node_idxs,
                "field2_values": field2_vals,
                "field2_names": [filter_names.get(v) for v in field2_vals if v in filter_names],
                "node_u16_roles": node_u16_roles,
            }
        )

    return {
        "op_count": dec.get("op_count"),
        "node_count": dec.get("node_count"),
        "anchors": anchor_hits,
        "literal_strings_sample": literal_strings[:10],
    }


def main() -> None:
    filter_names = load_filter_names()
    anchors_map = json.loads(ANCHOR_MAP_PATH.read_text())
    canonical = digests_mod.canonical_system_profile_blobs(REPO_ROOT)
    sys_profiles = {"sys:airlock": canonical["airlock"], "sys:bsd": canonical["bsd"], "sys:sample": canonical["sample"]}
    outputs: Dict[str, Any] = {}
    profile_sources: Dict[str, Dict[str, str]] = {}

    for name, anchors in sorted(anchors_map.items()):
        p = PROFILES_DIR / f"{name}.sb.bin"
        if not p.exists():
            continue
        profile_id = f"probe:{name}"
        outputs[profile_id] = summarize(p, anchors, filter_names)
        profile_sources[profile_id] = {
            "path": _rel(p),
            "sha256": tooling.sha256_path(p),
        }

    for name, p in sorted(sys_profiles.items()):
        if not p.exists():
            continue
        outputs[name] = summarize(p, anchors_map.get(name, []), filter_names)
        profile_sources[name] = {"path": _rel(p), "sha256": tooling.sha256_path(p)}

    outputs["metadata"] = {
        "schema_version": SCHEMA_VERSION,
        "world_id": WORLD_ID,
        "inputs": {
            "anchor_map": {"path": _rel(ANCHOR_MAP_PATH), "sha256": tooling.sha256_path(ANCHOR_MAP_PATH)},
            "filters_vocab": {"path": _rel(FILTERS_PATH), "sha256": tooling.sha256_path(FILTERS_PATH)},
            "profiles": profile_sources,
        },
        "command": path_utils.relativize_command(sys.argv, repo_root=REPO_ROOT),
    }

    OUT_DIR.mkdir(exist_ok=True)
    OUT_PATH.write_text(json.dumps(outputs, indent=2, sort_keys=True))
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool": "probe-op-structure.anchor_scan",
        "world_id": WORLD_ID,
        "inputs": outputs["metadata"]["inputs"],
        "outputs": {
            "anchor_hits": _rel(OUT_PATH),
            "receipt": _rel(RECEIPT_PATH),
        },
        "command": outputs["metadata"]["command"],
    }
    RECEIPT_PATH.write_text(json.dumps(receipt, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_PATH}")
    print(f"[+] wrote {RECEIPT_PATH}")


if __name__ == "__main__":
    main()
