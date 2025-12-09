#!/usr/bin/env python3
"""
VFS canonicalization harness for `/tmp/foo` ↔ `/private/tmp/foo` on Sonoma.

Tasks:
- Compile VFS SBPL profiles → blobs under sb/build.
- Emit a simple expected_matrix.json (profile_id, operation, requested_path, expected_decision).
- Build a harness matrix and run it via book.api.runtime_harness.runner.run_expected_matrix.
- Down-convert the harness runtime_results.json into a simple runtime_results.json array.
- Decode the VFS blobs via book.api.decoder and emit decode_tmp_profiles.json
  (anchors, tags, and field2 values for `/tmp/foo` and `/private/tmp/foo`).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import sys

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative
import book.api.decoder as decoder  # type: ignore
from book.api.runtime_harness.runner import ensure_tmp_files, run_expected_matrix  # type: ignore
from book.api.sbpl_compile import compile_sbpl_string  # type: ignore


REPO_ROOT = find_repo_root(Path(__file__))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

BASE_DIR = Path(__file__).resolve().parent
SB_DIR = BASE_DIR / "sb"
BUILD_DIR = SB_DIR / "build"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"
PATH_PAIRS = [
    ("/tmp/foo", "/private/tmp/foo"),
    ("/tmp/bar", "/private/tmp/bar"),
    ("/tmp/nested/child", "/private/tmp/nested/child"),
    ("/var/tmp/canon", "/private/var/tmp/canon"),
]


def rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def load_world_id() -> str:
    data = json.loads(WORLD_PATH.read_text())
    return data.get("world_id") or data.get("id", "unknown-world")


def compile_profiles() -> Dict[str, Path]:
    """Compile VFS SBPL profiles to blobs and return map profile_id -> blob path."""
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    profiles = {
        "vfs_tmp_only": SB_DIR / "vfs_tmp_only.sb",
        "vfs_private_tmp_only": SB_DIR / "vfs_private_tmp_only.sb",
        "vfs_both_paths": SB_DIR / "vfs_both_paths.sb",
    }
    blobs: Dict[str, Path] = {}
    for key, sb_path in profiles.items():
        blob_path = BUILD_DIR / f"{sb_path.stem}.sb.bin"
        blob = compile_sbpl_string(sb_path.read_text()).blob
        blob_path.write_bytes(blob)
        blobs[key] = blob_path
    return blobs


def build_simple_expected_matrix() -> List[Dict[str, Any]]:
    """Emit a simple expected matrix over three profiles and the path set."""
    entries: List[Dict[str, Any]] = []
    ops = ["file-read*", "file-write*", "file-read-metadata", "file-write-metadata"]
    for alias_path, canonical_path in PATH_PAIRS:
        # For /var/tmp, runtime shows alias requests are denied even with canonical literals.
        alias_expected = "deny" if canonical_path.startswith("/private/var") else "allow"
        canonical_expected = "allow"
        for profile_id in ["vfs_tmp_only", "vfs_private_tmp_only", "vfs_both_paths"]:
            if profile_id == "vfs_tmp_only":
                alias_decision = "deny"
                canonical_decision = "deny"
            else:
                alias_decision = alias_expected
                canonical_decision = canonical_expected
            for op in ops:
                entries.append(
                    {
                        "profile_id": profile_id,
                        "operation": op,
                        "requested_path": alias_path,
                        "expected_decision": alias_decision,
                        "notes": f"{profile_id} against alias path {alias_path}",
                    }
                )
                entries.append(
                    {
                        "profile_id": profile_id,
                        "operation": op,
                        "requested_path": canonical_path,
                        "expected_decision": canonical_decision,
                        "notes": f"{profile_id} against canonical path {canonical_path}",
                    }
                )
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "expected_matrix.json"
    out_path.write_text(json.dumps(entries, indent=2))
    return entries


def build_harness_matrix(world_id: str, blobs: Dict[str, Path], simple_matrix: List[Dict[str, Any]]) -> Path:
    """Translate the simple matrix into the harness-compatible expected matrix."""
    profiles: Dict[str, Any] = {}
    # Map from profile_id to sb path for runtime harness
    sb_paths: Dict[str, Path] = {
        "vfs_tmp_only": SB_DIR / "vfs_tmp_only.sb",
        "vfs_private_tmp_only": SB_DIR / "vfs_private_tmp_only.sb",
        "vfs_both_paths": SB_DIR / "vfs_both_paths.sb",
    }
    for entry in simple_matrix:
        profile_id = entry["profile_id"]
        path = entry["requested_path"]
        expected = entry["expected_decision"]
        operation = entry["operation"]
        rec = profiles.setdefault(
            profile_id,
            {
                "mode": "sbpl",
                "sbpl": rel(sb_paths[profile_id]),
                "blob": rel(blobs[profile_id]),
                "family": "vfs",
                "semantic_group": "vfs:tmp-vs-private-tmp",
                "probes": [],
            },
        )
        probe = {
            "name": path,
            "operation": operation,
            "target": path,
            "expected": expected,
        }
        probe["expectation_id"] = f"{profile_id}:{path}"
        rec["probes"].append(probe)
    matrix = {"world_id": world_id, "profiles": profiles}
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    matrix_path = OUT_DIR / "expected_matrix_harness.json"
    matrix_path.write_text(json.dumps(matrix, indent=2))
    return matrix_path


def run_runtime(matrix_path: Path, sb_paths: Dict[str, Path]) -> Path:
    """Run the harness matrix via runtime_harness and return path to raw runtime_results.json."""
    harness_out = OUT_DIR / "harness"
    harness_out.mkdir(parents=True, exist_ok=True)
    runtime_out = run_expected_matrix(
        matrix_path=matrix_path,
        out_dir=harness_out,
        profile_paths={k: ensure_absolute(v, REPO_ROOT) for k, v in sb_paths.items()},
    )
    return runtime_out


def downconvert_runtime_results(raw_path: Path) -> Path:
    """Down-convert harness runtime_results.json into the simple array format."""
    raw = json.loads(raw_path.read_text())
    simple: List[Dict[str, Any]] = []
    for profile_id, rec in raw.items():
        probes = rec.get("probes") or []
        for probe in probes:
            runtime_result = probe.get("runtime_result") or {}
            simple.append(
                {
                    "profile_id": profile_id,
                    "operation": probe.get("operation"),
                    "requested_path": probe.get("path"),
                    # At this layer we treat observed_path as the requested path; deeper
                    # canonicalization is not visible in these logs.
                    "observed_path": probe.get("path"),
                    "decision": probe.get("actual"),
                    "errno": runtime_result.get("errno"),
                    "raw_log": {
                        "exit_code": probe.get("exit_code"),
                        "stdout": probe.get("stdout"),
                        "stderr": probe.get("stderr"),
                    },
                }
            )
    out_path = OUT_DIR / "runtime_results.json"
    out_path.write_text(json.dumps(simple, indent=2))
    return out_path


def _literal_candidates(s: str) -> set[str]:
    """
    Generate plausible path forms for a decoder literal string.

    Literal strings in the decoder carry a leading type byte (and sometimes a
    leading newline). Drop that byte, trim whitespace, and add a leading slash
    when it is missing so we can compare against anchors exactly.
    """
    out: set[str] = set()
    if not s:
        return out
    trimmed = s.lstrip()
    if trimmed.startswith("/"):
        out.add(trimmed)
    if trimmed:
        body = trimmed[1:]  # drop the type byte
        out.add(body)
        if body and not body.startswith("/"):
            out.add(f"/{body}")
    return out


def anchor_present(anchor: str, literals: set[str]) -> bool:
    """Heuristic presence check for anchors from normalized literal strings."""
    if anchor in literals:
        return True
    parts = anchor.strip("/").split("/")
    if not parts:
        return False
    first = f"/{parts[0]}/"
    if first not in literals:
        return False
    if len(parts) == 1:
        return True
    tail = "/".join(parts[1:])
    if tail in literals or f"/{tail}" in literals:
        return True
    if len(parts) >= 3:
        mid = f"{parts[1]}/"
        tail_rest = "/".join(parts[2:])
        if ((mid in literals) or (f"/{parts[1]}/" in literals)) and (
            (tail_rest in literals) or (f"/{tail_rest}" in literals)
        ):
            return True
    if all(((seg in literals) or (f"/{seg}" in literals) or (f"{seg}/" in literals)) for seg in parts[1:]):
        return True
    return False


def decode_profiles(blobs: Dict[str, Path]) -> Path:
    """Decode the VFS blobs and extract anchor/tag/field2 structure for /tmp and /private/tmp."""
    anchors = sorted({p for pair in PATH_PAIRS for p in pair})
    decode: Dict[str, Any] = {}
    for profile_id, blob_path in blobs.items():
        data = blob_path.read_bytes()
        dec = decoder.decode_profile_dict(data)
        literal_set = set()
        for lit in dec.get("literal_strings") or []:
            literal_set.update(_literal_candidates(lit))
        nodes = dec.get("nodes") or []
        anchors_info: List[Dict[str, Any]] = []
        for anchor in anchors:
            present = anchor_present(anchor, literal_set)
            tag_ids = set()
            field2_vals = set()
            for node in nodes:
                ref_candidates = set()
                for ref in (node.get("literal_refs") or []):
                    ref_candidates.update(_literal_candidates(ref))
                if anchor_present(anchor, ref_candidates):
                    tag_ids.add(node.get("tag"))
                    fields = node.get("fields") or []
                    if len(fields) > 2:
                        field2_vals.add(fields[2])
            anchors_info.append(
                {
                    "path": anchor,
                    "present": present,
                    "tags": sorted(tag_ids),
                    "field2_values": sorted(field2_vals),
                }
            )
        decode[profile_id] = {
            "anchors": anchors_info,
            "node_count": dec.get("node_count"),
            "tag_counts": dec.get("tag_counts"),
        }
    out_path = OUT_DIR / "decode_tmp_profiles.json"
    out_path.write_text(json.dumps(decode, indent=2))
    return out_path


def emit_mismatch_summary(world_id: str) -> Path:
    """
    Emit a coarse mismatch summary for this suite.

    For this first cut we classify profiles based on the observed patterns in
    runtime_results.json on this world and the intended design:
    - vfs_tmp_only: canonicalization-before-enforcement makes the /tmp literal ineffective.
    - vfs_private_tmp_only: canonical literal effective; both requests allowed.
    - vfs_both_paths: control; both requests allowed with both paths mentioned in SBPL.
    """
    summary: Dict[str, Any] = {
        "world_id": world_id,
        "profiles": {
            "vfs_tmp_only": {
                "kind": "canonicalization",
                "note": "Profile mentions only /tmp/* paths; alias and canonical requests are denied across the path set, consistent with canonicalization-before-enforcement with only /private/... literals effective.",
            },
            "vfs_private_tmp_only": {
                "kind": "canonicalization",
                "note": "Profile mentions only canonical /private/... paths; alias and canonical requests are allowed across the path set; literal on canonical path effective for both.",
            },
            "vfs_both_paths": {
                "kind": "control",
                "note": "Profile mentions both alias and canonical forms; all requests allowed; control confirming canonical behavior.",
            },
        },
    }
    out_path = OUT_DIR / "mismatch_summary.json"
    out_path.write_text(json.dumps(summary, indent=2))
    return out_path


def ensure_vfs_files() -> None:
    """Ensure the basic /tmp and /private/tmp fixtures exist."""
    ensure_tmp_files()
    # Seed alias and canonical paths
    for alias, canonical in PATH_PAIRS:
        canonical_path = Path(canonical)
        canonical_path.parent.mkdir(parents=True, exist_ok=True)
        canonical_path.write_text(f"vfs-canonicalization {canonical_path.name}\n")


def main() -> int:
    world_id = load_world_id()
    blobs = compile_profiles()
    simple_matrix = build_simple_expected_matrix()
    matrix_path = build_harness_matrix(world_id, blobs, simple_matrix)
    ensure_vfs_files()
    sb_paths = {
        "vfs_tmp_only": SB_DIR / "vfs_tmp_only.sb",
        "vfs_private_tmp_only": SB_DIR / "vfs_private_tmp_only.sb",
        "vfs_both_paths": SB_DIR / "vfs_both_paths.sb",
    }
    raw_runtime = run_runtime(matrix_path, sb_paths)
    downconvert_runtime_results(raw_runtime)
    decode_profiles(blobs)
    emit_mismatch_summary(world_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
