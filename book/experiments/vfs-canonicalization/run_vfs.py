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

import book.api.decoder as decoder  # type: ignore
from book.api.runtime_harness.runner import ensure_tmp_files, run_expected_matrix  # type: ignore
from book.api.sbpl_compile import compile_sbpl_string  # type: ignore


BASE_DIR = Path(__file__).resolve().parent
SB_DIR = BASE_DIR / "sb"
BUILD_DIR = SB_DIR / "build"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"


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
    """Emit a simple expected matrix over three profiles and two paths."""
    entries: List[Dict[str, Any]] = []
    scenarios = [
        ("vfs_tmp_only", "/tmp/foo", "allow", "literal /tmp/foo in tmp-only profile"),
        ("vfs_tmp_only", "/private/tmp/foo", "deny", "control for canonicalization"),
        ("vfs_private_tmp_only", "/tmp/foo", "deny", "control for canonicalization"),
        ("vfs_private_tmp_only", "/private/tmp/foo", "allow", "literal /private/tmp/foo in private-tmp-only profile"),
        ("vfs_both_paths", "/tmp/foo", "allow", "both tmp and private tmp allowed"),
        ("vfs_both_paths", "/private/tmp/foo", "allow", "both tmp and private tmp allowed"),
    ]
    for profile_id, path, expected, note in scenarios:
        entries.append(
            {
                "profile_id": profile_id,
                "operation": "file-read*",
                "requested_path": path,
                "expected_decision": expected,
                "notes": note,
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
        rec = profiles.setdefault(
            profile_id,
            {
                "mode": "sbpl",
                "sbpl": str(sb_paths[profile_id]),
                "blob": str(blobs[profile_id]),
                "family": "vfs",
                "semantic_group": "vfs:tmp-vs-private-tmp",
                "probes": [],
            },
        )
        probe = {
            "name": path,
            "operation": "file-read*",
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
        profile_paths=sb_paths,
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


def decode_profiles(blobs: Dict[str, Path]) -> Path:
    """Decode the VFS blobs and extract anchor/tag/field2 structure for /tmp and /private/tmp."""
    anchors = ["/tmp/foo", "/private/tmp/foo"]
    decode: Dict[str, Any] = {}
    for profile_id, blob_path in blobs.items():
        data = blob_path.read_bytes()
        dec = decoder.decode_profile_dict(data)
        literals = dec.get("literal_strings") or []
        nodes = dec.get("nodes") or []
        anchors_info: List[Dict[str, Any]] = []
        for anchor in anchors:
            present = any(anchor in s for s in literals)
            tag_ids = set()
            field2_vals = set()
            for node in nodes:
                refs = node.get("literal_refs") or []
                if any(anchor in r for r in refs):
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


def ensure_vfs_files() -> None:
    """Ensure the basic /tmp and /private/tmp fixtures exist."""
    ensure_tmp_files()
    private_tmp = Path("/private/tmp")
    private_tmp.mkdir(parents=True, exist_ok=True)
    (private_tmp / "foo").write_text("vfs-canonicalization foo\n")


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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
