#!/usr/bin/env python3
"""
Phase 1 adversarial runtime harness.

Builds expected matrices for two families (structural variants, path/literal edges),
compiles SBPL → blob, runs runtime probes via golden_runner, and emits mismatch summaries.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import golden_runner
from book.api.sbpl_compile import compile_sbpl_string

BASE_DIR = Path(__file__).resolve().parent
SB_DIR = BASE_DIR / "sb"
BUILD_DIR = SB_DIR / "build"
OUT_DIR = BASE_DIR / "out"
WORLD_PATH = REPO_ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"
ADVERSARIAL_SUMMARY = REPO_ROOT / "book" / "graph" / "mappings" / "runtime" / "adversarial_summary.json"


@dataclass
class ProfileSpec:
    key: str
    sbpl: Path
    family: str
    semantic_group: str


def load_world_id() -> str:
    data = json.loads(WORLD_PATH.read_text())
    return data.get("id", "unknown-world")


def ensure_fixture_files() -> None:
    """Create file fixtures used by probes."""
    struct_root = Path("/tmp/runtime-adv/struct")
    edges_root = Path("/tmp/runtime-adv/edges")

    for path in [
        struct_root / "ok" / "allowed.txt",
        struct_root / "ok" / "deep" / "nested.txt",
        struct_root / "blocked.txt",
        struct_root / "outside.txt",
        edges_root / "a",
        edges_root / "okdir" / "item.txt",
        edges_root / "okdir" / ".." / "blocked.txt",
    ]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"runtime-adv fixture for {path}\n")


def compile_profiles(specs: List[ProfileSpec]) -> Dict[str, Path]:
    """Compile SBPL profiles to blobs under sb/build and return a map of key -> blob path."""
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    blob_paths: Dict[str, Path] = {}
    for spec in specs:
        blob_path = BUILD_DIR / f"{spec.sbpl.stem}.sb.bin"
        blob = compile_sbpl_string(spec.sbpl.read_text()).blob
        blob_path.write_bytes(blob)
        blob_paths[spec.key] = blob_path
    return blob_paths


def build_expected_matrix(world_id: str, specs: List[ProfileSpec], blobs: Dict[str, Path]) -> Dict[str, Any]:
    """Construct expected_matrix.json payload."""
    probes_common = [
        {
            "name": "allow-ok-root",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/ok/allowed.txt",
            "expected": "allow",
        },
        {
            "name": "allow-ok-deep",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/ok/deep/nested.txt",
            "expected": "allow",
        },
        {
            "name": "deny-blocked",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/blocked.txt",
            "expected": "deny",
        },
        {
            "name": "deny-outside",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/struct/outside.txt",
            "expected": "deny",
        },
    ]
    probes_edges = [
        {
            "name": "allow-tmp",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/edges/a",
            "expected": "allow",
        },
        {
            "name": "deny-private",
            "operation": "file-read*",
            "target": "/private/tmp/runtime-adv/edges/a",
            "expected": "deny",
        },
        {
            "name": "allow-subpath",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/edges/okdir/item.txt",
            "expected": "allow",
        },
        {
            "name": "deny-dotdot",
            "operation": "file-read*",
            "target": "/tmp/runtime-adv/edges/okdir/../blocked.txt",
            "expected": "deny",
        },
    ]

    probes_mach = [
        {
            "name": "allow-cfprefsd",
            "operation": "mach-lookup",
            "target": "com.apple.cfprefsd.agent",
            "expected": "allow",
        },
        {
            "name": "deny-bogus",
            "operation": "mach-lookup",
            "target": "com.apple.sandboxadversarial.fake",
            "expected": "deny",
        },
    ]
    probes_mach_local = [
        {
            "name": "allow-cfprefsd-local",
            "operation": "mach-lookup",
            "target": "com.apple.cfprefsd.agent",
            "expected": "allow",
            "mode": "local",
        },
        {
            "name": "deny-bogus-local",
            "operation": "mach-lookup",
            "target": "com.apple.sandboxadversarial.fake",
            "expected": "deny",
            "mode": "local",
        },
    ]

    matrix: Dict[str, Any] = {"world": world_id, "profiles": {}}
    for spec in specs:
        if spec.family == "structural_variants":
            probes = probes_common
        elif spec.family == "path_edges":
            probes = probes_edges
        elif spec.family == "mach_variants":
            probes = probes_mach
        elif spec.family == "mach_local":
            probes = probes_mach_local
        else:
            probes = []
        profile_entry = {
            "mode": "sbpl",
            "sbpl": str(spec.sbpl),
            "blob": str(blobs[spec.key]),
            "family": spec.family,
            "semantic_group": spec.semantic_group,
            "probes": [],
        }
        for probe in probes:
            probe_copy = dict(probe)
            probe_copy["expectation_id"] = f"{spec.key}:{probe['name']}"
            profile_entry["probes"].append(probe_copy)
        matrix["profiles"][spec.key] = profile_entry
    return matrix


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def classify_mismatch(expected: str | None, actual: str | None, probe: Dict[str, Any]) -> str:
    op = probe.get("operation")
    if expected == "allow" and actual == "deny":
        path = probe.get("path") or ""
        if op == "file-read*" and (".." in path or path.startswith("/tmp/runtime-adv/edges")):
            return "path_normalization"
        return "unexpected_deny"
    if expected == "deny" and actual == "allow":
        if op == "file-read*" and ".." in (probe.get("path") or ""):
            return "path_normalization"
        return "unexpected_allow"
    if probe.get("violation_summary") == "EPERM":
        return "apply_gate"
    return "filter_diff"


def static_prediction_for(profile_id: str, expected_probe: Dict[str, Any]) -> Dict[str, Any]:
    """Manual static expectations for mismatches to record which filters were intended to fire."""
    path = expected_probe.get("target")
    name = expected_probe.get("name")
    if profile_id == "adv:path_edges":
        if name == "allow-tmp":
            return {
                "static_filters": ["literal:/tmp/runtime-adv/edges/a"],
                "static_reason": "literal allow on /tmp path; separate deny literal on /private/tmp expected to distinguish canonical paths",
            }
        if name == "allow-subpath":
            return {
                "static_filters": ["subpath:/tmp/runtime-adv/edges/okdir"],
                "static_reason": "subpath allow under /tmp/.../okdir; deny literal on .. sibling intended to catch traversal",
            }
    if profile_id.startswith("adv:mach_simple"):
        if name == "allow-cfprefsd":
            return {
                "static_filters": ["mach-lookup:global-name com.apple.cfprefsd.agent"],
                "static_reason": "allow specific mach global-name, default deny others",
            }
        if name == "deny-bogus":
            return {
                "static_filters": ["mach-lookup default deny"],
                "static_reason": "bogus service should be denied by default",
            }
    if profile_id.startswith("adv:mach_local"):
        if name == "allow-cfprefsd-local":
            return {
                "static_filters": ["mach-lookup:local-name com.apple.cfprefsd.agent"],
                "static_reason": "allow specific mach local-name, default deny others",
            }
        if name == "deny-bogus-local":
            return {
                "static_filters": ["mach-lookup default deny"],
                "static_reason": "bogus local service should be denied by default",
            }
    return {}


def compare_results(expected_matrix: Path, runtime_results: Path, world_id: str) -> Dict[str, Any]:
    expected = json.loads(expected_matrix.read_text())
    runtime = json.loads(runtime_results.read_text()) if runtime_results.exists() else {}
    mismatches: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}

    for profile_id, rec in (expected.get("profiles") or {}).items():
        expected_by_id = {p["expectation_id"]: p for p in rec.get("probes") or []}
        runtime_entry = runtime.get(profile_id) or {}
        for probe in runtime_entry.get("probes") or []:
            eid = probe.get("expectation_id")
            expected_probe = expected_by_id.get(eid) or {}
            expected_decision = expected_probe.get("expected")
            actual_decision = probe.get("actual")
            match = expected_decision == actual_decision and probe.get("match", True)
            if match:
                continue
            mismatch_type = classify_mismatch(expected_decision, actual_decision, probe)
            counts[mismatch_type] = counts.get(mismatch_type, 0) + 1
            static_view = static_prediction_for(profile_id, expected_probe)
            mismatches.append(
                {
                    "world": world_id,
                    "profile_id": profile_id,
                    "expectation_id": eid,
                    "operation": probe.get("operation"),
                    "path": probe.get("path"),
                    "expected": expected_decision,
                    "actual": actual_decision,
                    "mismatch_type": mismatch_type,
                    "notes": probe.get("stderr"),
                    **static_view,
                }
            )

    summary = {
        "world": world_id,
        "generated_by": "book/experiments/runtime-adversarial/run_adversarial.py",
        "mismatches": mismatches,
        "counts": counts,
    }
    write_json(OUT_DIR / "mismatch_summary.json", summary)
    return summary


def update_adversarial_summary(world_id: str, matrix: Dict[str, Any], summary: Dict[str, Any]) -> None:
    rows = {
        "world": world_id,
        "profiles": len(matrix.get("profiles") or {}),
        "expectations": sum(len(p.get("probes") or []) for p in (matrix.get("profiles") or {}).values()),
        "mismatch_counts": summary.get("counts") or {},
    }
    write_json(ADVERSARIAL_SUMMARY, rows)


def main() -> int:
    world_id = load_world_id()
    ensure_fixture_files()
    specs = [
        ProfileSpec(
            key="adv:struct_flat",
            sbpl=SB_DIR / "struct_flat.sb",
            family="structural_variants",
            semantic_group="structural:file-read-subpath",
        ),
        ProfileSpec(
            key="adv:struct_nested",
            sbpl=SB_DIR / "struct_nested.sb",
            family="structural_variants",
            semantic_group="structural:file-read-subpath",
        ),
        ProfileSpec(
            key="adv:path_edges",
            sbpl=SB_DIR / "path_edges.sb",
            family="path_edges",
            semantic_group="paths:literal-vs-normalized",
        ),
        ProfileSpec(
            key="adv:mach_simple_allow",
            sbpl=SB_DIR / "mach_simple_allow.sb",
            family="mach_variants",
            semantic_group="mach:global-name-allow",
        ),
        ProfileSpec(
            key="adv:mach_simple_variants",
            sbpl=SB_DIR / "mach_simple_variants.sb",
            family="mach_variants",
            semantic_group="mach:global-name-allow",
        ),
        ProfileSpec(
            key="adv:mach_local_literal",
            sbpl=SB_DIR / "mach_local_literal.sb",
            family="mach_local",
            semantic_group="mach:local-name-allow",
        ),
        ProfileSpec(
            key="adv:mach_local_regex",
            sbpl=SB_DIR / "mach_local_regex.sb",
            family="mach_local",
            semantic_group="mach:local-name-allow",
        ),
    ]

    blobs = compile_profiles(specs)
    matrix = build_expected_matrix(world_id, specs, blobs)
    matrix_path = OUT_DIR / "expected_matrix.json"
    write_json(matrix_path, matrix)

    profile_paths = {spec.key: spec.sbpl for spec in specs}
    runtime_out = golden_runner.run_expected_matrix(matrix_path, out_dir=OUT_DIR, profile_paths=profile_paths)
    summary = compare_results(matrix_path, runtime_out, world_id)

    impact_map = OUT_DIR / "impact_map.json"
    if not impact_map.exists():
        write_json(impact_map, {})

    update_adversarial_summary(world_id, matrix, summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
