"""
Shared runtime pipeline helpers.

This module centralizes:
- Building op-level summaries from curated events/scenarios.
- Generating a complete runtime "cut" (per-scenario traces, scenarios, ops, indexes, manifest)
  from expected_matrix + runtime_results.
- Promoting a staged runtime cut into canonical mapping locations (optional; caller-controlled).
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Callable, Any, Tuple

from book.api import path_utils
from book.api.runtime import events as runtime_events
from book.api.runtime import mappings as rt_map
from book.api.runtime_harness import runner as runtime_harness
from book.api.profile_tools import compile_sbpl_string

REPO_ROOT = path_utils.find_repo_root(Path(__file__))
RUNTIME_CUTS_ROOT = REPO_ROOT / "book" / "graph" / "mappings" / "runtime_cuts"


@dataclass
class FamilySpec:
    """
    Declarative runtime family description for the shared driver.

    Fields:
    - profile_id: identifier for this profile run (used in expected matrix)
    - profile_path: path to SBPL or blob to run
    - probes: list of probes with expected decisions
      Each probe: {name, operation, target, expected, expectation_id?, mode?}
    - mode/profile_mode: optional mode hints (e.g., "sbpl", "blob")
    - family/semantic_group: optional tags for grouping/reporting
    - key_specific_rules: optional SBPL snippets to patch in for this key
    """

    profile_id: str
    profile_path: Path
    probes: List[Dict[str, Any]]
    mode: Optional[str] = None
    family: Optional[str] = None
    semantic_group: Optional[str] = None
    key_specific_rules: List[str] = field(default_factory=list)


def _load_json(path: Path) -> Mapping[str, any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _ensure_blob(profile_path: Path, build_dir: Path) -> Path:
    """
    Compile SBPL to a blob if needed; return path to blob or original if already binary.
    """

    profile_path = path_utils.ensure_absolute(profile_path, REPO_ROOT)
    if profile_path.suffix == ".bin":
        return profile_path
    text = profile_path.read_text()
    blob = compile_sbpl_string(text).blob
    build_dir.mkdir(parents=True, exist_ok=True)
    blob_path = build_dir / f"{profile_path.stem}.sb.bin"
    blob_path.write_bytes(blob)
    return blob_path


def _inject_expectation_ids(probes: List[Dict[str, Any]], profile_id: str) -> List[Dict[str, Any]]:
    patched: List[Dict[str, Any]] = []
    for probe in probes:
        copy = dict(probe)
        if not copy.get("expectation_id"):
            name = copy.get("name") or copy.get("operation") or "probe"
            copy["expectation_id"] = f"{profile_id}:{name}"
        patched.append(copy)
    return patched


def build_expected_matrix_from_families(world_id: str, families: List[FamilySpec], build_dir: Path) -> Dict[str, Any]:
    """
    Build an expected_matrix-like dict from family specs, compiling SBPL as needed.
    """

    profiles: Dict[str, Any] = {}
    for spec in families:
        blob_path = _ensure_blob(spec.profile_path, build_dir)
        probes = _inject_expectation_ids(spec.probes, spec.profile_id)
        profiles[spec.profile_id] = {
            "blob": path_utils.to_repo_relative(blob_path, REPO_ROOT),
            "mode": spec.mode or ("sbpl" if spec.profile_path.suffix == ".sb" else "blob"),
            "family": spec.family,
            "semantic_group": spec.semantic_group,
            "probes": probes,
        }
    return {"world_id": world_id, "profiles": profiles}


def load_events_from_index(events_index_path: Path) -> Iterable[runtime_events.RuntimeObservation]:
    """
    Stream observations from a per-scenario events index.
    """

    events_index = _load_json(events_index_path)
    traces = events_index.get("traces") or {}
    for scenario_id, trace_paths in traces.items():
        for trace_path in trace_paths:
            abs_path = path_utils.ensure_absolute(trace_path, REPO_ROOT)
            with abs_path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    payload = json.loads(line)
                    # Ensure scenario_id is present even if the line is missing it.
                    payload.setdefault("scenario_id", scenario_id)
                    yield runtime_events.RuntimeObservation(**payload)


def build_op_summary_from_index(events_index_path: Path, world_id: Optional[str] = None) -> Dict[str, any]:
    """
    Given an events_index (per-scenario JSONL traces), build the canonical op-level mapping.
    """

    observations = list(load_events_from_index(events_index_path))
    op_doc = rt_map.build_op_summaries(observations, world_id=world_id)
    return op_doc


def classify_mismatches(
    expected_matrix: Mapping[str, Any],
    runtime_results: Mapping[str, Any],
    world_id: str,
    classification_strategy: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
) -> Dict[str, Any]:
    """
    Compare expected vs runtime results and emit a mismatch summary.
    """

    def _default_classify(expected: str | None, actual: str | None, probe: Dict[str, Any]) -> str:
        op = probe.get("operation")
        if expected == "allow" and actual == "deny":
            path = probe.get("path") or probe.get("target") or ""
            if op == "file-read*" and (".." in path or path.startswith("/tmp/runtime-adv/edges")):
                return "path_normalization"
            return "unexpected_deny"
        if expected == "deny" and actual == "allow":
            if op == "file-read*" and ".." in (probe.get("path") or probe.get("target") or ""):
                return "path_normalization"
            return "unexpected_allow"
        if probe.get("violation_summary") == "EPERM":
            return "apply_gate"
        return "filter_diff"

    classify = classification_strategy or _default_classify
    mismatches: List[Dict[str, Any]] = []
    counts: Dict[str, int] = {}

    for profile_id, rec in (expected_matrix.get("profiles") or {}).items():
        expected_by_id = {p["expectation_id"]: p for p in rec.get("probes") or []}
        runtime_entry = (runtime_results or {}).get(profile_id) or {}
        for probe in runtime_entry.get("probes") or []:
            eid = probe.get("expectation_id")
            expected_probe = expected_by_id.get(eid) or {}
            expected_decision = expected_probe.get("expected")
            actual_decision = probe.get("actual")
            match = expected_decision == actual_decision and probe.get("match", True)
            if match:
                continue
            mismatch_type = classify(expected_decision, actual_decision, probe)
            counts[mismatch_type] = counts.get(mismatch_type, 0) + 1
            mismatches.append(
                {
                    "world_id": world_id,
                    "profile_id": profile_id,
                    "expectation_id": eid,
                    "operation": probe.get("operation"),
                    "path": probe.get("path") or probe.get("target"),
                    "expected": expected_decision,
                    "actual": actual_decision,
                    "mismatch_type": mismatch_type,
                    "violation_summary": probe.get("violation_summary"),
                    "notes": probe.get("stderr"),
                }
            )

    return {
        "world_id": world_id,
        "generated_by": "book/api/runtime/pipeline.py",
        "mismatches": mismatches,
        "counts": counts,
    }


def generate_runtime_cut(
    expected_matrix_path: Path | str,
    runtime_results_path: Path | str,
    staging_root: Path | str,
    world_id: Optional[str] = None,
) -> Dict[str, Path]:
    """
    Produce a complete runtime cut in the staging_root:
    - per-scenario traces (JSONL) + events_index.json
    - scenarios.json
    - ops.json
    - runtime_indexes.json
    - runtime_manifest.json

    Returns a dict of artifact paths.
    """

    staging_root = path_utils.ensure_absolute(staging_root, REPO_ROOT)
    staging_root.mkdir(parents=True, exist_ok=True)

    observations = runtime_events.normalize_from_paths(expected_matrix_path, runtime_results_path, world_id=world_id)
    expected_doc = _load_json(path_utils.ensure_absolute(expected_matrix_path, REPO_ROOT))

    traces_dir = staging_root / "traces"
    events_index, _ = rt_map.write_per_scenario_traces(observations, traces_dir, world_id=world_id)
    events_index_path = staging_root / "events_index.json"
    rt_map.write_events_index(events_index, events_index_path)

    scenario_doc = rt_map.build_scenario_summaries(observations, expected_doc, world_id=world_id)
    scenario_path = staging_root / "scenarios.json"
    rt_map.write_scenario_mapping(scenario_doc, scenario_path)

    op_doc = rt_map.build_op_summaries(observations, world_id=world_id)
    op_path = staging_root / "ops.json"
    rt_map.write_op_mapping(op_doc, op_path)

    idx_doc = rt_map.build_indexes(scenario_doc, events_index)
    idx_path = staging_root / "runtime_indexes.json"
    rt_map.write_index_mapping(idx_doc, idx_path)

    manifest = rt_map.build_manifest(
        world_id or runtime_events.WORLD_ID,
        events_index_path,
        scenario_path,
        op_path,
    )
    manifest_path = staging_root / "runtime_manifest.json"
    rt_map.write_manifest(manifest, manifest_path)

    return {
        "events_index": events_index_path,
        "scenarios": scenario_path,
        "ops": op_path,
        "indexes": idx_path,
        "manifest": manifest_path,
    }


def families_from_matrix(matrix_doc: Mapping[str, Any]) -> List[FamilySpec]:
    """
    Convert an existing expected_matrix dict into FamilySpec instances.
    """

    families: List[FamilySpec] = []
    for profile_id, rec in (matrix_doc.get("profiles") or {}).items():
        blob = rec.get("blob")
        if not blob:
            continue
        profile_path = path_utils.ensure_absolute(blob, REPO_ROOT)
        probes = rec.get("probes") or []
        families.append(
            FamilySpec(
                profile_id=profile_id,
                profile_path=profile_path,
                probes=probes,
                mode=rec.get("mode"),
                family=rec.get("family"),
                semantic_group=rec.get("semantic_group"),
                key_specific_rules=[],
            )
        )
    return families


def run_family_specs(
    families: List[FamilySpec],
    out_dir: Path,
    world_id: Optional[str] = None,
    key_specific_rules: Optional[Dict[str, List[str]]] = None,
    classification_strategy: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
) -> Dict[str, Path]:
    """
    Run the harness for the given families and emit a staged runtime cut.
    Returns a dict of artifact paths (expected_matrix, runtime_results, runtime cut paths, mismatch_summary).
    """

    out_dir = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    out_dir.mkdir(parents=True, exist_ok=True)
    world = world_id or runtime_events.WORLD_ID
    build_dir = out_dir / "sb_build"

    matrix_doc = build_expected_matrix_from_families(world, families, build_dir)
    matrix_path = out_dir / "expected_matrix.generated.json"
    matrix_path.write_text(json.dumps(matrix_doc, indent=2))

    profile_paths: Dict[str, Path] = {}
    for spec in families:
        blob_path = _ensure_blob(spec.profile_path, build_dir)
        profile_paths[spec.profile_id] = blob_path

    # Merge key-specific rules: global + per-family
    key_rules: Dict[str, List[str]] = {}
    if key_specific_rules:
        key_rules.update(key_specific_rules)
    for spec in families:
        if spec.key_specific_rules:
            key_rules.setdefault(spec.profile_id, []).extend(spec.key_specific_rules)

    runtime_results_path = runtime_harness.run_expected_matrix(
        matrix_path,
        out_dir=out_dir,
        runtime_profile_dir=out_dir / "runtime_profiles",
        profile_paths=profile_paths,
        key_specific_rules=key_rules,
    )

    artifacts = generate_runtime_cut(matrix_path, runtime_results_path, out_dir / "runtime_mappings", world_id=world)
    summary = classify_mismatches(matrix_doc, _load_json(runtime_results_path), world, classification_strategy)
    mismatch_path = out_dir / "mismatch_summary.json"
    mismatch_path.write_text(json.dumps(summary, indent=2))
    artifacts["mismatch_summary"] = mismatch_path
    artifacts["expected_matrix"] = matrix_path
    artifacts["runtime_results"] = runtime_results_path
    return artifacts


def run_from_expected_matrix(
    matrix_path: Path,
    out_dir: Path,
    world_id: Optional[str] = None,
    key_specific_rules: Optional[Dict[str, List[str]]] = None,
    classification_strategy: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
) -> Dict[str, Path]:
    """
    Convenience wrapper: load an existing expected_matrix.json and run it via the shared driver.
    """

    matrix_doc = _load_json(path_utils.ensure_absolute(matrix_path, REPO_ROOT))
    families = families_from_matrix(matrix_doc)
    return run_family_specs(
        families,
        out_dir,
        world_id=world_id or matrix_doc.get("world_id"),
        key_specific_rules=key_specific_rules,
        classification_strategy=classification_strategy,
    )


def promote_runtime_cut(staging_root: Path | str, target_root: Path | str = RUNTIME_CUTS_ROOT) -> Dict[str, Path]:
    """
    Promote a staged runtime cut into canonical runtime mapping locations.
    Validates readability via the shared loaders before copying.
    """

    staging_root = path_utils.ensure_absolute(staging_root, REPO_ROOT)
    target_root = path_utils.ensure_absolute(target_root, REPO_ROOT)
    target_root.mkdir(parents=True, exist_ok=True)

    events_index_path = staging_root / "events_index.json"
    scenarios_path = staging_root / "scenarios.json"
    ops_path = staging_root / "ops.json"
    indexes_path = staging_root / "runtime_indexes.json"
    manifest_path = staging_root / "runtime_manifest.json"

    # Basic readability checks
    _ = list(load_events_from_index(events_index_path))
    _ = _load_json(scenarios_path)
    _ = _load_json(ops_path)
    _ = _load_json(indexes_path)
    manifest_doc = _load_json(manifest_path)

    artifacts = {
        "events_index": target_root / "events_index.json",
        "scenarios": target_root / "scenarios.json",
        "ops": target_root / "ops.json",
        "indexes": target_root / "runtime_indexes.json",
        "manifest": target_root / "runtime_manifest.json",
    }

    shutil.copy2(events_index_path, artifacts["events_index"])
    shutil.copy2(scenarios_path, artifacts["scenarios"])
    shutil.copy2(ops_path, artifacts["ops"])
    shutil.copy2(indexes_path, artifacts["indexes"])

    # Re-point manifest to promoted paths so callers stay within runtime_cuts.
    manifest_doc["events_index"] = path_utils.to_repo_relative(artifacts["events_index"], REPO_ROOT)
    manifest_doc["scenarios"] = path_utils.to_repo_relative(artifacts["scenarios"], REPO_ROOT)
    manifest_doc["ops"] = path_utils.to_repo_relative(artifacts["ops"], REPO_ROOT)
    story_src = staging_root / "runtime_story.json"
    if story_src.exists():
        story_dest = target_root / story_src.name
        shutil.copy2(story_src, story_dest)
        manifest_doc["runtime_story"] = path_utils.to_repo_relative(story_dest, REPO_ROOT)
    elif manifest_doc.get("runtime_story"):
        # If a runtime story was already recorded elsewhere, point it to the canonical location under runtime_cuts.
        story_dest = target_root / Path(manifest_doc["runtime_story"]).name
        manifest_doc["runtime_story"] = path_utils.to_repo_relative(story_dest, REPO_ROOT)
    shutil.copy2(manifest_path, artifacts["manifest"])
    artifacts["manifest"].write_text(json.dumps(manifest_doc, indent=2))

    return artifacts


# Harness runner and expected-matrix builder can be added here; experiments
# should supply a list of FamilySpec instances and call into a single entrypoint
# to execute and materialize runtime cuts. This keeps runtime execution logic
# centralized in the shared pipeline.
