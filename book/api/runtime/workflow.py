"""
Shared runtime workflow helpers.

This module centralizes:
- Building op-level summaries from curated events/scenarios.
- Generating a complete runtime "cut" (per-scenario traces, scenarios, ops, indexes, manifest)
  from expected_matrix + runtime_results.
- Promoting a staged runtime cut into canonical mapping locations (optional; caller-controlled).
- Running harness families end-to-end into normalized mappings.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional

from book.api import path_utils
from book.api.profile_tools import compile_sbpl_string
from book.api.runtime.core import contract
from book.api.runtime.core import models
from book.api.runtime.core import normalize
from book.api.runtime.harness import golden as harness_golden
from book.api.runtime.harness import runner as harness_runner
from book.api.runtime.mapping import build as mapping_build

REPO_ROOT = path_utils.find_repo_root(Path(__file__))
RUNTIME_CUTS_ROOT = REPO_ROOT / "book" / "graph" / "mappings" / "runtime_cuts"


@dataclass
class ProfileSpec:
    """
    Declarative runtime profile description for the shared driver.

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


def _load_json(path: Path) -> Mapping[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _run_id_from_env() -> Optional[str]:
    run_id = os.environ.get("SANDBOX_LORE_RUN_ID")
    if not run_id:
        return None
    run_id = run_id.strip()
    return run_id or None


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


def _effective_profile_mode(spec: ProfileSpec) -> str:
    if spec.mode in {"sbpl", "blob"}:
        return spec.mode
    return "sbpl" if spec.profile_path.suffix == ".sb" else "blob"


def _profile_path_for_mode(spec: ProfileSpec, build_dir: Path) -> Path:
    mode = _effective_profile_mode(spec)
    profile_path = path_utils.ensure_absolute(spec.profile_path, REPO_ROOT)
    if mode == "blob":
        return _ensure_blob(profile_path, build_dir)
    if profile_path.suffix == ".bin":
        raise ValueError(f"profile_mode=sbpl requires an SBPL text path, got: {profile_path}")
    return profile_path


def _inject_expectation_ids(probes: List[Dict[str, Any]], profile_id: str) -> List[Dict[str, Any]]:
    patched: List[Dict[str, Any]] = []
    for probe in probes:
        copy = dict(probe)
        if not copy.get("expectation_id"):
            name = copy.get("name") or copy.get("operation") or "probe"
            copy["expectation_id"] = f"{profile_id}:{name}"
        patched.append(copy)
    return patched


def build_matrix(world_id: str, profiles: List[ProfileSpec], build_dir: Path) -> Dict[str, Any]:
    """
    Build an expected_matrix-like dict from profile specs.

    Note: The harness treats the `blob` field as the profile input path, which can be
    either SBPL text (mode=sbpl) or a compiled blob (mode=blob). Do not force SBPL
    inputs into blob-mode: on this host, `sandbox_apply` is frequently apply-gated.
    """

    doc: Dict[str, Any] = {"world_id": world_id, "profiles": {}}
    for spec in profiles:
        mode = _effective_profile_mode(spec)
        profile_path = _profile_path_for_mode(spec, build_dir)
        probes = _inject_expectation_ids(spec.probes, spec.profile_id)
        doc["profiles"][spec.profile_id] = {
            "blob": path_utils.to_repo_relative(profile_path, REPO_ROOT),
            "mode": mode,
            "family": spec.family,
            "semantic_group": spec.semantic_group,
            "probes": probes,
        }
    return doc


def load_observations_from_index(events_index_path: Path) -> Iterable[models.RuntimeObservation]:
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
                    yield models.RuntimeObservation(**payload)


def build_ops_from_index(events_index_path: Path, world_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Given an events_index (per-scenario JSONL traces), build the canonical op-level mapping.
    """

    observations = list(load_observations_from_index(events_index_path))
    return mapping_build.build_ops(observations, world_id=world_id)


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
        runtime_result = contract.upgrade_runtime_result(probe.get("runtime_result") or {}, probe.get("stderr"))
        failure_stage = runtime_result.get("failure_stage")
        failure_kind = runtime_result.get("failure_kind")
        if failure_stage == "preflight":
            return "preflight_blocked"
        if failure_stage == "apply":
            return "apply_gate"
        if failure_stage == "bootstrap" and failure_kind == "bootstrap_deny_process_exec":
            return "bootstrap_deny_process_exec"
        if failure_stage == "bootstrap":
            return "bootstrap_failed"

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
        "generated_by": "book/api/runtime/workflow.py",
        "mismatches": mismatches,
        "counts": counts,
    }


def build_cut(
    expected_matrix_path: Path | str,
    runtime_results_path: Path | str,
    staging_root: Path | str,
    world_id: Optional[str] = None,
    run_id: Optional[str] = None,
) -> models.RuntimeCut:
    """
    Produce a complete runtime cut in the staging_root:
    - per-scenario traces (JSONL) + events_index.json
    - scenarios.json
    - ops.json
    - runtime_indexes.json
    - runtime_manifest.json
    """

    staging_root = path_utils.ensure_absolute(staging_root, REPO_ROOT)
    staging_root.mkdir(parents=True, exist_ok=True)

    observations = normalize.normalize_matrix_paths(
        expected_matrix_path,
        runtime_results_path,
        world_id=world_id,
        run_id=run_id,
    )
    expected_doc = _load_json(path_utils.ensure_absolute(Path(expected_matrix_path), REPO_ROOT))

    traces_dir = staging_root / "traces"
    events_index, _ = mapping_build.write_traces(observations, traces_dir, world_id=world_id)
    events_index_path = staging_root / "events_index.json"
    mapping_build.write_events_index(events_index, events_index_path)

    scenario_doc = mapping_build.build_scenarios(observations, expected_doc, world_id=world_id)
    scenario_path = staging_root / "scenarios.json"
    mapping_build.write_scenarios(scenario_doc, scenario_path)

    op_doc = mapping_build.build_ops(observations, world_id=world_id)
    op_path = staging_root / "ops.json"
    mapping_build.write_ops(op_doc, op_path)

    idx_doc = mapping_build.build_indexes(scenario_doc, events_index)
    idx_path = staging_root / "runtime_indexes.json"
    mapping_build.write_indexes(idx_doc, idx_path)

    manifest = mapping_build.build_manifest(
        world_id or models.WORLD_ID,
        events_index_path,
        scenario_path,
        op_path,
    )
    manifest_path = staging_root / "runtime_manifest.json"
    mapping_build.write_manifest(manifest, manifest_path)

    return models.RuntimeCut(
        events_index=events_index_path,
        scenarios=scenario_path,
        ops=op_path,
        indexes=idx_path,
        manifest=manifest_path,
    )


def profiles_from_matrix(matrix_doc: Mapping[str, Any]) -> List[ProfileSpec]:
    """
    Convert an existing expected_matrix dict into ProfileSpec instances.
    """

    profiles: List[ProfileSpec] = []
    for profile_id, rec in (matrix_doc.get("profiles") or {}).items():
        blob = rec.get("blob")
        if not blob:
            continue
        profile_path = path_utils.ensure_absolute(blob, REPO_ROOT)
        probes = rec.get("probes") or []
        profiles.append(
            ProfileSpec(
                profile_id=profile_id,
                profile_path=profile_path,
                probes=probes,
                mode=rec.get("mode"),
                family=rec.get("family"),
                semantic_group=rec.get("semantic_group"),
                key_specific_rules=[],
            )
        )
    return profiles


def run_profiles(
    profiles: List[ProfileSpec],
    out_dir: Path,
    world_id: Optional[str] = None,
    key_specific_rules: Optional[Dict[str, List[str]]] = None,
    classification_strategy: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
) -> models.RuntimeRun:
    """
    Run the harness for the given profiles and emit a staged runtime cut.
    Returns a RuntimeRun bundle (expected_matrix, runtime_results, runtime cut paths, mismatch summary).
    """

    out_dir = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    out_dir.mkdir(parents=True, exist_ok=True)
    world = world_id or models.WORLD_ID
    build_dir = out_dir / "sb_build"

    matrix_doc = build_matrix(world, profiles, build_dir)
    matrix_path = out_dir / "expected_matrix.generated.json"
    matrix_path.write_text(json.dumps(matrix_doc, indent=2))

    profile_paths: Dict[str, Path] = {}
    for spec in profiles:
        profile_paths[spec.profile_id] = _profile_path_for_mode(spec, build_dir)

    # Merge key-specific rules: global + per-profile
    key_rules: Dict[str, List[str]] = {}
    if key_specific_rules:
        key_rules.update(key_specific_rules)
    for spec in profiles:
        if spec.key_specific_rules:
            key_rules.setdefault(spec.profile_id, []).extend(spec.key_specific_rules)

    runtime_results_path = harness_runner.run_matrix(
        matrix_path,
        out_dir=out_dir,
        runtime_profile_dir=out_dir / "runtime_profiles",
        profile_paths=profile_paths,
        key_specific_rules=key_rules,
    )

    run_id = _run_id_from_env()
    cut = build_cut(matrix_path, runtime_results_path, out_dir / "runtime_mappings", world_id=world, run_id=run_id)
    summary = classify_mismatches(matrix_doc, _load_json(runtime_results_path), world, classification_strategy)
    mismatch_path = out_dir / "mismatch_summary.json"
    mismatch_path.write_text(json.dumps(summary, indent=2))

    return models.RuntimeRun(
        expected_matrix=matrix_path,
        runtime_results=runtime_results_path,
        cut=cut,
        mismatch_summary=mismatch_path,
    )


def run_from_matrix(
    matrix_path: Path,
    out_dir: Path,
    world_id: Optional[str] = None,
    key_specific_rules: Optional[Dict[str, List[str]]] = None,
    classification_strategy: Optional[Callable[[str, str, Dict[str, Any]], str]] = None,
) -> models.RuntimeRun:
    """
    Convenience wrapper: load an existing expected_matrix.json and run it via the shared driver.
    """

    matrix_doc = _load_json(path_utils.ensure_absolute(matrix_path, REPO_ROOT))
    profiles = profiles_from_matrix(matrix_doc)
    return run_profiles(
        profiles,
        out_dir,
        world_id=world_id or matrix_doc.get("world_id"),
        key_specific_rules=key_specific_rules,
        classification_strategy=classification_strategy,
    )


def promote_cut(staging_root: Path | str, target_root: Path | str = RUNTIME_CUTS_ROOT) -> models.RuntimeCut:
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
    _ = list(load_observations_from_index(events_index_path))
    _ = _load_json(scenarios_path)
    _ = _load_json(ops_path)
    _ = _load_json(indexes_path)
    manifest_doc = _load_json(manifest_path)

    events_dest = target_root / "events_index.json"
    scenarios_dest = target_root / "scenarios.json"
    ops_dest = target_root / "ops.json"
    indexes_dest = target_root / "runtime_indexes.json"
    manifest_dest = target_root / "runtime_manifest.json"

    shutil.copy2(events_index_path, events_dest)
    shutil.copy2(scenarios_path, scenarios_dest)
    shutil.copy2(ops_path, ops_dest)
    shutil.copy2(indexes_path, indexes_dest)

    # Re-point manifest to promoted paths so callers stay within runtime_cuts.
    manifest_doc["events_index"] = path_utils.to_repo_relative(events_dest, REPO_ROOT)
    manifest_doc["scenarios"] = path_utils.to_repo_relative(scenarios_dest, REPO_ROOT)
    manifest_doc["ops"] = path_utils.to_repo_relative(ops_dest, REPO_ROOT)
    story_src = staging_root / "runtime_story.json"
    runtime_story: Optional[Path] = None
    if story_src.exists():
        story_dest = target_root / story_src.name
        shutil.copy2(story_src, story_dest)
        manifest_doc["runtime_story"] = path_utils.to_repo_relative(story_dest, REPO_ROOT)
        runtime_story = story_dest
    elif manifest_doc.get("runtime_story"):
        story_dest = target_root / Path(manifest_doc["runtime_story"]).name
        manifest_doc["runtime_story"] = path_utils.to_repo_relative(story_dest, REPO_ROOT)
        runtime_story = story_dest
    shutil.copy2(manifest_path, manifest_dest)
    manifest_dest.write_text(json.dumps(manifest_doc, indent=2))

    return models.RuntimeCut(
        events_index=events_dest,
        scenarios=scenarios_dest,
        ops=ops_dest,
        indexes=indexes_dest,
        manifest=manifest_dest,
        runtime_story=runtime_story,
    )


def generate_golden_artifacts(
    matrix_path: Path,
    runtime_results_path: Path,
    baseline_ref: Path,
    out_root: Path,
) -> models.GoldenArtifacts:
    """
    Build golden decodes/expectations/traces from runtime-checks outputs.
    """

    baseline = harness_golden.load_baseline_info(str(baseline_ref))
    profiles = harness_golden.load_golden_matrix(Path(matrix_path))

    out_root = path_utils.ensure_absolute(out_root, REPO_ROOT)
    decoded_blobs = out_root / "decoded_blobs"
    decode_summary = out_root / "golden_decodes.json"
    expectations = out_root / "golden_expectations.json"
    traces = out_root / "traces" / "golden_traces.jsonl"

    decodes = []
    for key, prof in profiles.items():
        blob = harness_golden.compile_golden_profile(prof)
        out_blob = decoded_blobs / f"{key.replace(':', '_')}.sb.bin"
        out_blob.parent.mkdir(parents=True, exist_ok=True)
        out_blob.write_bytes(blob)
        decoded = harness_golden.decode_blob(blob)
        decodes.append(harness_golden.summarize_blob(key, prof.path, blob, decoded))
    harness_golden.write_json(decode_summary, {"metadata": {"world_id": baseline.world_id}, "decodes": decodes})

    expectations_payload = {
        "metadata": {"world_id": baseline.world_id},
        "profiles": {
            key: {
                "blob": str(prof.path),
                "mode": prof.mode,
                "sha256": {d["key"]: d for d in decodes}[key]["sha256"],
            }
            for key, prof in profiles.items()
        },
    }
    harness_golden.write_json(expectations, expectations_payload)

    traces_rows = harness_golden.normalize_golden_results(Path(runtime_results_path), harness_golden.GOLDEN_KEYS)
    harness_golden.write_jsonl(traces, traces_rows)

    return models.GoldenArtifacts(
        decode_summary=decode_summary,
        expectations=expectations,
        traces=traces,
    )
