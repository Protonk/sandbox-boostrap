"""
Public runtime_tools API surface for plan-based execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from book.api import path_utils
from . import baseline as baseline_lane
from . import mismatch as mismatch_lane
from . import plan as plan_loader
from . import preflight as apply_preflight
from . import workflow
from . import inventory as runtime_inventory
from .core import normalize
from .core import models
from .channels import ChannelSpec
from .channels import launchd_clean


REPO_ROOT = path_utils.find_repo_root(Path(__file__))

RUN_MANIFEST_SCHEMA_VERSION = "runtime-tools.run_manifest.v0.1"
SUMMARY_SCHEMA_VERSION = "runtime-tools.summary.v0.1"
RUNTIME_RESULTS_SCHEMA_VERSION = "runtime-tools.runtime_results.v0.1"
ARTIFACT_INDEX_SCHEMA_VERSION = "runtime-tools.artifact_index.v0.1"
MISMATCH_PACKET_SCHEMA_VERSION = "runtime-tools.mismatch_packet.v0.1"
ORACLE_SCHEMA_VERSION = "runtime-tools.oracle_results.v0.1"
BASELINE_SCHEMA_VERSION = "runtime-tools.baseline_results.v0.1"

CORE_ARTIFACTS = [
    "run_manifest.json",
    "apply_preflight.json",
    "baseline_results.json",
    "expected_matrix.generated.json",
    "expected_matrix.json",
    "runtime_results.json",
    "runtime_events.normalized.json",
    "mismatch_summary.json",
    "mismatch_packets.jsonl",
    "oracle_results.json",
    "summary.json",
    "summary.md",
]


@dataclass(frozen=True)
class RunBundle:
    out_dir: Path
    status: str
    run_manifest: Path
    artifact_index: Path


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    errors: list[str]


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _run_id() -> str:
    run_id = os.environ.get("SANDBOX_LORE_RUN_ID")
    if run_id:
        return run_id
    run_id = str(uuid.uuid4())
    os.environ["SANDBOX_LORE_RUN_ID"] = run_id
    return run_id


def _channel_from_env(default: str) -> str:
    return os.environ.get("SANDBOX_LORE_CHANNEL") or default


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _annotate_runtime_results(path: Path, schema_version: str, run_id: str) -> None:
    doc = json.loads(path.read_text())
    for profile in doc.values():
        if isinstance(profile, dict):
            profile.setdefault("schema_version", schema_version)
            profile.setdefault("run_id", run_id)
    path.write_text(json.dumps(doc, indent=2))


def _write_oracle_results(events_path: Path, world_id: str, out_path: Path) -> None:
    if events_path.exists():
        data = json.loads(events_path.read_text())
    else:
        data = []
    results = []
    for row in data:
        callouts = row.get("seatbelt_callouts") or []
        if not callouts:
            continue
        for callout in callouts:
            results.append(
                {
                    "world_id": world_id,
                    "run_id": row.get("run_id"),
                    "expectation_id": row.get("expectation_id"),
                    "operation": callout.get("operation"),
                    "filter_type": callout.get("filter_type"),
                    "filter_type_name": callout.get("filter_type_name"),
                    "argument": callout.get("argument"),
                    "decision": callout.get("decision"),
                    "stage": callout.get("stage"),
                }
            )
    _write_json(
        out_path,
        {
            "schema_version": ORACLE_SCHEMA_VERSION,
            "world_id": world_id,
            "run_id": os.environ.get("SANDBOX_LORE_RUN_ID"),
            "results": results,
        },
    )


def _write_summary(
    *,
    world_id: str,
    run_id: str,
    expected_profiles: Iterable[str],
    mismatch_summary: Dict[str, Any],
    status: str,
    out_json: Path,
    out_md: Path,
    schema_version: str,
) -> None:
    summary = {
        "schema_version": schema_version,
        "world_id": world_id,
        "run_id": run_id,
        "status": status,
        "expected_profiles": list(expected_profiles),
        "mismatch_counts": mismatch_summary.get("counts") or {},
    }
    _write_json(out_json, summary)
    lines = ["# Runtime Summary", "", f"Status: {status}", ""]
    mismatches = mismatch_summary.get("mismatches") or []
    lines.append(f"Mismatches: {len(mismatches)}" if mismatches else "Mismatches: none")
    out_md.write_text("\n".join(lines) + "\n")


def _write_run_manifest(
    *,
    out_dir: Path,
    world_id: str,
    run_id: str,
    channel: str,
    plan_id: str,
    plan_digest: str,
    schema_version: str,
    apply_preflight_doc: Optional[Dict[str, Any]],
) -> Path:
    stage_used = os.environ.get("SANDBOX_LORE_STAGE_USED") == "1"
    stage_root = os.environ.get("SANDBOX_LORE_STAGE_ROOT")
    staged_output_root = os.environ.get("SANDBOX_LORE_STAGE_OUTPUT_ROOT")
    manifest = {
        "schema_version": schema_version,
        "run_id": run_id,
        "world_id": world_id,
        "channel": channel,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "stage_used": stage_used,
        "stage_root": stage_root,
        "repo_root_context": stage_root if stage_used else str(REPO_ROOT),
        "staged_output_root": staged_output_root,
        "output_root": path_utils.to_repo_relative(out_dir, repo_root=REPO_ROOT),
        "apply_preflight": apply_preflight_doc,
    }
    path = out_dir / "run_manifest.json"
    _write_json(path, manifest)
    return path


def _write_artifact_index(
    out_dir: Path,
    run_id: str,
    world_id: str,
    schema_version: str,
    expected_artifacts: Optional[Iterable[str]] = None,
) -> Path:
    artifacts = []
    missing = []
    for name in expected_artifacts or CORE_ARTIFACTS:
        path = out_dir / name
        if not path.exists():
            missing.append(path_utils.to_repo_relative(path, repo_root=REPO_ROOT))
            continue
        artifacts.append(
            {
                "path": path_utils.to_repo_relative(path, repo_root=REPO_ROOT),
                "file_size": path.stat().st_size,
                "sha256": _sha256_path(path),
                "schema_version": _extract_schema_version(path),
            }
        )
    index = {
        "schema_version": schema_version,
        "run_id": run_id,
        "world_id": world_id,
        "artifacts": artifacts,
        "missing": missing,
        "status": "ok" if not missing else "partial",
    }
    path = out_dir / "artifact_index.json"
    _write_json(path, index)
    return path


def load_bundle(out_dir: Path) -> Dict[str, Any]:
    out_dir = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    index_path = out_dir / "artifact_index.json"
    if not index_path.exists():
        raise FileNotFoundError(f"missing artifact_index.json in {out_dir}")
    index = json.loads(index_path.read_text())
    artifacts = index.get("artifacts") or []
    for entry in artifacts:
        path = path_utils.ensure_absolute(Path(entry["path"]), REPO_ROOT)
        if not path.exists():
            raise FileNotFoundError(f"missing artifact: {entry['path']}")
        expected = entry.get("sha256")
        if expected and _sha256_path(path) != expected:
            raise ValueError(f"digest mismatch for {entry['path']}")
    return index


def validate_bundle(out_dir: Path) -> ValidationResult:
    errors: list[str] = []
    try:
        index = load_bundle(out_dir)
    except Exception as exc:
        return ValidationResult(ok=False, errors=[str(exc)])
    if index.get("status") not in {"ok", "partial"}:
        errors.append(f"unexpected bundle status: {index.get('status')}")
    missing = index.get("missing") or []
    if missing:
        errors.append(f"missing artifacts: {missing}")
    return ValidationResult(ok=not errors, errors=errors)


def emit_promotion_packet(out_dir: Path, out_path: Path) -> Dict[str, Any]:
    out_dir = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    packet = {
        "schema_version": "runtime-tools.promotion_packet.v0.1",
        "run_manifest": path_utils.to_repo_relative(out_dir / "run_manifest.json", repo_root=REPO_ROOT),
        "expected_matrix": path_utils.to_repo_relative(out_dir / "expected_matrix.json", repo_root=REPO_ROOT),
        "runtime_results": path_utils.to_repo_relative(out_dir / "runtime_results.json", repo_root=REPO_ROOT),
        "runtime_events": path_utils.to_repo_relative(out_dir / "runtime_events.normalized.json", repo_root=REPO_ROOT),
        "baseline_results": path_utils.to_repo_relative(out_dir / "baseline_results.json", repo_root=REPO_ROOT),
        "oracle_results": path_utils.to_repo_relative(out_dir / "oracle_results.json", repo_root=REPO_ROOT),
        "mismatch_packets": path_utils.to_repo_relative(out_dir / "mismatch_packets.jsonl", repo_root=REPO_ROOT),
        "summary": path_utils.to_repo_relative(out_dir / "summary.json", repo_root=REPO_ROOT),
    }
    out_path = path_utils.ensure_absolute(out_path, REPO_ROOT)
    _write_json(out_path, packet)
    return packet


def build_runtime_inventory(repo_root: Path, out_path: Path) -> Dict[str, Any]:
    return runtime_inventory.build_runtime_inventory(repo_root=repo_root, out_path=out_path)


def _extract_schema_version(path: Path) -> Optional[str]:
    if path.suffix == ".jsonl":
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except Exception:
                return None
            return row.get("schema_version")
        return None
    if path.suffix == ".json":
        try:
            doc = json.loads(path.read_text())
        except Exception:
            return None
        if isinstance(doc, dict):
            return doc.get("schema_version")
    return None


def run_plan(
    plan_path: Path,
    out_dir: Path,
    *,
    channel: ChannelSpec | str = "direct",
    only_profiles: Optional[Iterable[str]] = None,
    only_scenarios: Optional[Iterable[str]] = None,
) -> RunBundle:
    channel_spec = channel if isinstance(channel, ChannelSpec) else ChannelSpec(channel=channel)
    if channel_spec.channel == "launchd_clean" and os.environ.get("SANDBOX_LORE_LAUNCHD_CLEAN") != "1":
        launchd_clean.run_via_launchctl(
            plan_path=plan_path,
            out_dir=out_dir,
            channel_spec=channel_spec,
            only_profiles=only_profiles,
            only_scenarios=only_scenarios,
        )
        run_manifest = path_utils.ensure_absolute(out_dir, REPO_ROOT) / "run_manifest.json"
        artifact_index = path_utils.ensure_absolute(out_dir, REPO_ROOT) / "artifact_index.json"
        status = "ok"
        if (path_utils.ensure_absolute(out_dir, REPO_ROOT) / "summary.json").exists():
            status = json.loads((path_utils.ensure_absolute(out_dir, REPO_ROOT) / "summary.json").read_text()).get("status") or "ok"
        return RunBundle(out_dir=path_utils.ensure_absolute(out_dir, REPO_ROOT), status=status, run_manifest=run_manifest, artifact_index=artifact_index)

    plan_doc = plan_loader.load_plan(plan_path)
    run_id = _run_id()
    world_id = plan_doc.get("world_id") or models.WORLD_ID
    out_dir = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    out_dir.mkdir(parents=True, exist_ok=True)
    channel_name = _channel_from_env(channel_spec.channel)

    schema_versions = plan_doc.get("schema_versions") or {}
    run_manifest_schema = schema_versions.get("run_manifest", RUN_MANIFEST_SCHEMA_VERSION)
    summary_schema = schema_versions.get("summary", SUMMARY_SCHEMA_VERSION)
    runtime_results_schema = schema_versions.get("runtime_results", RUNTIME_RESULTS_SCHEMA_VERSION)
    artifact_index_schema = schema_versions.get("artifact_index", ARTIFACT_INDEX_SCHEMA_VERSION)
    mismatch_schema = schema_versions.get("mismatch_packet", MISMATCH_PACKET_SCHEMA_VERSION)
    oracle_schema = schema_versions.get("oracle", ORACLE_SCHEMA_VERSION)
    baseline_schema = schema_versions.get("baseline", BASELINE_SCHEMA_VERSION)

    lanes = plan_doc.get("lanes") or {}
    profiles = plan_loader.compile_profiles(
        plan_doc,
        only_profiles=only_profiles,
        only_scenarios=only_scenarios,
    )
    if not profiles:
        raise RuntimeError("plan resolved to zero profiles")

    apply_preflight_doc = None
    apply_preflight_profile = plan_doc.get("apply_preflight_profile")
    if apply_preflight_profile:
        profile_path = path_utils.ensure_absolute(Path(apply_preflight_profile), REPO_ROOT)
        runner_path = REPO_ROOT / "book" / "experiments" / "runtime-checks" / "sandbox_runner"
        apply_preflight_doc = apply_preflight.run_apply_preflight(
            world_id=world_id,
            profile_path=profile_path,
            runner_path=runner_path,
        )
        apply_preflight_doc["schema_version"] = "runtime-tools.apply_preflight.v0.1"
        _write_json(out_dir / "apply_preflight.json", apply_preflight_doc)

    run_manifest = _write_run_manifest(
        out_dir=out_dir,
        world_id=world_id,
        run_id=run_id,
        channel=channel_name,
        plan_id=plan_doc["plan_id"],
        plan_digest=plan_loader.plan_digest(plan_doc),
        schema_version=run_manifest_schema,
        apply_preflight_doc={"path": "apply_preflight.json", "record": apply_preflight_doc}
        if apply_preflight_doc
        else None,
    )

    if lanes.get("scenario", True):
        run = workflow.run_profiles(profiles, out_dir, world_id=world_id)
        expected_matrix_path = out_dir / "expected_matrix.json"
        expected_matrix_path.write_text((out_dir / "expected_matrix.generated.json").read_text())

        runtime_results_path = out_dir / "runtime_results.json"
        _annotate_runtime_results(runtime_results_path, runtime_results_schema, run_id)

        normalize.write_matrix_observations(
            expected_matrix_path,
            runtime_results_path,
            out_dir / "runtime_events.normalized.json",
            world_id=world_id,
            run_id=run_id,
        )
    else:
        (out_dir / "expected_matrix.json").write_text((out_dir / "expected_matrix.generated.json").read_text())

    if lanes.get("baseline", True):
        baseline_doc = baseline_lane.build_baseline_results(
            world_id,
            profiles=[{"profile_id": p.profile_id, "probes": p.probes} for p in profiles],
            run_id=run_id,
        )
        baseline_doc["schema_version"] = baseline_schema
        _write_json(out_dir / "baseline_results.json", baseline_doc)

    if lanes.get("oracle", True):
        _write_oracle_results(out_dir / "runtime_events.normalized.json", world_id, out_dir / "oracle_results.json")
        oracle_doc = json.loads((out_dir / "oracle_results.json").read_text())
        oracle_doc["schema_version"] = oracle_schema
        _write_json(out_dir / "oracle_results.json", oracle_doc)

    mismatch_packets = []
    if (out_dir / "mismatch_summary.json").exists():
        mismatch_packets = mismatch_lane.emit_packets(
            mismatch_summary=out_dir / "mismatch_summary.json",
            events_path=out_dir / "runtime_events.normalized.json",
            baseline_results=out_dir / "baseline_results.json",
            run_manifest=run_manifest,
            out_path=out_dir / "mismatch_packets.jsonl",
        )
    if mismatch_packets:
        # Stamp schema version per packet.
        stamped = []
        for row in mismatch_packets:
            row = dict(row)
            row["schema_version"] = mismatch_schema
            stamped.append(row)
        (out_dir / "mismatch_packets.jsonl").write_text(
            "\n".join(json.dumps(p, sort_keys=True) for p in stamped) + "\n"
        )
    elif not (out_dir / "mismatch_packets.jsonl").exists():
        (out_dir / "mismatch_packets.jsonl").write_text("")

    if (out_dir / "mismatch_summary.json").exists():
        mismatch_summary_doc = json.loads((out_dir / "mismatch_summary.json").read_text())
    else:
        mismatch_summary_doc = {
            "world_id": world_id,
            "generated_by": "book/api/runtime_tools/api.py",
            "mismatches": [],
            "counts": {},
        }
        _write_json(out_dir / "mismatch_summary.json", mismatch_summary_doc)
    status = "ok" if not mismatch_summary_doc.get("mismatches") else "partial"

    _write_summary(
        world_id=world_id,
        run_id=run_id,
        expected_profiles=[p.profile_id for p in profiles],
        mismatch_summary=mismatch_summary_doc,
        status=status,
        out_json=out_dir / "summary.json",
        out_md=out_dir / "summary.md",
        schema_version=summary_schema,
    )

    expected_artifacts = [
        "run_manifest.json",
        "mismatch_summary.json",
        "mismatch_packets.jsonl",
        "summary.json",
        "summary.md",
    ]
    if lanes.get("scenario", True):
        expected_artifacts.extend(
            [
                "expected_matrix.generated.json",
                "expected_matrix.json",
                "runtime_results.json",
                "runtime_events.normalized.json",
            ]
        )
    if apply_preflight_doc:
        expected_artifacts.append("apply_preflight.json")
    if lanes.get("baseline", True):
        expected_artifacts.append("baseline_results.json")
    if lanes.get("oracle", True):
        expected_artifacts.append("oracle_results.json")

    artifact_index = _write_artifact_index(out_dir, run_id, world_id, artifact_index_schema, expected_artifacts)
    return RunBundle(out_dir=out_dir, status=status, run_manifest=run_manifest, artifact_index=artifact_index)
