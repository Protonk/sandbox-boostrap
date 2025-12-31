"""
Runtime service API (plan execution + bundle lifecycle).

This module is the orchestration layer for plan-based runtime runs. It is
responsible for:
- Running a plan (`plan.json`) under a specified channel (direct or launchd_clean).
- Producing a run-scoped bundle directory at `out/<run_id>/...`.
- Writing lifecycle markers (`run_status.json`, `run_manifest.json`) and a stable
  commit barrier (`artifact_index.json`).
- Updating `out/LATEST` only after the run-scoped bundle is committed so callers
  can safely resolve a bundle root to the newest committed run.

This module assumes the plan-data and registries are valid inputs. It guarantees
that bundle state is explicit (`run_status.state` is in_progress/complete/failed),
that strict bundle loads verify digests, and that promotion packet emission
enforces clean-channel gating rather than trusting caller intent.

This module deliberately refuses to "repair" bundles implicitly; repairs are
explicit (`reindex_bundle`) and leave an audit log. Mapping generation remains
outside runtime; the contract boundary is the promotion packet.

The service layer is about provenance. It records what ran, how it
ran, and which artifacts are trustworthy before any mapping is attempted.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, Optional, Tuple

from book.api import path_utils
from .lanes import baseline as baseline_lane
from .lanes import mismatch as mismatch_lane
from ..plans import loader as plan_loader
from . import preflight as apply_preflight
from . import workflow
from ..analysis import inventory as runtime_inventory
from .lanes import path_witnesses
from ..contracts import normalize
from ..contracts import models
from .channels import ChannelSpec
from .channels import launchd_clean
from ..bundles.reader import load_bundle_index_strict as _load_bundle_index_strict
from ..bundles.reader import open_bundle_unverified as _open_bundle_unverified
from ..bundles.reader import resolve_bundle_dir as _resolve_bundle_dir_impl
from ..bundles.writer import write_artifact_index as _write_artifact_index_impl
from ..bundles.writer import write_json_atomic as _write_json_atomic
from ..bundles.writer import write_text_atomic as _write_text_atomic
from ..bundles.promotion import emit_promotion_packet as _emit_promotion_packet_impl


REPO_ROOT = path_utils.find_repo_root(Path(__file__))

RUN_MANIFEST_SCHEMA_VERSION = "runtime-tools.run_manifest.v0.1"
RUN_STATUS_SCHEMA_VERSION = "runtime-tools.run_status.v0.1"
SUMMARY_SCHEMA_VERSION = "runtime-tools.summary.v0.1"
RUNTIME_RESULTS_SCHEMA_VERSION = "runtime-tools.runtime_results.v0.1"
ARTIFACT_INDEX_SCHEMA_VERSION = "runtime-tools.artifact_index.v0.1"
MISMATCH_PACKET_SCHEMA_VERSION = "runtime-tools.mismatch_packet.v0.1"
ORACLE_SCHEMA_VERSION = "runtime-tools.oracle_results.v0.1"
BASELINE_SCHEMA_VERSION = "runtime-tools.baseline_results.v0.1"
PATH_WITNESSES_SCHEMA_VERSION = "runtime-tools.path_witnesses.v0.1"
STATUS_SCHEMA_VERSION = "runtime-tools.status.v0.1"

# Keep core artifacts ordered for deterministic artifact indexes and summaries.
CORE_ARTIFACTS = [
    "run_status.json",
    "run_manifest.json",
    "apply_preflight.json",
    "baseline_results.json",
    "path_witnesses.json",
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


def _run_id() -> str:
    run_id = os.environ.get("SANDBOX_LORE_RUN_ID")
    if run_id:
        return run_id
    run_id = str(uuid.uuid4())
    os.environ["SANDBOX_LORE_RUN_ID"] = run_id
    return run_id


def _channel_from_env(default: str) -> str:
    return os.environ.get("SANDBOX_LORE_CHANNEL") or default


def runtime_status(repo_root: Optional[Path] = None) -> Dict[str, Any]:
    """Return a structured snapshot of the runtime execution environment."""
    repo_root = path_utils.ensure_absolute(repo_root or REPO_ROOT, REPO_ROOT)
    stage_used = os.environ.get("SANDBOX_LORE_STAGE_USED") == "1"
    stage_root = os.environ.get("SANDBOX_LORE_STAGE_ROOT")
    stage_output_root = os.environ.get("SANDBOX_LORE_STAGE_OUTPUT_ROOT")
    clean_active = os.environ.get("SANDBOX_LORE_LAUNCHD_CLEAN") == "1"
    status = {
        "schema_version": STATUS_SCHEMA_VERSION,
        "world_id": models.WORLD_ID,
        "repo_root": str(path_utils.to_repo_relative(repo_root, repo_root=REPO_ROOT)),
        "channel": _channel_from_env("direct"),
        "clean_channel_active": clean_active,
        "stage_used": stage_used,
        "stage_root": stage_root,
        "stage_output_root": stage_output_root,
        "run_id": os.environ.get("SANDBOX_LORE_RUN_ID"),
        "sandbox_check_self": apply_preflight.sandbox_check_self(),
        "tools": {
            "launchctl": bool(shutil.which("launchctl")),
            "sandbox_runner": (REPO_ROOT / "book" / "api" / "runtime" / "native" / "sandbox_runner" / "sandbox_runner").exists(),
        },
    }
    return status


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    _write_json_atomic(path, payload)


def _write_text(path: Path, text: str) -> None:
    _write_text_atomic(path, text)


@contextlib.contextmanager
def _bundle_lock(
    lock_path: Path,
    *,
    mode: str,
    timeout_seconds: float,
) -> Iterator[None]:
    # Bundle-root lock used to prevent concurrent writers corrupting `LATEST` or
    # interleaving artifact writes under the same output root.
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = lock_path.open("a+")
    fh.seek(0)
    fh.truncate()
    fh.write(f"pid={os.getpid()}\n")
    fh.flush()

    start = time.monotonic()
    if mode not in {"fail", "wait"}:
        raise ValueError(f"invalid lock_mode: {mode!r}")
    while True:
        try:
            fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if mode == "fail":
                raise RuntimeError(f"runtime bundle is locked: {lock_path}")
            if time.monotonic() - start >= timeout_seconds:
                raise RuntimeError(f"runtime lock timeout after {timeout_seconds}s: {lock_path}")
            time.sleep(0.05)
    try:
        yield None
    finally:
        try:
            fcntl.flock(fh, fcntl.LOCK_UN)
        finally:
            fh.close()


def _resolve_bundle_dir(bundle_dir: Path) -> Tuple[Path, Optional[str]]:
    # Bundle roots resolve via `out/LATEST` to the most recent committed run.
    return _resolve_bundle_dir_impl(bundle_dir, repo_root=REPO_ROOT)


def _write_run_status(
    *,
    out_dir: Path,
    run_id: str,
    world_id: str,
    channel: str,
    plan_id: str,
    plan_digest: str,
    state: str,
    error: Optional[str] = None,
    failure_stage: Optional[str] = None,
) -> Path:
    payload: Dict[str, Any] = {
        "schema_version": RUN_STATUS_SCHEMA_VERSION,
        "run_id": run_id,
        "world_id": world_id,
        "channel": channel,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "state": state,
        "writer_pid": os.getpid(),
        "updated_at_unix": time.time(),
        "error": error,
        "failure_stage": failure_stage,
    }
    path = out_dir / "run_status.json"
    _write_json(path, payload)
    return path


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
    plan_id: str,
    plan_digest: str,
    channel: str,
    lanes: Dict[str, bool],
    expected_profiles: Iterable[str],
    profile_count: int,
    scenario_count: int,
    mismatch_summary: Dict[str, Any],
    status: str,
    out_json: Path,
    out_md: Path,
    schema_version: str,
    dry_run: bool = False,
) -> None:
    summary = {
        "schema_version": schema_version,
        "world_id": world_id,
        "run_id": run_id,
        "status": status,
        "plan_id": plan_id,
        "plan_digest": plan_digest,
        "channel": channel,
        "lanes": lanes,
        "profile_count": profile_count,
        "scenario_count": scenario_count,
        "expected_profiles": list(expected_profiles),
        "mismatch_counts": mismatch_summary.get("counts") or {},
        "dry_run": dry_run,
    }
    _write_json(out_json, summary)
    lines = [
        "# Runtime Summary",
        "",
        f"Status: {status}",
        f"Plan: {plan_id}",
        f"Channel: {channel}",
        f"Profiles: {profile_count}",
        f"Scenarios: {scenario_count}",
        "",
    ]
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
    dry_run: bool = False,
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
        "dry_run": dry_run,
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
    *,
    status_override: Optional[str] = None,
) -> Path:
    # The artifact index is the bundle commit barrier (written last).
    return _write_artifact_index_impl(
        out_dir,
        run_id=run_id,
        world_id=world_id,
        schema_version=schema_version,
        expected_artifacts=expected_artifacts or CORE_ARTIFACTS,
        repo_root=REPO_ROOT,
        status_override=status_override,
    )


def load_bundle(out_dir: Path) -> Dict[str, Any]:
    """Strictly load a bundle (verify digests, refuse in-progress bundles)."""
    # Strict loader: refuses in-progress bundles and verifies digests.
    return _load_bundle_index_strict(out_dir, repo_root=REPO_ROOT)


def validate_bundle(out_dir: Path) -> ValidationResult:
    """Validate a bundle and return a structured OK/error summary."""
    errors: list[str] = []
    try:
        index = load_bundle(out_dir)
    except Exception as exc:
        return ValidationResult(ok=False, errors=[str(exc)])
    if index.get("status") not in {"ok", "partial", "failed"}:
        errors.append(f"unexpected bundle status: {index.get('status')}")
    missing = index.get("missing") or []
    if missing:
        errors.append(f"missing artifacts: {missing}")
    return ValidationResult(ok=not errors, errors=errors)


def open_bundle_unverified(out_dir: Path) -> Dict[str, Any]:
    """Load a bundle without digest or completeness checks (debug only)."""
    return _open_bundle_unverified(out_dir, repo_root=REPO_ROOT)


def reindex_bundle(out_dir: Path, *, repair: bool = False) -> Dict[str, Any]:
    """Recompute a bundle index; optionally repair digest mismatches."""
    bundle_dir, _run_id = _resolve_bundle_dir(out_dir)
    bundle_dir = path_utils.ensure_absolute(bundle_dir, REPO_ROOT)

    if not repair:
        _ = load_bundle(bundle_dir)
        return {"status": "ok", "bundle_dir": str(path_utils.to_repo_relative(bundle_dir, repo_root=REPO_ROOT))}

    status_path = bundle_dir / "run_status.json"
    if status_path.exists():
        state = (json.loads(status_path.read_text()).get("state") or "").strip()
        if state == "in_progress":
            raise RuntimeError("refusing to repair an in-progress bundle")

    manifest_path = bundle_dir / "run_manifest.json"
    run_id = None
    world_id = None
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())
        run_id = manifest.get("run_id")
        world_id = manifest.get("world_id")
    run_id = run_id or _run_id() or "unknown"
    world_id = world_id or models.WORLD_ID

    before = open_bundle_unverified(bundle_dir)
    _write_artifact_index(
        bundle_dir,
        run_id,
        world_id,
        ARTIFACT_INDEX_SCHEMA_VERSION,
        expected_artifacts=[p for p in CORE_ARTIFACTS if (bundle_dir / p).exists()],
    )
    after = open_bundle_unverified(bundle_dir)
    repair_log = {
        "schema_version": "runtime-tools.repair_log.v0.1",
        "bundle_dir": str(path_utils.to_repo_relative(bundle_dir, repo_root=REPO_ROOT)),
        "repaired_at_unix": time.time(),
        "before": {
            "missing": before.get("missing"),
            "digest_mismatches": before.get("digest_mismatches"),
        },
        "after": {
            "missing": after.get("missing"),
            "digest_mismatches": after.get("digest_mismatches"),
        },
    }
    _write_json(bundle_dir / "repair_log.json", repair_log)
    return {"status": "repaired", "bundle_dir": str(path_utils.to_repo_relative(bundle_dir, repo_root=REPO_ROOT))}


def emit_promotion_packet(out_dir: Path, out_path: Path, *, require_promotable: bool = False) -> Dict[str, Any]:
    """Emit a promotion packet for a bundle."""
    # Packet emission enforces clean-channel gating and records promotability.
    return _emit_promotion_packet_impl(
        out_dir,
        out_path,
        repo_root=REPO_ROOT,
        require_promotable=require_promotable,
    )


def build_runtime_inventory(repo_root: Path, out_path: Path) -> Dict[str, Any]:
    """Build and write the runtime inventory document."""
    return runtime_inventory.build_runtime_inventory(repo_root=repo_root, out_path=out_path)


def run_plan(
    plan_path: Path,
    out_dir: Path,
    *,
    channel: ChannelSpec | str = "direct",
    only_profiles: Optional[Iterable[str]] = None,
    only_scenarios: Optional[Iterable[str]] = None,
    dry_run: bool = False,
) -> RunBundle:
    """Execute a runtime plan and write a run-scoped bundle."""
    channel_spec = channel if isinstance(channel, ChannelSpec) else ChannelSpec(channel=channel)
    plan_doc = plan_loader.load_plan(plan_path)
    run_id = _run_id()
    world_id = plan_doc.get("world_id") or models.WORLD_ID
    out_root = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    out_root.mkdir(parents=True, exist_ok=True)
    channel_name = _channel_from_env(channel_spec.channel)

    # Critical section: we serialize writers at the bundle root.
    # The lock protects run directory creation and the `LATEST` pointer update.
    lock_path = out_root / ".runtime.lock"
    lock_ctx: contextlib.AbstractContextManager[None]
    if channel_spec.lock:
        lock_ctx = _bundle_lock(
            lock_path,
            mode=channel_spec.lock_mode,
            timeout_seconds=float(channel_spec.lock_timeout_seconds),
        )
    else:
        lock_ctx = contextlib.nullcontext()

    with lock_ctx:
        if (
            channel_spec.channel == "launchd_clean"
            and os.environ.get("SANDBOX_LORE_LAUNCHD_CLEAN") != "1"
            and not dry_run
        ):
            # Clean-channel runs must start from an unsandboxed process context.
            # We stage the repo, invoke a fresh worker via launchd, and sync the
            # staged `out/<run_id>/...` bundle back into the repo output root.
            launchd_clean.run_via_launchctl(
                plan_path=plan_path,
                out_dir=out_root,
                channel_spec=channel_spec,
                only_profiles=only_profiles,
                only_scenarios=only_scenarios,
                run_id=run_id,
            )
            run_dir = out_root / run_id
            run_manifest = run_dir / "run_manifest.json"
            artifact_index = run_dir / "artifact_index.json"
            status = "failed"
            if (run_dir / "summary.json").exists():
                status = json.loads((run_dir / "summary.json").read_text()).get("status") or "failed"
            return RunBundle(out_dir=run_dir, status=status, run_manifest=run_manifest, artifact_index=artifact_index)

        run_dir = out_root / run_id
        if run_dir.exists():
            raise RuntimeError(f"run_dir already exists: {run_dir}")
        run_dir.mkdir(parents=True, exist_ok=False)

        run_manifest_schema = RUN_MANIFEST_SCHEMA_VERSION
        summary_schema = SUMMARY_SCHEMA_VERSION
        runtime_results_schema = RUNTIME_RESULTS_SCHEMA_VERSION
        artifact_index_schema = ARTIFACT_INDEX_SCHEMA_VERSION
        mismatch_schema = MISMATCH_PACKET_SCHEMA_VERSION
        oracle_schema = ORACLE_SCHEMA_VERSION
        baseline_schema = BASELINE_SCHEMA_VERSION
        path_witnesses_schema = PATH_WITNESSES_SCHEMA_VERSION

        lanes = plan_doc.get("lanes") or {}
        effective_lanes = dict(lanes)
        if dry_run:
            effective_lanes.update({"scenario": False, "baseline": False, "oracle": False})

        profiles = plan_loader.compile_profiles(
            plan_doc,
            only_profiles=only_profiles,
            only_scenarios=only_scenarios,
        )
        if not profiles:
            raise RuntimeError("plan resolved to zero profiles")

        plan_id = plan_doc["plan_id"]
        plan_digest = plan_loader.plan_digest(plan_doc)

        # First durable marker: record that the run has started and is writing.
        _write_run_status(
            out_dir=run_dir,
            run_id=run_id,
            world_id=world_id,
            channel=channel_name,
            plan_id=plan_id,
            plan_digest=plan_digest,
            state="in_progress",
        )

        error: Optional[str] = None
        failure_stage: Optional[str] = None
        apply_preflight_doc = None
        run_manifest_path = run_dir / "run_manifest.json"
        run_manifest = run_manifest_path
        try:
            apply_preflight_profile = plan_doc.get("apply_preflight_profile")
            if apply_preflight_profile and not dry_run:
                profile_path = path_utils.ensure_absolute(Path(apply_preflight_profile), REPO_ROOT)
                runner_path = (
                    REPO_ROOT / "book" / "api" / "runtime" / "native" / "sandbox_runner" / "sandbox_runner"
                )
                apply_preflight_doc = apply_preflight.run_apply_preflight(
                    world_id=world_id,
                    profile_path=profile_path,
                    runner_path=runner_path,
                )
                apply_preflight_doc["schema_version"] = "runtime-tools.apply_preflight.v0.1"
                _write_json(run_dir / "apply_preflight.json", apply_preflight_doc)

            run_manifest = _write_run_manifest(
                out_dir=run_dir,
                world_id=world_id,
                run_id=run_id,
                channel=channel_name,
                plan_id=plan_id,
                plan_digest=plan_digest,
                schema_version=run_manifest_schema,
                apply_preflight_doc={"path": "apply_preflight.json", "record": apply_preflight_doc}
                if apply_preflight_doc
                else None,
                dry_run=dry_run,
            )

            if effective_lanes.get("scenario", True):
                _ = workflow.run_profiles(profiles, run_dir, world_id=world_id)
                expected_matrix_path = run_dir / "expected_matrix.json"
                expected_matrix_path.write_text((run_dir / "expected_matrix.generated.json").read_text())

                runtime_results_path = run_dir / "runtime_results.json"
                _annotate_runtime_results(runtime_results_path, runtime_results_schema, run_id)

                normalize.write_matrix_observations(
                    expected_matrix_path,
                    runtime_results_path,
                    run_dir / "runtime_events.normalized.json",
                    world_id=world_id,
                    run_id=run_id,
                )
            else:
                matrix_doc = workflow.build_matrix(world_id, profiles, run_dir / "sb_build")
                (run_dir / "expected_matrix.generated.json").write_text(json.dumps(matrix_doc, indent=2))
                (run_dir / "expected_matrix.json").write_text((run_dir / "expected_matrix.generated.json").read_text())

            if effective_lanes.get("baseline", True):
                baseline_doc = baseline_lane.build_baseline_results(
                    world_id,
                    profiles=[{"profile_id": p.profile_id, "probes": p.probes} for p in profiles],
                    run_id=run_id,
                )
                baseline_doc["schema_version"] = baseline_schema
                _write_json(run_dir / "baseline_results.json", baseline_doc)

            if effective_lanes.get("oracle", True):
                _write_oracle_results(
                    run_dir / "runtime_events.normalized.json",
                    world_id,
                    run_dir / "oracle_results.json",
                )
                oracle_doc = json.loads((run_dir / "oracle_results.json").read_text())
                oracle_doc["schema_version"] = oracle_schema
                _write_json(run_dir / "oracle_results.json", oracle_doc)

            if effective_lanes.get("scenario", True) or effective_lanes.get("baseline", True):
                path_witnesses_doc = path_witnesses.build_path_witnesses_doc(
                    run_dir,
                    world_id=world_id,
                    run_id=run_id,
                    plan_id=plan_id,
                )
                path_witnesses_doc["schema_version"] = path_witnesses_schema
                _write_json(run_dir / "path_witnesses.json", path_witnesses_doc)

            mismatch_packets = []
            if effective_lanes.get("scenario", True) and (run_dir / "mismatch_summary.json").exists():
                mismatch_packets = mismatch_lane.emit_packets(
                    mismatch_summary=run_dir / "mismatch_summary.json",
                    events_path=run_dir / "runtime_events.normalized.json",
                    baseline_results=run_dir / "baseline_results.json",
                    run_manifest=run_manifest,
                    out_path=run_dir / "mismatch_packets.jsonl",
                )
            if mismatch_packets:
                stamped = []
                for row in mismatch_packets:
                    row = dict(row)
                    row["schema_version"] = mismatch_schema
                    stamped.append(row)
                (run_dir / "mismatch_packets.jsonl").write_text(
                    "\n".join(json.dumps(p, sort_keys=True) for p in stamped) + "\n"
                )
            elif not (run_dir / "mismatch_packets.jsonl").exists():
                (run_dir / "mismatch_packets.jsonl").write_text("")

            if (run_dir / "mismatch_summary.json").exists():
                mismatch_summary_doc = json.loads((run_dir / "mismatch_summary.json").read_text())
            else:
                mismatch_summary_doc = {
                    "world_id": world_id,
                    "generated_by": "book/api/runtime/execution/service.py",
                    "mismatches": [],
                    "counts": {},
                }
                _write_json(run_dir / "mismatch_summary.json", mismatch_summary_doc)
        except Exception as exc:
            # Failure path must still leave a readable bundle:
            # emit empty mismatch artifacts so consumers don't crash on missing files.
            error = str(exc)
            failure_stage = "exception"
            mismatch_summary_doc = {
                "world_id": world_id,
                "generated_by": "book/api/runtime/execution/service.py",
                "mismatches": [],
                "counts": {},
                "error": error,
            }
            _write_json(run_dir / "mismatch_summary.json", mismatch_summary_doc)
            if not (run_dir / "mismatch_packets.jsonl").exists():
                (run_dir / "mismatch_packets.jsonl").write_text("")

        status = "ok" if not mismatch_summary_doc.get("mismatches") else "partial"
        if error:
            status = "failed"
        if dry_run and not error:
            status = "dry"

        scenario_count = sum(len(p.probes) for p in profiles)
        _write_summary(
            world_id=world_id,
            run_id=run_id,
            plan_id=plan_id,
            plan_digest=plan_digest,
            channel=channel_name,
            lanes=effective_lanes,
            expected_profiles=[p.profile_id for p in profiles],
            profile_count=len(profiles),
            scenario_count=scenario_count,
            mismatch_summary=mismatch_summary_doc,
            status=status,
            out_json=run_dir / "summary.json",
            out_md=run_dir / "summary.md",
            schema_version=summary_schema,
            dry_run=dry_run,
        )

        expected_artifacts = [
            "run_status.json",
            "run_manifest.json",
            "mismatch_summary.json",
            "mismatch_packets.jsonl",
            "summary.json",
            "summary.md",
        ]
        if effective_lanes.get("scenario", True):
            expected_artifacts.extend(
                [
                    "expected_matrix.generated.json",
                    "expected_matrix.json",
                    "runtime_results.json",
                    "runtime_events.normalized.json",
                ]
            )
        else:
            expected_artifacts.extend(
                [
                    "expected_matrix.generated.json",
                    "expected_matrix.json",
                ]
            )
        if apply_preflight_doc:
            expected_artifacts.append("apply_preflight.json")
        if effective_lanes.get("baseline", True):
            expected_artifacts.append("baseline_results.json")
        if effective_lanes.get("scenario", True) or effective_lanes.get("baseline", True):
            expected_artifacts.append("path_witnesses.json")
        if effective_lanes.get("oracle", True):
            expected_artifacts.append("oracle_results.json")

        # Commit sequence (order matters):
        # 1) finalize run_status.json
        # 2) write artifact_index.json (bundle commit barrier)
        # 3) update out/LATEST pointer
        _write_run_status(
            out_dir=run_dir,
            run_id=run_id,
            world_id=world_id,
            channel=channel_name,
            plan_id=plan_id,
            plan_digest=plan_digest,
            state="complete" if status not in {"failed"} else "failed",
            error=error,
            failure_stage=failure_stage,
        )
        artifact_index = _write_artifact_index(
            run_dir,
            run_id,
            world_id,
            artifact_index_schema,
            expected_artifacts,
            status_override="failed" if status == "failed" else None,
        )
        _write_text(out_root / "LATEST", f"{run_id}\n")
        return RunBundle(out_dir=run_dir, status=status, run_manifest=run_manifest, artifact_index=artifact_index)
