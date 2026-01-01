"""
Runtime promotion packet emission (service contract).

This module defines the promotion packet schema and the rules for when a packet
may be treated as decision-stage promotable evidence.

Key points:
- Promotion packets are "pointers": repo-relative paths to bundle artifacts,
  plus a `promotability` block that states whether decision-stage promotion is
  allowed and why.
- Promotability is derived from bundle artifacts (run_manifest + strict bundle
  integrity) and is not caller-controlled.
- `require_promotable=True` is a strict mode that refuses to emit a packet that
  could be misread as promotable.

This module does not build mappings. Mapping generators consume promotion
packets and must continue to enforce gating; packet emission is an additional
ergonomic guardrail, not a replacement.

Promotion packets are an intentionally small, reviewable interface.
They decouple evidence capture from mapping promotion so we can audit inputs.
"""

from __future__ import annotations

import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api import path_utils

from .reader import load_bundle_index_strict, resolve_bundle_dir
from .writer import write_json_atomic


PROMOTION_PACKET_SCHEMA_VERSION = "runtime-tools.promotion_packet.v0.2"


class PromotabilityReason(StrEnum):
    """
    Enumerated reasons that decision-stage promotion is not allowed.

    The intent is to keep non-promotability "bounded and portable": callers can
    key off these reasons without re-deriving the gating logic.
    """

    MANIFEST_MISSING = "manifest_missing"
    RUN_STATUS_MISSING = "run_status_missing"
    BUNDLE_IN_PROGRESS = "bundle_in_progress"
    NOT_CLEAN_CHANNEL = "not_clean_channel"
    APPLY_PREFLIGHT_MISSING = "apply_preflight_missing"
    ALREADY_SANDBOXED = "already_sandboxed"
    APPLY_FAILED = "apply_failed"
    BUNDLE_INTEGRITY_UNVERIFIED = "bundle_integrity_unverified"
    BUNDLE_FAILED = "bundle_failed"
    BUNDLE_INCOMPLETE = "bundle_incomplete"
    DECISION_STAGE_ARTIFACTS_MISSING = "decision_stage_artifacts_missing"


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def assess_promotability(bundle_dir: Path, *, repo_root: Path) -> Dict[str, Any]:
    """
    Compute the promotion gating decision for a run-scoped bundle.

    Authoritative inputs:
    - `run_manifest.json` (channel + apply_preflight record)
    - strict bundle integrity (`artifact_index.json` + digest verification)
    - presence of decision-stage artifacts (results + normalized events)
    """

    # Promotability is *derived* from bundle artifacts; callers cannot override
    # this by passing flags. This keeps decision-stage evidence tier-disciplined.
    reasons: List[PromotabilityReason] = []
    promotable = True

    run_manifest_path = bundle_dir / "run_manifest.json"
    if not run_manifest_path.exists():
        promotable = False
        reasons.append(PromotabilityReason.MANIFEST_MISSING)
        run_manifest = {}
    else:
        run_manifest = _read_json(run_manifest_path)

    run_status_path = bundle_dir / "run_status.json"
    if run_status_path.exists():
        state = (_read_json(run_status_path).get("state") or "").strip()
        if state == "in_progress":
            promotable = False
            reasons.append(PromotabilityReason.BUNDLE_IN_PROGRESS)
    else:
        promotable = False
        reasons.append(PromotabilityReason.RUN_STATUS_MISSING)

    channel = run_manifest.get("channel")
    if channel != "launchd_clean":
        promotable = False
        reasons.append(PromotabilityReason.NOT_CLEAN_CHANNEL)

    apply_preflight = (run_manifest.get("apply_preflight") or {}).get("record") or {}
    if not apply_preflight:
        promotable = False
        reasons.append(PromotabilityReason.APPLY_PREFLIGHT_MISSING)
    else:
        sandboxed = (apply_preflight.get("sandbox_check_self") or {}).get("sandboxed")
        if sandboxed is True:
            promotable = False
            reasons.append(PromotabilityReason.ALREADY_SANDBOXED)
        if apply_preflight.get("apply_ok") is not True:
            promotable = False
            reasons.append(PromotabilityReason.APPLY_FAILED)

    try:
        # Strict bundle integrity is part of the promotability decision: if the
        # bundle cannot be loaded and verified, it is not decision-stage promotable.
        index = load_bundle_index_strict(bundle_dir, repo_root=repo_root)
    except Exception:
        promotable = False
        reasons.append(PromotabilityReason.BUNDLE_INTEGRITY_UNVERIFIED)
        index = {}

    if index.get("status") in {"failed"}:
        promotable = False
        reasons.append(PromotabilityReason.BUNDLE_FAILED)
    if index.get("missing"):
        promotable = False
        reasons.append(PromotabilityReason.BUNDLE_INCOMPLETE)

    for required in ("runtime_results.json", "runtime_events.normalized.json", "expected_matrix.json"):
        if not (bundle_dir / required).exists():
            promotable = False
            reasons.append(PromotabilityReason.DECISION_STAGE_ARTIFACTS_MISSING)
            break

    # Sort reasons for deterministic packet output and stable diffs.
    return {
        "promotable_decision_stage": promotable,
        "reasons": sorted({r.value for r in reasons}),
        "gating_inputs": {
            "channel": channel,
            "apply_preflight_present": bool(apply_preflight),
            "apply_ok": apply_preflight.get("apply_ok") if apply_preflight else None,
            "sandbox_check_self": apply_preflight.get("sandbox_check_self") if apply_preflight else None,
        },
    }


def emit_promotion_packet(
    bundle_dir: Path,
    out_path: Path,
    *,
    repo_root: Path,
    require_promotable: bool = False,
) -> Dict[str, Any]:
    """Emit a promotion packet for a bundle and optionally enforce promotability."""
    bundle_dir, _run_id = resolve_bundle_dir(bundle_dir, repo_root=repo_root)
    bundle_dir = path_utils.ensure_absolute(bundle_dir, repo_root)
    promotability = assess_promotability(bundle_dir, repo_root=repo_root)

    if require_promotable and not promotability.get("promotable_decision_stage"):
        # Strict mode refuses to emit a packet that could be misread as
        # decision-stage promotable by downstream tooling or future agents.
        reasons = promotability.get("reasons") or []
        raise RuntimeError(f"bundle is not promotable: {reasons}")

    packet: Dict[str, Any] = {
        "schema_version": PROMOTION_PACKET_SCHEMA_VERSION,
        "run_manifest": path_utils.to_repo_relative(bundle_dir / "run_manifest.json", repo_root=repo_root),
        "expected_matrix": path_utils.to_repo_relative(bundle_dir / "expected_matrix.json", repo_root=repo_root),
        "runtime_results": path_utils.to_repo_relative(bundle_dir / "runtime_results.json", repo_root=repo_root),
        "runtime_events": path_utils.to_repo_relative(bundle_dir / "runtime_events.normalized.json", repo_root=repo_root),
        "baseline_results": path_utils.to_repo_relative(bundle_dir / "baseline_results.json", repo_root=repo_root),
        "oracle_results": path_utils.to_repo_relative(bundle_dir / "oracle_results.json", repo_root=repo_root),
        "mismatch_packets": path_utils.to_repo_relative(bundle_dir / "mismatch_packets.jsonl", repo_root=repo_root),
        "summary": path_utils.to_repo_relative(bundle_dir / "summary.json", repo_root=repo_root),
        "promotability": promotability,
    }
    path_witnesses = bundle_dir / "path_witnesses.json"
    if path_witnesses.exists():
        packet["path_witnesses"] = path_utils.to_repo_relative(path_witnesses, repo_root=repo_root)
    fixtures = bundle_dir / "fixtures.json"
    if fixtures.exists():
        packet["fixtures"] = path_utils.to_repo_relative(fixtures, repo_root=repo_root)
    impact_map = bundle_dir / "impact_map.json"
    if impact_map.exists():
        packet["impact_map"] = path_utils.to_repo_relative(impact_map, repo_root=repo_root)

    out_path = path_utils.ensure_absolute(out_path, repo_root)
    write_json_atomic(out_path, packet)
    return packet
