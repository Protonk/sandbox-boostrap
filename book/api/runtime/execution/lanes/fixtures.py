"""
Fixture marker extraction for runtime bundles.

This builds a small lane-scoped fixture record so prereq state stays explicit
in the bundle rather than being an implicit harness side effect.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional


FIXTURE_SCHEMA_VERSION = "runtime-tools.fixture_marker.v0.1"
FIXTURES_SCHEMA_VERSION = "runtime-tools.fixtures.v0.1"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8", errors="ignore"))


def _is_network_outbound(op: Optional[str]) -> bool:
    return op == "network-outbound"


def build_fixture_markers_doc(
    run_dir: Path,
    *,
    world_id: str,
    run_id: str,
    plan_id: str,
) -> Dict[str, Any]:
    """Build a fixtures document from bundle artifacts."""
    records: List[Dict[str, Any]] = []
    runtime_results = _load_json(run_dir / "runtime_results.json")
    for profile_id, profile in (runtime_results or {}).items():
        if not isinstance(profile, dict):
            continue
        for probe in profile.get("probes") or []:
            if not isinstance(probe, dict):
                continue
            op = probe.get("operation")
            if not _is_network_outbound(op):
                continue
            records.append(
                {
                    "schema_version": FIXTURE_SCHEMA_VERSION,
                    "fixture_id": "loopback_listener",
                    "lane": "scenario",
                    "profile_id": profile_id,
                    "probe_name": probe.get("name"),
                    "scenario_id": probe.get("expectation_id"),
                    "operation": op,
                    "target": probe.get("path") or probe.get("target"),
                    "listener": probe.get("listener"),
                }
            )

    baseline_results = _load_json(run_dir / "baseline_results.json")
    for row in (baseline_results.get("results") or []):
        if not isinstance(row, dict):
            continue
        op = row.get("operation")
        if not _is_network_outbound(op):
            continue
        records.append(
            {
                "schema_version": FIXTURE_SCHEMA_VERSION,
                "fixture_id": "loopback_listener",
                "lane": "baseline",
                "profile_id": row.get("profile_id"),
                "probe_name": row.get("probe_name"),
                "scenario_id": row.get("name"),
                "operation": op,
                "target": row.get("target"),
                "listener": row.get("listener"),
            }
        )

    return {
        "schema_version": FIXTURES_SCHEMA_VERSION,
        "world_id": world_id,
        "run_id": run_id,
        "plan_id": plan_id,
        "records": records,
    }
