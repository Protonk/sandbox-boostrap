"""
Runtime wrapper for the Field2 Atlas experiment.

This maps field2 seeds to concrete runtime probes (one per seed where available)
and emits `out/runtime/field2_runtime_results.json`. It reuses canonical runtime
signatures for this host to keep the harness field2-tagged.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Optional

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())
DEFAULT_SEEDS = Path(__file__).with_name("field2_seeds.json")
DEFAULT_RUNTIME_SIGNATURES = REPO_ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_signatures.json"
DEFAULT_PROMOTION_PACKET = (
    REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "promotion_packet.json"
)
DEFAULT_RUNTIME_EVENTS = [
    REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "runtime_events.normalized.json",
]
DEFAULT_HISTORICAL_EVENTS = REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "historical_runtime_events.json"
DEFAULT_RUN_MANIFEST = REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "run_manifest.json"
DEFAULT_BASELINE_RESULTS = REPO_ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "baseline_results.json"
DEFAULT_ANCHOR_MAP = REPO_ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json"
DEFAULT_OUTPUT = Path(__file__).with_name("out") / "runtime" / "field2_runtime_results.json"

# For the initial seed slice, pick one canonical runtime signature per field2.
RUNTIME_CANDIDATES = {
    0: {"profile_id": "adv:path_edges", "probe_name": "allow-tmp", "scenario_id": "field2-0-path_edges"},
    1: {"profile_id": "adv:path_edges", "probe_name": "allow-subpath", "scenario_id": "field2-1-path-subpath"},
    5: {"profile_id": "adv:mach_simple_allow", "probe_name": "allow-cfprefsd", "scenario_id": "field2-5-mach-global"},
    7: {"profile_id": "adv:mach_local_literal", "probe_name": "allow-cfprefsd-local", "scenario_id": "field2-7-mach-local"},
    2560: {
        "profile_id": "adv:flow_divert_require_all_tcp",
        "probe_name": "tcp-loopback",
        "scenario_id": "field2-2560-flow-divert",
    },
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _lookup_probe(runtime_doc: Dict[str, Any], profile_id: str, probe_name: str) -> Optional[Dict[str, Any]]:
    profile_block = runtime_doc.get("expected_matrix", {}).get("profiles", {}).get(profile_id)
    if not profile_block:
        return None
    for probe in profile_block.get("probes", []):
        if probe.get("name") == probe_name:
            return probe
    return None


def _load_runtime_events(paths: list[Path], tier: str) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            continue
        for row in load_json(path) or []:
            if isinstance(row, dict):
                row = dict(row)
                row["source"] = path_utils.to_repo_relative(path, repo_root=REPO_ROOT)
                row["tier"] = tier
                events.append(row)
    return events


def _load_promotion_paths(packet_path: Path) -> Optional[Dict[str, Path]]:
    if not packet_path.exists():
        return None
    doc = load_json(packet_path)
    paths: Dict[str, Path] = {}
    for key in ("runtime_events", "baseline_results", "run_manifest"):
        value = doc.get(key)
        if value:
            paths[key] = path_utils.ensure_absolute(Path(value), repo_root=REPO_ROOT)
    if not paths:
        return None
    paths["promotion_packet"] = packet_path
    return paths


def _load_baseline_results(path: Path) -> Dict[tuple[str, str], Dict[str, Any]]:
    if not path.exists():
        return {}
    doc = load_json(path)
    out: Dict[tuple[str, str], Dict[str, Any]] = {}
    for row in doc.get("results") or []:
        profile_id = row.get("profile_id")
        probe_name = row.get("probe_name")
        if profile_id and probe_name:
            out[(profile_id, probe_name)] = row
    return out


def _index_runtime_events(events: list[Dict[str, Any]]) -> Dict[tuple[str, str], Dict[str, Any]]:
    indexed: Dict[tuple[str, str], Dict[str, Any]] = {}
    for row in events:
        profile_id = row.get("profile_id")
        probe_name = row.get("probe_name")
        if not profile_id or not probe_name:
            continue
        indexed[(profile_id, probe_name)] = row
    return indexed


def _anchor_alias_path(path: str) -> tuple[str, bool]:
    if path.startswith("/private/tmp/"):
        return "/tmp/" + path[len("/private/tmp/") :], True
    if path == "/private/tmp":
        return "/tmp", True
    return path, False


def _anchor_match(anchor_map: Dict[str, Any], normalized_path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not normalized_path:
        return None
    entry = anchor_map.get(normalized_path)
    if entry:
        return {"anchor": normalized_path, "alias_used": False, "entry": entry}
    alias_path, used = _anchor_alias_path(normalized_path)
    entry = anchor_map.get(alias_path)
    if entry:
        return {"anchor": alias_path, "alias_used": used, "entry": entry}
    return None


def _canonicalization_detected(event: Optional[Dict[str, Any]]) -> bool:
    if not event:
        return False
    requested = event.get("requested_path") or ""
    normalized = event.get("normalized_path") or ""
    if isinstance(requested, str) and isinstance(normalized, str):
        if requested.startswith("/tmp") and normalized.startswith("/private/tmp"):
            return True
    return False

def _is_blocked_event(event: Optional[Dict[str, Any]]) -> bool:
    if not event:
        return False
    if event.get("runtime_status") == "blocked":
        return True
    if event.get("failure_stage") in {"apply", "bootstrap", "preflight"}:
        return True
    return False


def _path_witness(events_by_key: Dict[tuple[str, str], Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    profile_id = "adv:path_alias"
    probes = []
    for probe_name in ("alias-tmp", "alias-private"):
        row = events_by_key.get((profile_id, probe_name))
        if not row:
            continue
        probes.append(
            {
                "probe_name": probe_name,
                "requested_path": row.get("requested_path"),
                "observed_path": row.get("observed_path"),
                "observed_path_source": row.get("observed_path_source"),
                "normalized_path": row.get("normalized_path"),
                "normalized_path_source": row.get("normalized_path_source"),
                "actual": row.get("actual"),
            }
        )
    if not probes:
        return None
    return {
        "profile_id": profile_id,
        "probes": probes,
        "source": events_by_key.get((profile_id, probes[0]["probe_name"])).get("source"),
    }


def build_runtime_results(
    seeds_path: Path = DEFAULT_SEEDS,
    runtime_signatures_path: Path = DEFAULT_RUNTIME_SIGNATURES,
    promotion_packet_path: Path = DEFAULT_PROMOTION_PACKET,
) -> Dict[str, Any]:
    seeds_doc = load_json(seeds_path)
    runtime_doc = load_json(runtime_signatures_path)
    anchor_map = load_json(DEFAULT_ANCHOR_MAP)
    promotion_paths = _load_promotion_paths(promotion_packet_path)
    runtime_event_paths = list(DEFAULT_RUNTIME_EVENTS)
    baseline_path = DEFAULT_BASELINE_RESULTS
    run_manifest_path = DEFAULT_RUN_MANIFEST
    if promotion_paths:
        runtime_event = promotion_paths.get("runtime_events")
        baseline = promotion_paths.get("baseline_results")
        manifest = promotion_paths.get("run_manifest")
        if runtime_event:
            runtime_event_paths = [runtime_event]
        if baseline:
            baseline_path = baseline
        if manifest:
            run_manifest_path = manifest
    events = _load_runtime_events(runtime_event_paths, tier="current")
    historical_events = _load_runtime_events([DEFAULT_HISTORICAL_EVENTS], tier="historical")
    events_by_key = _index_runtime_events(events)
    historical_by_key = _index_runtime_events(historical_events)
    baseline_by_key = _load_baseline_results(baseline_path)
    signatures = runtime_doc.get("signatures") or {}
    profiles_meta = runtime_doc.get("profiles_metadata") or {}
    mapping_status = (runtime_doc.get("metadata") or {}).get("status")
    path_witness = _path_witness(events_by_key)

    results = []
    for seed in seeds_doc.get("seeds", []):
        fid = seed["field2"]
        candidate = RUNTIME_CANDIDATES.get(fid)
        base_record: Dict[str, Any] = {
            "world_id": seeds_doc.get("world_id"),
            "field2": fid,
            "filter_name": seed.get("filter_name"),
            "target_ops": seed.get("target_ops") or [],
            "seed_anchors": seed.get("anchors") or [],
            "notes": seed.get("notes", ""),
        }

        if not candidate:
            base_record["status"] = "no_runtime_candidate"
            base_record["runtime_candidate"] = None
            results.append(base_record)
            continue

        profile_id = candidate["profile_id"]
        probe_name = candidate["probe_name"]
        scenario_id = candidate["scenario_id"]
        probe_info = _lookup_probe(runtime_doc, profile_id, probe_name)
        actual = (signatures.get(profile_id) or {}).get(probe_name)
        runtime_profile = profiles_meta.get(profile_id, {}).get("runtime_profile")
        event = events_by_key.get((profile_id, probe_name))
        historical_event = historical_by_key.get((profile_id, probe_name))

        if not probe_info:
            base_record["status"] = "missing_probe"
            base_record["runtime_candidate"] = candidate
            results.append(base_record)
            continue

        blocked = _is_blocked_event(event)
        historical_actual = None
        if historical_event and not _is_blocked_event(historical_event):
            historical_actual = historical_event.get("actual")

        result = None
        result_tier = None
        result_source = None
        if not blocked and actual is not None:
            result = actual
            result_tier = "current"
            result_source = path_utils.to_repo_relative(runtime_signatures_path, repo_root=REPO_ROOT)
        elif blocked and historical_actual is not None:
            result = historical_actual
            result_tier = "historical_event"
            result_source = historical_event.get("source")
        elif blocked and actual is not None:
            result = actual
            result_tier = "historical_mapping"
            result_source = path_utils.to_repo_relative(runtime_signatures_path, repo_root=REPO_ROOT)

        if not blocked and result is not None:
            status = "runtime_backed"
        elif blocked and result is not None:
            status = "runtime_backed_historical"
        elif blocked:
            status = "runtime_attempted_blocked"
        else:
            status = "missing_actual"

        anchor_match = _anchor_match(anchor_map, (event or {}).get("normalized_path"))
        path_observation = None
        if event:
            path_observation = {
                "requested_path": event.get("requested_path"),
                "observed_path": event.get("observed_path"),
                "observed_path_source": event.get("observed_path_source"),
                "normalized_path": event.get("normalized_path"),
                "normalized_path_source": event.get("normalized_path_source"),
                "runtime_status": event.get("runtime_status"),
                "failure_stage": event.get("failure_stage"),
                "failure_kind": event.get("failure_kind"),
                "source": event.get("source"),
            }

        base_record.update(
            {
                "status": status,
                "runtime_candidate": {
                    "scenario_id": scenario_id,
                    "profile_id": profile_id,
                    "probe_name": probe_name,
                    "operation": probe_info.get("operation"),
                    "target": probe_info.get("target"),
                    "expected": probe_info.get("expected"),
                    "result": result,
                    "result_tier": result_tier,
                    "result_source": result_source,
                    "mapping_status": mapping_status,
                "path_observation": path_observation,
                "latest_attempt": (
                    {
                        "runtime_status": event.get("runtime_status"),
                        "failure_stage": event.get("failure_stage"),
                        "failure_kind": event.get("failure_kind"),
                        "run_id": event.get("run_id"),
                        "source": event.get("source"),
                    }
                    if event
                    else None
                ),
                    "anchor_match": (
                        {
                            "anchor": anchor_match.get("anchor"),
                            "alias_used": anchor_match.get("alias_used"),
                            "filter_id": (anchor_match.get("entry") or {}).get("filter_id"),
                            "filter_name": (anchor_match.get("entry") or {}).get("filter_name"),
                            "status": (anchor_match.get("entry") or {}).get("status"),
                            "source": path_utils.to_repo_relative(DEFAULT_ANCHOR_MAP, repo_root=REPO_ROOT),
                        }
                        if anchor_match
                        else None
                    ),
                    "path_canonicalization_detected": _canonicalization_detected(event),
                    "runtime_profile": path_utils.to_repo_relative(runtime_profile, repo_root=REPO_ROOT)
                    if runtime_profile
                    else None,
                    "source": path_utils.to_repo_relative(runtime_signatures_path, repo_root=REPO_ROOT),
                },
            }
        )
        if historical_actual is not None:
            base_record["last_successful_witness"] = {
                "result": historical_actual,
                "runtime_status": historical_event.get("runtime_status"),
                "failure_stage": historical_event.get("failure_stage"),
                "source": historical_event.get("source"),
                "probe_name": probe_name,
                "profile_id": profile_id,
            }
        if fid == 0 and path_witness:
            base_record["path_canonicalization_witness"] = path_witness
        if fid == 2560:
            control_profile = "adv:flow_divert_partial_tcp"
            control_probe = "tcp-loopback"
            control_event = events_by_key.get((control_profile, control_probe))
            control_probe_info = _lookup_probe(runtime_doc, control_profile, control_probe)
            control = {
                "partial_triple": {
                    "profile_id": control_profile,
                    "probe_name": control_probe,
                    "expected": (control_probe_info or {}).get("expected"),
                    "actual": control_event.get("actual") if control_event else None,
                    "runtime_status": control_event.get("runtime_status") if control_event else None,
                    "source": control_event.get("source") if control_event else None,
                },
                "baseline": {
                    "source": path_utils.to_repo_relative(baseline_path, repo_root=REPO_ROOT)
                    if baseline_path.exists()
                    else None,
                    "record": baseline_by_key.get((profile_id, probe_name)),
                },
            }
            discriminating = None
            if control_event and result is not None:
                discriminating = control_event.get("actual") != result
            control["discriminating"] = discriminating
            if discriminating is False:
                control["notes"] = "control non-discriminating (same decision as require-all variant)"
            base_record["control_witness"] = control
        results.append(base_record)

    seed_ids = {entry["field2"] for entry in seeds_doc.get("seeds", [])}
    result_ids = {entry["field2"] for entry in results}
    if seed_ids != result_ids:
        missing = seed_ids - result_ids
        extra = result_ids - seed_ids
        raise ValueError(f"seed/runtime mismatch: missing={sorted(missing)} extra={sorted(extra)}")

    return {
        "world_id": seeds_doc.get("world_id"),
        "source_artifacts": {
            "seeds": path_utils.to_repo_relative(seeds_path, repo_root=REPO_ROOT),
            "runtime_signatures": path_utils.to_repo_relative(runtime_signatures_path, repo_root=REPO_ROOT),
            "runtime_events": [
                path_utils.to_repo_relative(path, repo_root=REPO_ROOT)
                for path in runtime_event_paths
                if path.exists()
            ],
            "run_manifest": path_utils.to_repo_relative(run_manifest_path, repo_root=REPO_ROOT)
            if run_manifest_path.exists()
            else None,
            "baseline_results": path_utils.to_repo_relative(baseline_path, repo_root=REPO_ROOT)
            if baseline_path.exists()
            else None,
            "promotion_packet": path_utils.to_repo_relative(promotion_paths["promotion_packet"], repo_root=REPO_ROOT)
            if promotion_paths
            else None,
            "historical_runtime_events": [
                path_utils.to_repo_relative(DEFAULT_HISTORICAL_EVENTS, repo_root=REPO_ROOT)
                for _ in [DEFAULT_HISTORICAL_EVENTS]
                if DEFAULT_HISTORICAL_EVENTS.exists()
            ],
            "anchor_map": path_utils.to_repo_relative(DEFAULT_ANCHOR_MAP, repo_root=REPO_ROOT),
        },
        "results": results,
    }


def write_results(doc: Dict[str, Any], output_path: Path = DEFAULT_OUTPUT) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)


def main() -> None:
    doc = build_runtime_results()
    write_results(doc)


if __name__ == "__main__":
    main()
