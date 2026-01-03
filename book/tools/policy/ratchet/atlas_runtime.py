"""
Runtime slice builder for the Field2 Atlas experiment (packet-only).

This consumes a promotion packet, resolves committed bundle exports, and
emits derived runtime results under `out/derived/<run_id>/runtime/`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.analysis import packet_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())
FIELD2_ROOT = REPO_ROOT / "book" / "evidence" / "experiments" / "field2-final-final"
DEFAULT_SEEDS = FIELD2_ROOT / "field2-atlas" / "field2_seeds.json"
DEFAULT_RUNTIME_SIGNATURES = (
    REPO_ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "runtime_signatures.json"
)
DEFAULT_ANCHOR_MAP = REPO_ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "anchors" / "anchor_filter_map.json"
DEFAULT_OUT_ROOT = FIELD2_ROOT / "field2-atlas" / "out" / "derived"
REQUIRED_EXPORTS = ("runtime_events", "baseline_results", "run_manifest", "path_witnesses")
RUNTIME_RESULTS_SCHEMA_VERSION = "field2-atlas.runtime_results.v0"
CONSUMPTION_RECEIPT_SCHEMA_VERSION = "field2-atlas.consumption_receipt.v0"



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


def _load_runtime_events(paths: list[Path]) -> list[Dict[str, Any]]:
    events: list[Dict[str, Any]] = []
    for path in paths:
        if not path.exists():
            continue
        for row in load_json(path) or []:
            if isinstance(row, dict):
                row = dict(row)
                row["source"] = path_utils.to_repo_relative(path, repo_root=REPO_ROOT)
                events.append(row)
    return events


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


def _path_witness_from_doc(path_witnesses: Dict[str, Any], *, source: str) -> Optional[Dict[str, Any]]:
    profile_id = "adv:path_alias"
    records = path_witnesses.get("records") or []
    probes = []
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get("lane") != "scenario":
            continue
        if record.get("profile_id") != profile_id:
            continue
        scenario_id = record.get("scenario_id") or ""
        probe_name = scenario_id.split(":")[-1] if isinstance(scenario_id, str) else None
        probes.append(
            {
                "probe_name": probe_name,
                "scenario_id": scenario_id,
                "requested_path": record.get("requested_path"),
                "observed_path": record.get("observed_path"),
                "observed_path_source": record.get("observed_path_source"),
                "normalized_path": record.get("normalized_path"),
                "normalized_path_source": record.get("normalized_path_source"),
                "decision": record.get("decision"),
            }
        )
    if not probes:
        return None
    return {
        "profile_id": profile_id,
        "probes": probes,
        "source": source,
    }


def build_runtime_results(
    packet_path: Path,
    *,
    receipt_path: Optional[Path] = None,
    packet_context: Optional[packet_utils.PacketContext] = None,
) -> tuple[Dict[str, Any], packet_utils.PacketContext]:
    ctx = packet_context or packet_utils.resolve_packet_context(
        packet_path, required_exports=REQUIRED_EXPORTS, repo_root=REPO_ROOT
    )
    seeds_doc = load_json(DEFAULT_SEEDS)
    runtime_doc = load_json(DEFAULT_RUNTIME_SIGNATURES)
    anchor_map = load_json(DEFAULT_ANCHOR_MAP)

    manifest_world_id = ctx.run_manifest.get("world_id")
    if manifest_world_id and seeds_doc.get("world_id") and manifest_world_id != seeds_doc.get("world_id"):
        raise ValueError("promotion packet world_id does not match field2 seeds")

    runtime_event_path = ctx.export_paths["runtime_events"]
    baseline_path = ctx.export_paths["baseline_results"]

    events = _load_runtime_events([runtime_event_path])
    events_by_key = _index_runtime_events(events)
    baseline_by_key = _load_baseline_results(baseline_path)
    signatures = runtime_doc.get("signatures") or {}
    profiles_meta = runtime_doc.get("profiles_metadata") or {}
    mapping_status_default = (runtime_doc.get("metadata") or {}).get("status")
    path_witnesses_path = ctx.export_paths["path_witnesses"]
    path_witnesses_doc = load_json(path_witnesses_path)
    path_witness = _path_witness_from_doc(
        path_witnesses_doc,
        source=path_utils.to_repo_relative(path_witnesses_path, repo_root=REPO_ROOT),
    )

    results = []
    for seed in seeds_doc.get("seeds", []):
        fid = seed["field2"]
        candidate = seed.get("runtime_candidate")
        if candidate is not None and not isinstance(candidate, dict):
            candidate = None
        mapping_status = mapping_status_default
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
        if not probe_info:
            base_record["status"] = "missing_probe"
            base_record["runtime_candidate"] = candidate
            results.append(base_record)
            continue

        blocked = _is_blocked_event(event)
        result = None
        result_origin = None
        result_source = None
        if not blocked and actual is not None:
            result = actual
            result_origin = "mapping"
            result_source = path_utils.to_repo_relative(DEFAULT_RUNTIME_SIGNATURES, repo_root=REPO_ROOT)
        elif not blocked and event and event.get("actual") is not None:
            result = event.get("actual")
            result_origin = "packet_event"
            result_source = path_utils.to_repo_relative(runtime_event_path, repo_root=REPO_ROOT)
            mapping_status = "packet_only"
        elif blocked and actual is not None:
            result = actual
            result_origin = "historical_mapping"
            result_source = path_utils.to_repo_relative(DEFAULT_RUNTIME_SIGNATURES, repo_root=REPO_ROOT)

        if not blocked and result is not None:
            status = "runtime_backed"
        elif blocked and result is not None:
            status = "runtime_backed_historical"
        elif blocked:
            status = "runtime_attempted_blocked"
        else:
            status = "missing_actual"

        anchor_match = _anchor_match(anchor_map, (event or {}).get("normalized_path"))
        if not runtime_profile and event:
            runtime_profile = (event.get("preflight") or {}).get("input_ref")
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
                    "result_origin": result_origin,
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
                    "source": path_utils.to_repo_relative(DEFAULT_RUNTIME_SIGNATURES, repo_root=REPO_ROOT),
                },
            }
        )
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
                    "source": path_utils.to_repo_relative(baseline_path, repo_root=REPO_ROOT),
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

    provenance = packet_utils.format_packet_provenance(
        ctx, exports=REQUIRED_EXPORTS, receipt_path=receipt_path, repo_root=REPO_ROOT
    )
    packet_exports = {
        key: path_utils.to_repo_relative(path, repo_root=REPO_ROOT) for key, path in ctx.export_paths.items()
    }
    doc = {
        "schema_version": RUNTIME_RESULTS_SCHEMA_VERSION,
        "world_id": seeds_doc.get("world_id"),
        "provenance": provenance,
        "source_artifacts": {
            "seeds": path_utils.to_repo_relative(DEFAULT_SEEDS, repo_root=REPO_ROOT),
            "runtime_signatures": path_utils.to_repo_relative(DEFAULT_RUNTIME_SIGNATURES, repo_root=REPO_ROOT),
            "anchor_map": path_utils.to_repo_relative(DEFAULT_ANCHOR_MAP, repo_root=REPO_ROOT),
            "packet_exports": packet_exports,
        },
        "results": results,
    }
    return doc, ctx


def derived_run_dir(out_root: Path, run_id: str) -> Path:
    out_root = path_utils.ensure_absolute(out_root, repo_root=REPO_ROOT)
    return out_root / run_id


def runtime_results_path(out_root: Path, run_id: str) -> Path:
    return derived_run_dir(out_root, run_id) / "runtime" / "field2_runtime_results.json"


def write_results(doc: Dict[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)


def write_consumption_receipt(
    receipt_path: Path,
    *,
    world_id: str,
    packet_ctx: packet_utils.PacketContext,
    exports_used: Iterable[str],
    outputs: Dict[str, Path],
) -> Path:
    receipt_path = path_utils.ensure_absolute(receipt_path, repo_root=REPO_ROOT)
    export_paths: Dict[str, str] = {}
    for key in exports_used:
        export_paths[key] = path_utils.to_repo_relative(packet_ctx.export_paths[key], repo_root=REPO_ROOT)
    receipt = {
        "schema_version": CONSUMPTION_RECEIPT_SCHEMA_VERSION,
        "world_id": world_id,
        "consumed_packets": [
            {
                "packet_path": path_utils.to_repo_relative(packet_ctx.packet_path, repo_root=REPO_ROOT),
                "run_id": packet_ctx.run_id,
                "artifact_index": path_utils.to_repo_relative(packet_ctx.artifact_index_path, repo_root=REPO_ROOT),
                "artifact_index_sha256": packet_ctx.artifact_index_sha256,
                "exports": export_paths,
            }
        ],
        "outputs": {key: path_utils.to_repo_relative(path, repo_root=REPO_ROOT) for key, path in outputs.items()},
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True), encoding="utf-8")
    return receipt_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Field2 Atlas runtime results from promotion packets.")
    parser.add_argument("--packet", type=Path, required=True, help="Path to promotion_packet.json")
    parser.add_argument(
        "--out-root",
        type=Path,
        default=DEFAULT_OUT_ROOT,
        help="Output root for derived artifacts (run_id subdir will be created)",
    )
    args = parser.parse_args()

    ctx = packet_utils.resolve_packet_context(args.packet, required_exports=REQUIRED_EXPORTS, repo_root=REPO_ROOT)
    derived_root = derived_run_dir(args.out_root, ctx.run_id)
    receipt_path = derived_root / "consumption_receipt.json"
    doc, _ = build_runtime_results(args.packet, receipt_path=receipt_path, packet_context=ctx)
    output_path = runtime_results_path(args.out_root, ctx.run_id)
    write_results(doc, output_path=output_path)
    write_consumption_receipt(
        receipt_path,
        world_id=doc.get("world_id"),
        packet_ctx=ctx,
        exports_used=REQUIRED_EXPORTS,
        outputs={"runtime_results": output_path},
    )


if __name__ == "__main__":
    main()
