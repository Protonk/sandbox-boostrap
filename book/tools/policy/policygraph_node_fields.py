#!/usr/bin/env python3
"""
PolicyGraph node field enumerator.

This tool is deterministic by default: it consumes pinned artifacts and emits
repo-relative outputs. Runtime evidence is packet-driven when provided.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils, tooling  # type: ignore

REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())


WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
FIELDS_SCHEMA_VERSION = "policygraph_node_fields.v0"
ARG16_SCHEMA_VERSION = "policygraph_node_arg16.v0"
UNKNOWNS_SCHEMA_VERSION = "policygraph_node_unknowns.v0"
RECEIPT_SCHEMA_VERSION = "policygraph_node_fields_receipt.v0"


def _rel(path: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root=REPO_ROOT)


def _static_inputs() -> Dict[str, Path]:
    return {
        "tag_layouts": REPO_ROOT
        / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json",
        "vocab_ops": REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/ops.json",
        "vocab_filters": REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json",
        "anchor_filter_map": REPO_ROOT
        / "book/integration/carton/bundle/relationships/mappings/anchors/anchor_filter_map.json",
        "anchor_ctx_filter_map": REPO_ROOT
        / "book/integration/carton/bundle/relationships/mappings/anchors/anchor_ctx_filter_map.json",
        "field2_inventory": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/field2-filters/out/field2_inventory.json",
        "unknown_nodes": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/field2-filters/out/unknown_nodes.json",
        "anchor_hits": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits.json",
        "anchor_hits_delta": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/probe-op-structure/out/anchor_hits_delta.json",
        "field2_seeds": REPO_ROOT / "book/evidence/experiments/field2-final-final/field2-atlas/field2_seeds.json",
        "network_matrix_index": REPO_ROOT
        / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/index.json",
    }


def _output_paths(out_root: Path) -> Dict[str, Path]:
    return {
        "fields": out_root / "policygraph_node_fields.json",
        "arg16": out_root / "policygraph_node_arg16.json",
        "unknowns": out_root / "policygraph_node_unknowns.json",
        "receipt": out_root / "policygraph_node_fields_receipt.json",
        "report": out_root / "policygraph_node_fields.md",
    }


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _ensure_inputs(inputs: Dict[str, Path]) -> None:
    missing = [name for name, path in inputs.items() if not path.exists()]
    if missing:
        missing_list = ", ".join(sorted(missing))
        raise FileNotFoundError(f"policygraph_node_fields missing inputs: {missing_list}")


def _check_world_id(doc: Any, source: str) -> None:
    world_id = None
    if isinstance(doc, dict):
        meta = doc.get("metadata")
        if isinstance(meta, dict):
            world_id = meta.get("world_id")
        if world_id is None:
            world_id = doc.get("world_id")
    if world_id and world_id != WORLD_ID:
        raise ValueError(f"world_id mismatch for {source}: {world_id} != {WORLD_ID}")


def _record_size_bytes(tag_layouts: Dict[str, Any]) -> Tuple[int, List[Dict[str, Any]]]:
    tags = tag_layouts.get("tags") or []
    if not tags:
        raise ValueError("tag_layouts missing tags")
    sizes = {entry.get("record_size_bytes") for entry in tags}
    sizes.discard(None)
    if len(sizes) != 1:
        raise ValueError(f"unexpected record_size_bytes set: {sorted(sizes)}")
    record_size_bytes = sizes.pop()
    if record_size_bytes % 2 != 0:
        raise ValueError(f"record_size_bytes not divisible by 2: {record_size_bytes}")
    return record_size_bytes, tags


def _derive_arg16_index(tags: List[Dict[str, Any]]) -> Optional[int]:
    payload_sets = {tuple(entry.get("payload_fields") or []) for entry in tags}
    if len(payload_sets) != 1:
        return None
    payload = next(iter(payload_sets))
    if len(payload) != 1:
        return None
    return payload[0]


def _build_field_layout(tag_layouts: Dict[str, Any]) -> Dict[str, Any]:
    record_size_bytes, tags = _record_size_bytes(tag_layouts)
    field_count = record_size_bytes // 2
    all_tags = sorted({int(entry.get("tag")) for entry in tags if entry.get("tag") is not None})
    usage: Dict[int, Dict[str, List[int]]] = {
        idx: {"edge": [], "payload": []} for idx in range(field_count)
    }
    for entry in tags:
        tag_id = entry.get("tag")
        if tag_id is None:
            continue
        for idx in entry.get("edge_fields") or []:
            usage[idx]["edge"].append(tag_id)
        for idx in entry.get("payload_fields") or []:
            usage[idx]["payload"].append(tag_id)

    arg16_index = _derive_arg16_index(tags)
    fields: List[Dict[str, Any]] = []
    for idx in range(field_count):
        edge_tags = sorted(usage[idx]["edge"])
        payload_tags = sorted(usage[idx]["payload"])
        role = "unassigned"
        if edge_tags and payload_tags:
            role = "mixed"
        elif edge_tags:
            role = "edge"
        elif payload_tags:
            role = "payload"
        field = {
            "field_index": idx,
            "byte_offset": idx * 2,
            "width_bits": 16,
            "role": role,
            "edge_tag_count": len(edge_tags),
            "payload_tag_count": len(payload_tags),
            "edge_tags": edge_tags,
            "payload_tags": payload_tags,
            "unassigned_tag_count": len(all_tags) - len(edge_tags) - len(payload_tags),
        }
        if idx == arg16_index:
            field["canonical_name"] = "policygraph_node_arg16"
            field["legacy_names"] = ["field2", "filter_arg_raw"]
        else:
            field["canonical_name"] = f"u16_{idx}"
        fields.append(field)

    return {
        "schema_version": FIELDS_SCHEMA_VERSION,
        "world_id": WORLD_ID,
        "record_size_bytes": record_size_bytes,
        "field_width_bits": 16,
        "field_count": field_count,
        "arg16_field_index": arg16_index,
        "edge_field_indices": sorted({idx for idx, data in usage.items() if data["edge"]}),
        "payload_field_indices": sorted({idx for idx, data in usage.items() if data["payload"]}),
        "tag_count": len(all_tags),
        "fields": fields,
    }


def _filter_vocab_map(filters_doc: Dict[str, Any]) -> Dict[int, str]:
    entries = filters_doc.get("filters") or []
    mapping: Dict[int, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        fid = entry.get("id")
        name = entry.get("name")
        if isinstance(fid, int) and isinstance(name, str):
            mapping[fid] = name
    return mapping


def _aggregate_field2_inventory(field2_inventory: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    aggregated: Dict[int, Dict[str, Any]] = {}
    for profile_id in sorted(field2_inventory.keys()):
        payload = field2_inventory.get(profile_id) or {}
        for entry in payload.get("field2", []):
            raw = entry.get("raw")
            if raw is None:
                continue
            raw_int = int(raw)
            record = aggregated.setdefault(
                raw_int,
                {
                    "arg16": raw_int,
                    "raw_hex": entry.get("raw_hex") or f"0x{raw_int:x}",
                    "hi": entry.get("hi") if entry.get("hi") is not None else (raw_int >> 8),
                    "lo": entry.get("lo") if entry.get("lo") is not None else (raw_int & 0xFF),
                    "profiles": [],
                    "tag_ids": set(),
                    "total_count": 0,
                    "inventory_names": set(),
                },
            )
            tag_counts = entry.get("tags") or {}
            record["profiles"].append(
                {
                    "profile": profile_id,
                    "count": entry.get("count"),
                    "tags": tag_counts,
                    "name": entry.get("name"),
                }
            )
            record["total_count"] += int(entry.get("count") or 0)
            for tag in tag_counts.keys():
                record["tag_ids"].add(int(tag))
            if entry.get("name"):
                record["inventory_names"].add(entry.get("name"))
    for record in aggregated.values():
        record["profiles"] = sorted(record["profiles"], key=lambda item: item.get("profile") or "")
        record["tag_ids"] = sorted(record["tag_ids"])
        record["inventory_names"] = sorted(record["inventory_names"])
    return aggregated


def _collect_anchor_map_hits(anchor_map: Dict[str, Any]) -> Dict[int, List[Dict[str, Any]]]:
    hits: Dict[int, List[Dict[str, Any]]] = {}
    for anchor, entry in anchor_map.items():
        if anchor == "metadata" or not isinstance(entry, dict):
            continue
        values = sorted(set(entry.get("field2_values") or []))
        if not values:
            continue
        hit = {
            "anchor": anchor,
            "status": entry.get("status", "partial"),
            "filter_name": entry.get("filter_name"),
            "filter_id": entry.get("filter_id"),
            "sources": entry.get("sources") or [],
            "ctx_ids": entry.get("ctx_ids") or [],
            "field2_values": values,
            "source": "anchor_filter_map",
        }
        for raw in values:
            hits.setdefault(int(raw), []).append(hit)
    for value in hits.values():
        value.sort(key=lambda item: item.get("anchor") or "")
    return hits


def _iter_probe_anchor_hits(payload: Dict[str, Any]) -> Iterable[Tuple[str, Dict[str, Any]]]:
    for profile_id, entry in payload.items():
        if profile_id == "metadata":
            continue
        anchors = entry.get("anchors") or []
        for anchor_entry in anchors:
            yield profile_id, anchor_entry


def _collect_probe_anchor_hits(doc: Dict[str, Any], *, source: str) -> Dict[int, List[Dict[str, Any]]]:
    hits: Dict[int, List[Dict[str, Any]]] = {}
    seen: set[Tuple[int, str, str]] = set()
    for profile_id, anchor_entry in _iter_probe_anchor_hits(doc):
        values = anchor_entry.get("field2_values") or []
        for raw in values:
            key = (int(raw), profile_id, anchor_entry.get("anchor") or "")
            if key in seen:
                continue
            seen.add(key)
            hit = {
                "anchor": anchor_entry.get("anchor"),
                "profile": profile_id,
                "node_indices": anchor_entry.get("node_indices") or [],
                "field2_values": values,
                "field2_names": anchor_entry.get("field2_names") or [],
                "offsets": anchor_entry.get("offsets") or [],
                "literal_offsets": anchor_entry.get("literal_offsets") or [],
                "literal_string_index": anchor_entry.get("literal_string_index"),
                "source": source,
            }
            hits.setdefault(int(raw), []).append(hit)
    for value in hits.values():
        value.sort(key=lambda item: (item.get("anchor") or "", item.get("profile") or ""))
    return hits


def _seed_index(seeds_doc: Dict[str, Any]) -> Dict[int, Dict[str, Any]]:
    seed_map: Dict[int, Dict[str, Any]] = {}
    for seed in seeds_doc.get("seeds") or []:
        raw = seed.get("field2")
        if raw is None:
            continue
        seed_map[int(raw)] = {
            "filter_name": seed.get("filter_name"),
            "target_ops": seed.get("target_ops") or [],
            "anchors": seed.get("anchors") or [],
            "runtime_candidate": seed.get("runtime_candidate"),
            "notes": seed.get("notes") or "",
        }
    return seed_map


def _normalize_arg16_record(raw: int) -> Dict[str, Any]:
    return {
        "arg16": raw,
        "raw_hex": f"0x{raw:x}",
        "hi": raw >> 8,
        "lo": raw & 0xFF,
        "profiles": [],
        "tag_ids": [],
        "total_count": 0,
        "inventory_names": [],
    }


def _build_arg16_doc(
    *,
    field_index: Optional[int],
    field2_inventory: Dict[str, Any],
    filters_doc: Dict[str, Any],
    anchor_map: Dict[str, Any],
    anchor_hits: Dict[str, Any],
    anchor_hits_delta: Dict[str, Any],
    seeds_doc: Dict[str, Any],
    packet_provenance: Optional[Dict[str, Any]],
    runtime_index: Dict[Tuple[str, str], Dict[str, Any]],
    runtime_source: Optional[str],
    sources: Dict[str, str],
) -> Dict[str, Any]:
    vocab_map = _filter_vocab_map(filters_doc)
    aggregated = _aggregate_field2_inventory(field2_inventory)
    seed_map = _seed_index(seeds_doc)
    anchor_hits_map = _collect_anchor_map_hits(anchor_map)

    probe_hits_map = _collect_probe_anchor_hits(anchor_hits, source="probe-op-structure")
    delta_profiles = anchor_hits_delta.get("profiles") if isinstance(anchor_hits_delta, dict) else None
    delta_payload = delta_profiles if isinstance(delta_profiles, dict) else {}
    delta_hits_map = _collect_probe_anchor_hits(delta_payload, source="probe-op-structure-delta")

    all_values: set[int] = set(aggregated.keys())
    all_values.update(seed_map.keys())
    all_values.update(anchor_hits_map.keys())
    all_values.update(probe_hits_map.keys())
    all_values.update(delta_hits_map.keys())

    records: List[Dict[str, Any]] = []
    runtime_summary = {
        "candidates": 0,
        "matched": 0,
        "missing_probe": 0,
        "blocked": 0,
    }
    for raw in sorted(all_values):
        record = aggregated.get(raw, _normalize_arg16_record(raw))
        filter_name = vocab_map.get(raw)
        inventory_names = record.get("inventory_names") or []
        record["filter_vocab_id"] = raw if filter_name is not None else None
        record["filter_name"] = filter_name or (inventory_names[0] if len(inventory_names) == 1 else None)
        record["inventory_names"] = inventory_names
        record["seed"] = seed_map.get(raw)
        record["anchor_hits"] = anchor_hits_map.get(raw, [])
        record["probe_anchor_hits"] = probe_hits_map.get(raw, []) + delta_hits_map.get(raw, [])
        record["status"] = "mapped" if record["filter_name"] else "opaque"
        runtime_candidate = (record.get("seed") or {}).get("runtime_candidate")
        if runtime_candidate and isinstance(runtime_candidate, dict):
            runtime_summary["candidates"] += 1
            profile_id = runtime_candidate.get("profile_id")
            probe_name = runtime_candidate.get("probe_name")
            scenario_id = runtime_candidate.get("scenario_id")
            runtime_entry = None
            if isinstance(profile_id, str) and isinstance(probe_name, str):
                runtime_entry = runtime_index.get((profile_id, probe_name))
            if runtime_entry:
                runtime_summary["matched"] += 1
                probe = runtime_entry.get("probe") or {}
                runtime_result = probe.get("runtime_result") or {}
                failure_stage = runtime_result.get("failure_stage")
                stage = "operation"
                if failure_stage in {"apply", "bootstrap"}:
                    stage = failure_stage
                elif failure_stage == "preflight":
                    stage = "apply"
                if failure_stage in {"apply", "bootstrap", "preflight"}:
                    runtime_summary["blocked"] += 1
                record["runtime_annotation"] = {
                    "profile_id": profile_id,
                    "probe_name": probe_name,
                    "scenario_id": scenario_id,
                    "operation": probe.get("operation"),
                    "target": probe.get("path") or probe.get("target"),
                    "expected": probe.get("expected"),
                    "actual": probe.get("actual"),
                    "match": probe.get("match"),
                    "runtime_status": runtime_result.get("status"),
                    "failure_stage": failure_stage,
                    "failure_kind": runtime_result.get("failure_kind"),
                    "stage": stage,
                    "lane": "scenario",
                    "run_id": runtime_entry.get("run_id"),
                    "source": runtime_source,
                }
            else:
                runtime_summary["missing_probe"] += 1
                record["runtime_annotation"] = {
                    "profile_id": profile_id,
                    "probe_name": probe_name,
                    "scenario_id": scenario_id,
                    "status": "missing_probe",
                    "lane": "scenario",
                    "stage": "operation",
                    "source": runtime_source,
                }
        records.append(record)

    return {
        "schema_version": ARG16_SCHEMA_VERSION,
        "world_id": WORLD_ID,
        "field_index": field_index,
        "field_width_bits": 16,
        "canonical_name": "policygraph_node_arg16",
        "legacy_names": ["field2", "filter_arg_raw"],
        "records": records,
        "runtime_summary": runtime_summary,
        "sources": sources,
        "packet": packet_provenance,
    }


def _build_unknowns_doc(
    *,
    arg16_doc: Dict[str, Any],
    unknown_nodes: Dict[str, Any],
    sources: Dict[str, str],
) -> Dict[str, Any]:
    unknown_records: List[Dict[str, Any]] = []
    for record in arg16_doc.get("records") or []:
        if record.get("filter_vocab_id") is not None:
            continue
        if record.get("inventory_names"):
            continue
        unknown_records.append(
            {
                "arg16": record.get("arg16"),
                "raw_hex": record.get("raw_hex"),
                "profiles": record.get("profiles") or [],
                "tag_ids": record.get("tag_ids") or [],
                "anchor_hits": record.get("anchor_hits") or [],
                "probe_anchor_hits": record.get("probe_anchor_hits") or [],
                "reason": "no_filter_vocab_match",
            }
        )

    unknown_nodes_summary: Dict[str, Any] = {}
    total_unknown_nodes = 0
    for profile_id, entries in unknown_nodes.items():
        if profile_id == "metadata":
            continue
        count = len(entries) if isinstance(entries, list) else 0
        unknown_nodes_summary[profile_id] = {"count": count}
        total_unknown_nodes += count

    return {
        "schema_version": UNKNOWNS_SCHEMA_VERSION,
        "world_id": WORLD_ID,
        "arg16_unknowns": unknown_records,
        "unknown_nodes": {
            "profiles": unknown_nodes_summary,
            "total": total_unknown_nodes,
        },
        "sources": sources,
    }


def _write_json(path: Path, doc: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")


def _format_list(items: List[str], *, limit: int = 12) -> str:
    if not items:
        return "none"
    if len(items) <= limit:
        return ", ".join(items)
    return f"{', '.join(items[:limit])}, ... ({len(items)} total)"


def _format_int_list(items: List[int], *, limit: int = 12) -> str:
    return _format_list([str(item) for item in items], limit=limit)


def _write_report(
    path: Path,
    *,
    fields_doc: Dict[str, Any],
    arg16_doc: Dict[str, Any],
    unknowns_doc: Dict[str, Any],
    receipt: Dict[str, Any],
) -> None:
    records = arg16_doc.get("records") or []
    mapped = [r for r in records if r.get("filter_name")]
    opaque = [r for r in records if not r.get("filter_name")]
    seeds = [r for r in records if r.get("seed")]
    anchor_hits = [r for r in records if r.get("anchor_hits")]
    probe_hits = [r for r in records if r.get("probe_anchor_hits")]

    runtime_summary = arg16_doc.get("runtime_summary") or {}
    runtime_annotated = [r for r in records if r.get("runtime_annotation")]
    runtime_missing = [
        r
        for r in runtime_annotated
        if (r.get("runtime_annotation") or {}).get("status") == "missing_probe"
    ]
    runtime_matched = [
        r for r in runtime_annotated if (r.get("runtime_annotation") or {}).get("status") != "missing_probe"
    ]

    field_rows = []
    for field in fields_doc.get("fields") or []:
        field_rows.append(
            "| {idx} | {name} | {role} | {offset} | {width} | {edge} | {payload} |".format(
                idx=field.get("field_index"),
                name=field.get("canonical_name"),
                role=field.get("role"),
                offset=field.get("byte_offset"),
                width=field.get("width_bits"),
                edge=field.get("edge_tag_count"),
                payload=field.get("payload_tag_count"),
            )
        )

    runtime_rows = []
    for record in sorted(runtime_matched, key=lambda r: r.get("arg16", 0)):
        ann = record.get("runtime_annotation") or {}
        runtime_rows.append(
            "| {arg16} | {name} | {op} | {actual} | {stage} | {lane} | {scenario} |".format(
                arg16=record.get("arg16"),
                name=record.get("filter_name") or "opaque",
                op=ann.get("operation") or "",
                actual=ann.get("actual") or "",
                stage=ann.get("stage") or "",
                lane=ann.get("lane") or "",
                scenario=ann.get("scenario_id") or "",
            )
        )

    unknowns = unknowns_doc.get("arg16_unknowns") or []
    unknown_ranked = []
    for entry in unknowns:
        total = sum(profile.get("count") or 0 for profile in entry.get("profiles") or [])
        unknown_ranked.append((total, entry))
    unknown_ranked.sort(key=lambda item: item[0], reverse=True)
    top_unknowns = [
        f"{entry.get('arg16')} (count={count})" for count, entry in unknown_ranked[:10]
    ]

    inputs = receipt.get("inputs") or {}
    input_lines = []
    for name in sorted(inputs.keys()):
        payload = inputs[name] or {}
        input_lines.append(f"- {name}: `{payload.get('path')}` (sha256={payload.get('sha256')})")

    packet = receipt.get("packet")
    packet_line = "none"
    if isinstance(packet, dict):
        packet_line = (
            f"{packet.get('packet')} (run_id={packet.get('run_id')}, "
            f"artifact_index_sha256={packet.get('artifact_index_sha256')})"
        )

    report = [
        "# PolicyGraph Node Fields",
        "",
        f"- world_id: `{fields_doc.get('world_id')}`",
        f"- record_size_bytes: `{fields_doc.get('record_size_bytes')}`",
        f"- field_count: `{fields_doc.get('field_count')}`",
        f"- arg16_field_index: `{fields_doc.get('arg16_field_index')}`",
        f"- runtime_annotation: `{packet_line}`",
        "",
        "## Field Layout",
        "",
        "| field_index | canonical_name | role | byte_offset | width_bits | edge_tag_count | payload_tag_count |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        *field_rows,
        "",
        "## policygraph_node_arg16 Summary",
        "",
        f"- total_values: `{len(records)}`",
        f"- mapped_values: `{len(mapped)}`",
        f"- opaque_values: `{len(opaque)}`",
        f"- seeds_present: `{len(seeds)}`",
        f"- anchor_hits_present: `{len(anchor_hits)}`",
        f"- probe_anchor_hits_present: `{len(probe_hits)}`",
        f"- runtime_candidates: `{runtime_summary.get('candidates', 0)}`",
        f"- runtime_matched: `{runtime_summary.get('matched', 0)}`",
        f"- runtime_missing_probe: `{runtime_summary.get('missing_probe', 0)}`",
        f"- runtime_blocked: `{runtime_summary.get('blocked', 0)}`",
        "",
        "### Runtime Matched (scenario lane)",
        "",
    ]
    if runtime_rows:
        report += [
            "| arg16 | filter_name | operation | actual | stage | lane | scenario_id |",
            "| --- | --- | --- | --- | --- | --- | --- |",
            *runtime_rows,
            "",
        ]
    else:
        report += ["- none", ""]

    report += [
        "### Runtime Missing Probes",
        "",
        f"- values: {_format_int_list(sorted([r.get('arg16') for r in runtime_missing if r.get('arg16') is not None]))}",
        "",
        "## Unknowns",
        "",
        f"- unknown_arg16_values: `{len(unknowns)}`",
        f"- top_unknowns_by_count: {_format_list(top_unknowns)}",
        "",
        "## Inputs",
        "",
        *input_lines,
        "",
        "## Outputs",
        "",
        f"- fields: `{receipt.get('outputs', {}).get('fields')}`",
        f"- arg16: `{receipt.get('outputs', {}).get('arg16')}`",
        f"- unknowns: `{receipt.get('outputs', {}).get('unknowns')}`",
        f"- receipt: `{receipt.get('outputs', {}).get('receipt')}`",
        f"- report: `{receipt.get('outputs', {}).get('report')}`",
        "",
    ]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        fh.write("\n".join(report))


def _packet_context(packet_path: Optional[str]) -> Optional[Any]:
    if not packet_path:
        return None
    from book.api.runtime.analysis import packet_utils  # type: ignore

    return packet_utils.resolve_packet_context(
        Path(packet_path),
        required_exports=["runtime_results"],
        repo_root=REPO_ROOT,
    )


def _packet_provenance(ctx: Optional[Any], receipt_path: Optional[Path]) -> Optional[Dict[str, Any]]:
    if ctx is None:
        return None
    from book.api.runtime.analysis import packet_utils  # type: ignore

    return packet_utils.format_packet_provenance(
        ctx,
        exports=["runtime_results"],
        receipt_path=receipt_path,
        repo_root=REPO_ROOT,
    )


def _runtime_index(ctx: Optional[Any]) -> Tuple[Dict[Tuple[str, str], Dict[str, Any]], Optional[str]]:
    if ctx is None:
        return {}, None
    runtime_results_path = ctx.export_paths.get("runtime_results")
    if not runtime_results_path:
        return {}, None
    runtime_results = _load_json(runtime_results_path)
    index: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for profile_id, entry in runtime_results.items():
        if not isinstance(entry, dict):
            continue
        probes = entry.get("probes") or []
        for probe in probes:
            name = probe.get("name")
            if not isinstance(name, str):
                continue
            index[(profile_id, name)] = {
                "profile_id": profile_id,
                "run_id": entry.get("run_id"),
                "probe": probe,
            }
    return index, _rel(runtime_results_path)


def _describe(args: argparse.Namespace) -> int:
    out_root = Path(args.out).resolve()
    inputs = _static_inputs()
    outputs = _output_paths(out_root)
    doc = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool": "policygraph_node_fields",
        "world_id": WORLD_ID,
        "mode": "describe",
        "inputs": {name: {"path": _rel(path), "required": True} for name, path in inputs.items()},
        "optional": {
            "promotion_packet": _rel(Path(args.packet)) if args.packet else None,
            "validator_bin": _rel(Path(args.validator)) if args.validator else None,
        },
        "outputs": {name: _rel(path) for name, path in outputs.items()},
    }
    print(json.dumps(doc, indent=2, sort_keys=True))
    return 0


def _build(args: argparse.Namespace) -> int:
    out_root = Path(args.out).resolve()
    outputs = _output_paths(out_root)
    inputs = _static_inputs()
    _ensure_inputs(inputs)

    tag_layouts = _load_json(inputs["tag_layouts"])
    vocab_filters = _load_json(inputs["vocab_filters"])
    field2_inventory = _load_json(inputs["field2_inventory"])
    anchor_map = _load_json(inputs["anchor_filter_map"])
    anchor_hits = _load_json(inputs["anchor_hits"])
    anchor_hits_delta = _load_json(inputs["anchor_hits_delta"])
    field2_seeds = _load_json(inputs["field2_seeds"])
    unknown_nodes = _load_json(inputs["unknown_nodes"])

    _check_world_id(tag_layouts, "tag_layouts")
    _check_world_id(vocab_filters, "vocab_filters")
    _check_world_id(field2_seeds, "field2_seeds")

    ctx = _packet_context(args.packet)
    packet_provenance = _packet_provenance(ctx, outputs["receipt"])
    runtime_index, runtime_source = _runtime_index(ctx)

    fields_doc = _build_field_layout(tag_layouts)
    fields_doc["sources"] = {"tag_layouts": _rel(inputs["tag_layouts"])}

    source_paths = {
        name: _rel(path)
        for name, path in inputs.items()
        if name
        in {
            "vocab_ops",
            "vocab_filters",
            "field2_inventory",
            "anchor_filter_map",
            "anchor_hits",
            "anchor_hits_delta",
            "field2_seeds",
            "unknown_nodes",
            "network_matrix_index",
        }
    }
    if runtime_source:
        source_paths["runtime_results"] = runtime_source

    arg16_doc = _build_arg16_doc(
        field_index=fields_doc.get("arg16_field_index"),
        field2_inventory=field2_inventory,
        filters_doc=vocab_filters,
        anchor_map=anchor_map,
        anchor_hits=anchor_hits,
        anchor_hits_delta=anchor_hits_delta,
        seeds_doc=field2_seeds,
        packet_provenance=packet_provenance,
        runtime_index=runtime_index,
        runtime_source=runtime_source,
        sources=source_paths,
    )

    unknowns_doc = _build_unknowns_doc(
        arg16_doc=arg16_doc,
        unknown_nodes=unknown_nodes,
        sources={
            "unknown_nodes": _rel(inputs["unknown_nodes"]),
            "field2_inventory": _rel(inputs["field2_inventory"]),
        },
    )

    _write_json(outputs["fields"], fields_doc)
    _write_json(outputs["arg16"], arg16_doc)
    _write_json(outputs["unknowns"], unknowns_doc)

    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "tool": "policygraph_node_fields",
        "world_id": WORLD_ID,
        "inputs": {
            name: {
                "path": _rel(path),
                "sha256": tooling.sha256_path(path) if path.is_file() else None,
            }
            for name, path in inputs.items()
        },
        "outputs": {name: _rel(path) for name, path in outputs.items()},
        "packet": packet_provenance,
        "validator": _rel(Path(args.validator)) if args.validator else None,
        "command": path_utils.relativize_command(sys.argv, repo_root=REPO_ROOT),
    }
    _write_report(
        outputs["report"],
        fields_doc=fields_doc,
        arg16_doc=arg16_doc,
        unknowns_doc=unknowns_doc,
        receipt=receipt,
    )
    _write_json(outputs["receipt"], receipt)
    print(f"[+] wrote { _rel(outputs['fields']) }")
    print(f"[+] wrote { _rel(outputs['arg16']) }")
    print(f"[+] wrote { _rel(outputs['unknowns']) }")
    print(f"[+] wrote { _rel(outputs['receipt']) }")
    print(f"[+] wrote { _rel(outputs['report']) }")
    return 0


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="policygraph_node_fields",
        description="Enumerate fixed-width PolicyGraph node fields.",
    )
    parser.add_argument(
        "--out",
        default=str(REPO_ROOT / "book" / "evidence" / "syncretic" / "policygraph" / "node-fields"),
    )
    parser.add_argument("--packet", help="Promotion packet path (optional).")
    parser.add_argument("--validator", help="sb_validator binary path (optional).")
    parser.add_argument("--describe", action="store_true", help="Print intended inputs/outputs and exit.")

    args = parser.parse_args(argv)
    return args


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    if args.describe:
        return _describe(args)
    return _build(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
