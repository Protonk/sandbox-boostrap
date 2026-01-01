"""Packet-only summary for graph-shape-vs-semantics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.analysis import packet_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())
DEFAULT_OUT_ROOT = Path(__file__).resolve().parent / "out" / "derived"
SUMMARY_SCHEMA_VERSION = "graph-shape-vs-semantics.summary.v0"
VERDICTS_SCHEMA_VERSION = "graph-shape-vs-semantics.verdicts.v0"
COUNTEREXAMPLES_SCHEMA_VERSION = "graph-shape-vs-semantics.counterexamples.v0"
RECEIPT_SCHEMA_VERSION = "graph-shape-vs-semantics.consumption_receipt.v0"
REQUIRED_EXPORTS = ("runtime_results", "run_manifest", "path_witnesses")


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(doc, dict):
        raise ValueError(f"expected JSON object at {path}")
    return doc


def _index_path_witnesses(doc: Optional[Dict[str, Any]]) -> Dict[tuple[str, str], Dict[str, Any]]:
    if not doc:
        return {}
    records = doc.get("records") or []
    indexed: Dict[tuple[str, str], Dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        lane = record.get("lane")
        scenario_id = record.get("scenario_id")
        if isinstance(lane, str) and isinstance(scenario_id, str):
            indexed[(lane, scenario_id)] = record
    return indexed


def _is_canonicalization_pair(requested: Optional[str], observed: Optional[str]) -> bool:
    if not isinstance(requested, str) or not isinstance(observed, str):
        return False
    if requested == observed:
        return False
    alias_pairs = (("/tmp", "/private/tmp"),)
    for alias, canonical in alias_pairs:
        if requested.startswith(alias) and observed.startswith(canonical):
            return True
        if requested.startswith(canonical) and observed.startswith(alias):
            return True
    return False


def _canonicalization_witness(
    *,
    requested_path: Optional[str],
    scenario_witness: Optional[Dict[str, Any]],
    baseline_witness: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not isinstance(requested_path, str) or not requested_path:
        return None
    for witness in (scenario_witness, baseline_witness):
        if not witness:
            continue
        observed = witness.get("observed_path") or witness.get("normalized_path")
        if _is_canonicalization_pair(requested_path, observed):
            return {
                "lane": witness.get("lane"),
                "scenario_id": witness.get("scenario_id"),
                "requested_path": requested_path,
                "observed_path": witness.get("observed_path"),
                "observed_path_source": witness.get("observed_path_source"),
                "normalized_path": witness.get("normalized_path"),
                "normalized_path_source": witness.get("normalized_path_source"),
            }
    return None


def derive_output_paths(out_root: Path, run_id: str) -> Dict[str, Path]:
    out_root = path_utils.ensure_absolute(out_root, repo_root=REPO_ROOT)
    derived_root = out_root / run_id
    return {
        "derived_root": derived_root,
        "summary": derived_root / "graph_shape_semantics_summary.json",
        "verdicts": derived_root / "graph_shape_semantics_verdicts.json",
        "counterexamples": derived_root / "graph_shape_semantics_counterexamples.json",
        "receipt": derived_root / "consumption_receipt.json",
    }


def summarize_results(
    results: Dict[str, Any],
    *,
    path_witnesses: Optional[Dict[str, Any]] = None,
    witness_source: Optional[str] = None,
) -> Dict[str, Any]:
    witness_index = _index_path_witnesses(path_witnesses)
    pairs = [
        ("adv:struct_flat", "adv:struct_nested", "structural variants of same intent (read/write)"),
        ("adv:mach_simple_allow", "adv:mach_simple_variants", "mach global-name literal vs regex variants"),
        ("adv:mach_local_literal", "adv:mach_local_regex", "mach local-name literal vs regex variants"),
    ]

    summary: Dict[str, Any] = {}
    for a, b, label in pairs:
        ra = results.get(a)
        rb = results.get(b)
        if not ra or not rb:
            summary[label] = {"status": "missing", "details": f"missing results for {a} or {b}"}
            continue

        def key(probe: dict) -> str:
            exp_id = probe.get("expectation_id", "")
            parts = exp_id.split(":")
            return parts[-1] if parts else exp_id

        probes_a = {key(p): p for p in ra.get("probes", [])}
        probes_b = {key(p): p for p in rb.get("probes", [])}

        common = set(probes_a) & set(probes_b)
        aligned = []
        mismatches = []
        for exp_id in sorted(common):
            pa = probes_a[exp_id]
            pb = probes_b[exp_id]
            same = (
                pa.get("actual") == pb.get("actual") == pa.get("expected") == pb.get("expected")
                and pa.get("match")
                and pb.get("match")
            )
            aligned.append(
                {
                    "expectation_id": exp_id,
                    "profile_a": a,
                    "profile_b": b,
                    "expected": pa.get("expected"),
                    "actual_a": pa.get("actual"),
                    "actual_b": pb.get("actual"),
                    "both_match": same,
                }
            )
            if not same:
                mismatches.append(exp_id)

        summary[label] = {
            "profiles": [a, b],
            "aligned_expectations": aligned,
            "mismatches": mismatches,
        }

    path_edges = results.get("adv:path_edges")
    if path_edges:
        mismatches = [p for p in path_edges.get("probes", []) if not p.get("match")]
        canonicalization = []
        unresolved = []
        for probe in mismatches:
            probe_name = probe.get("name")
            expectation_id = probe.get("expectation_id")
            scenario_id = expectation_id or probe.get("scenario_id")
            requested = probe.get("path") or probe.get("target")
            scenario_witness = witness_index.get(("scenario", scenario_id)) if scenario_id else None
            baseline_id = f"baseline:adv:path_edges:{probe_name}" if probe_name else None
            baseline_witness = witness_index.get(("baseline", baseline_id)) if baseline_id else None
            witness = _canonicalization_witness(
                requested_path=requested,
                scenario_witness=scenario_witness,
                baseline_witness=baseline_witness,
            )
            if witness:
                canonicalization.append(
                    {
                        "expectation_id": expectation_id,
                        "probe_name": probe_name,
                        "operation": probe.get("operation"),
                        "witness": witness,
                    }
                )
            else:
                unresolved.append(expectation_id or probe_name or "unknown")

        summary["path_edges"] = {
            "profiles": ["adv:path_edges"],
            "mismatches": mismatches,
            "canonicalization_boundary": canonicalization,
            "unresolved_mismatches": unresolved,
            "witness_source": witness_source,
            "note": "path-edge evaluation uses witness-backed canonicalization equivalence",
        }

    return summary


def _counterexample_from_pair(label: str, entry: Dict[str, Any]) -> Dict[str, Any] | None:
    mismatches = entry.get("mismatches") or []
    if not mismatches:
        return None
    aligned = entry.get("aligned_expectations") or []
    by_id = {row.get("expectation_id"): row for row in aligned if isinstance(row, dict)}
    for exp_id in mismatches:
        row = by_id.get(exp_id)
        if not row:
            continue
        return {
            "transformation": label,
            "expectation_id": exp_id,
            "expected": row.get("expected"),
            "actual_a": row.get("actual_a"),
            "actual_b": row.get("actual_b"),
            "profile_a": row.get("profile_a"),
            "profile_b": row.get("profile_b"),
        }
    return {"transformation": label, "expectation_id": str(mismatches[0])}


def _counterexample_from_path_edges(
    entry: Dict[str, Any], *, mismatches: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any] | None:
    mismatches = mismatches or entry.get("mismatches") or []
    if not mismatches:
        return None
    first = mismatches[0] if isinstance(mismatches[0], dict) else {}
    witness_lookup = {}
    for row in entry.get("canonicalization_boundary") or []:
        if isinstance(row, dict):
            key = row.get("expectation_id") or row.get("probe_name")
            if key:
                witness_lookup[key] = row.get("witness")
    witness = witness_lookup.get(first.get("expectation_id") or first.get("name"))
    return {
        "transformation": "path_edges",
        "expectation_id": first.get("expectation_id"),
        "operation": first.get("operation"),
        "target": first.get("path"),
        "expected": first.get("expected"),
        "actual": first.get("actual"),
        "failure_stage": (first.get("runtime_result") or {}).get("failure_stage"),
        "failure_kind": (first.get("runtime_result") or {}).get("failure_kind"),
        "canonicalization_witness": witness,
    }


def build_verdicts(summary: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    verdicts: Dict[str, Any] = {}
    counterexamples: List[Dict[str, Any]] = []
    for label, entry in summary.items():
        if entry.get("status") == "missing":
            verdicts[label] = {
                "status": "missing",
                "details": entry.get("details"),
            }
            continue
        mismatches = entry.get("mismatches") or []
        if not mismatches:
            verdicts[label] = {
                "status": "preserved",
                "profiles": entry.get("profiles"),
                "coverage": len(entry.get("aligned_expectations") or []),
            }
            continue
        if label == "path_edges":
            boundary = entry.get("canonicalization_boundary") or []
            boundary_keys = set()
            for row in boundary:
                if not isinstance(row, dict):
                    continue
                key = row.get("expectation_id") or row.get("probe_name")
                if key:
                    boundary_keys.add(key)
            effective = []
            for mismatch in mismatches:
                if not isinstance(mismatch, dict):
                    continue
                key = mismatch.get("expectation_id") or mismatch.get("name")
                if key in boundary_keys:
                    continue
                effective.append(mismatch)
            if not effective:
                verdicts[label] = {
                    "status": "preserved",
                    "profiles": entry.get("profiles"),
                    "canonicalization_equivalence": len(boundary_keys),
                    "witness_source": entry.get("witness_source"),
                }
                continue
            counter = _counterexample_from_path_edges(entry, mismatches=effective)
        else:
            counter = _counterexample_from_pair(label, entry)
        verdicts[label] = {
            "status": "broken",
            "profiles": entry.get("profiles"),
            "mismatch_count": len(mismatches),
            "counterexample": counter,
        }
        if counter:
            counterexamples.append(counter)
    return verdicts, counterexamples


def write_receipt(
    receipt_path: Path,
    *,
    world_id: str,
    packet_ctx: packet_utils.PacketContext,
    exports_used: Tuple[str, ...],
    outputs: Dict[str, Path],
) -> None:
    receipt_path = path_utils.ensure_absolute(receipt_path, repo_root=REPO_ROOT)
    export_paths: Dict[str, str] = {}
    for key in exports_used:
        export_paths[key] = path_utils.to_repo_relative(packet_ctx.export_paths[key], repo_root=REPO_ROOT)
    receipt = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize graph-shape-vs-semantics from a promotion packet.")
    parser.add_argument("--packet", type=Path, required=True, help="Path to promotion_packet.json")
    parser.add_argument(
        "--out-root",
        type=Path,
        default=DEFAULT_OUT_ROOT,
        help="Output root for derived artifacts (run_id subdir will be created)",
    )
    args = parser.parse_args()

    ctx = packet_utils.resolve_packet_context(args.packet, required_exports=REQUIRED_EXPORTS, repo_root=REPO_ROOT)
    paths = derive_output_paths(args.out_root, ctx.run_id)
    runtime_results_path = ctx.export_paths["runtime_results"]
    results = _load_json(runtime_results_path)
    path_witnesses_doc = _load_json(ctx.export_paths["path_witnesses"])
    witness_source = path_utils.to_repo_relative(ctx.export_paths["path_witnesses"], repo_root=REPO_ROOT)

    provenance = packet_utils.format_packet_provenance(
        ctx, exports=REQUIRED_EXPORTS, receipt_path=paths["receipt"], repo_root=REPO_ROOT
    )
    summary = summarize_results(results, path_witnesses=path_witnesses_doc, witness_source=witness_source)
    doc = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "world_id": ctx.run_manifest.get("world_id"),
        "provenance": provenance,
        "summary": summary,
    }

    summary_path = paths["summary"]
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    verdicts, counterexamples = build_verdicts(summary)
    verdict_doc = {
        "schema_version": VERDICTS_SCHEMA_VERSION,
        "world_id": ctx.run_manifest.get("world_id"),
        "provenance": provenance,
        "verdicts": verdicts,
    }
    verdicts_path = paths["verdicts"]
    verdicts_path.write_text(json.dumps(verdict_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    counter_doc = {
        "schema_version": COUNTEREXAMPLES_SCHEMA_VERSION,
        "world_id": ctx.run_manifest.get("world_id"),
        "provenance": provenance,
        "counterexamples": counterexamples,
    }
    counterexamples_path = paths["counterexamples"]
    counterexamples_path.write_text(json.dumps(counter_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    write_receipt(
        paths["receipt"],
        world_id=ctx.run_manifest.get("world_id"),
        packet_ctx=ctx,
        exports_used=REQUIRED_EXPORTS,
        outputs={
            "summary": summary_path,
            "verdicts": verdicts_path,
            "counterexamples": counterexamples_path,
        },
    )


if __name__ == "__main__":
    main()
