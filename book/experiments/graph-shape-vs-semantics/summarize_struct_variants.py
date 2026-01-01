"""Packet-only summary for graph-shape-vs-semantics."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure repository root is on sys.path for `book` imports when run directly.
REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.analysis import packet_utils


REPO_ROOT = path_utils.find_repo_root(Path(__file__).resolve())
DEFAULT_OUT_ROOT = Path(__file__).resolve().parent / "out" / "derived"
SUMMARY_SCHEMA_VERSION = "graph-shape-vs-semantics.summary.v0"
RECEIPT_SCHEMA_VERSION = "graph-shape-vs-semantics.consumption_receipt.v0"
REQUIRED_EXPORTS = ("runtime_results", "run_manifest")


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing input: {path}")
    doc = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
    if not isinstance(doc, dict):
        raise ValueError(f"expected JSON object at {path}")
    return doc


def derive_output_paths(out_root: Path, run_id: str) -> Dict[str, Path]:
    out_root = path_utils.ensure_absolute(out_root, repo_root=REPO_ROOT)
    derived_root = out_root / run_id
    return {
        "derived_root": derived_root,
        "summary": derived_root / "graph_shape_semantics_summary.json",
        "receipt": derived_root / "consumption_receipt.json",
    }


def summarize_results(results: Dict[str, Any]) -> Dict[str, Any]:
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
        summary["path_edges"] = {
            "profiles": ["adv:path_edges"],
            "mismatches": [p for p in path_edges.get("probes", []) if not p.get("match")],
            "note": "expected allow on /tmp variants denied (VFS canonicalization likely)",
        }

    return summary


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

    provenance = packet_utils.format_packet_provenance(
        ctx, exports=REQUIRED_EXPORTS, receipt_path=paths["receipt"], repo_root=REPO_ROOT
    )
    summary = summarize_results(results)
    doc = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "world_id": ctx.run_manifest.get("world_id"),
        "provenance": provenance,
        "summary": summary,
    }

    summary_path = paths["summary"]
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    write_receipt(
        paths["receipt"],
        world_id=ctx.run_manifest.get("world_id"),
        packet_ctx=ctx,
        exports_used=REQUIRED_EXPORTS,
        outputs={"summary": summary_path},
    )


if __name__ == "__main__":
    main()
