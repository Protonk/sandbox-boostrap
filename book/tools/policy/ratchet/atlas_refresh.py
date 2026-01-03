#!/usr/bin/env python3
"""
Refresh Field2 Atlas outputs from a promotion packet and align decisions/frontier/tranche.
"""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

RATCHET_ROOT = Path(__file__).resolve().parent
if str(RATCHET_ROOT) not in sys.path:
    sys.path.insert(0, str(RATCHET_ROOT))

from book.api import path_utils
from book.api.runtime.analysis import packet_utils

import atlas_build
import atlas_runtime
import atlas_static

FIELD2_ROOT = REPO_ROOT / "book" / "evidence" / "experiments" / "field2-final-final"
DEFAULT_MILESTONE = FIELD2_ROOT / "active_milestone.json"
DEFAULT_DECISIONS = FIELD2_ROOT / "decisions.jsonl"
FRONTIER_SCRIPT = RATCHET_ROOT / "frontier_build.py"
TRANCHE_SCRIPT = RATCHET_ROOT / "tranche_select.py"


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _run_script(script_path: Path, args: Iterable[str]) -> None:
    argv = [str(script_path), *args]
    old_argv = sys.argv
    try:
        sys.argv = argv
        runpy.run_path(str(script_path), run_name="__main__")
    finally:
        sys.argv = old_argv


def _update_decisions(
    decisions_path: Path,
    *,
    claim_keys: set[str],
    run_id: str,
    artifact_digest: str,
    packet_relpath: str,
    atlas_run_id: str,
    mapping_delta_relpath: str,
    allow_missing: bool,
) -> int:
    lines = decisions_path.read_text(encoding="utf-8").splitlines()
    parsed = _load_jsonl(decisions_path)
    seen = {rec.get("claim_key") for rec in parsed if rec.get("claim_key")}
    missing = claim_keys - seen
    if missing and not allow_missing:
        raise ValueError(f"missing decisions for: {sorted(missing)}")

    updated = 0
    out_lines = []
    for line in lines:
        if not line.strip():
            out_lines.append(line)
            continue
        rec = json.loads(line)
        key = rec.get("claim_key")
        if key in claim_keys:
            evidence = rec.setdefault("evidence", {})
            evidence["packet_run_id"] = run_id
            evidence["artifact_index_digest"] = artifact_digest
            evidence["packet_relpath"] = packet_relpath
            consumer = rec.setdefault("consumer", {})
            consumer["atlas_run_id"] = atlas_run_id
            consumer["mapping_delta_relpath"] = mapping_delta_relpath
            rec["last_attempt_packet"] = packet_relpath
            out_lines.append(json.dumps(rec, ensure_ascii=True))
            updated += 1
            continue
        out_lines.append(line)

    decisions_path.write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    if missing:
        print(f"[!] missing decisions (not updated): {sorted(missing)}")
    return updated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--packet", type=Path, required=True, help="Path to promotion_packet.json")
    parser.add_argument(
        "--out-root",
        type=Path,
        default=atlas_build.DEFAULT_OUT_ROOT,
        help="Output root for derived artifacts",
    )
    parser.add_argument("--milestone", type=Path, default=DEFAULT_MILESTONE)
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    parser.add_argument("--skip-frontier", action="store_true")
    parser.add_argument("--skip-tranche", action="store_true")
    parser.add_argument("--allow-missing-decisions", action="store_true")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    packet_path = path_utils.ensure_absolute(args.packet, repo_root=repo_root)
    if not packet_path.exists():
        raise FileNotFoundError(f"missing packet: {packet_path}")

    static_doc = atlas_static.build_records()
    atlas_static.write_records(static_doc)

    ctx = packet_utils.resolve_packet_context(
        packet_path, required_exports=atlas_runtime.REQUIRED_EXPORTS, repo_root=repo_root
    )
    out_root = path_utils.ensure_absolute(args.out_root, repo_root=repo_root)
    paths = atlas_build.derive_output_paths(out_root, ctx.run_id)

    runtime_doc, ctx = atlas_runtime.build_runtime_results(
        packet_path, receipt_path=paths["receipt"], packet_context=ctx
    )
    atlas_runtime.write_results(runtime_doc, output_path=paths["runtime_results"])

    atlas_doc, summary_doc = atlas_build.build_atlas(runtime_doc, runtime_results_path=paths["runtime_results"])
    delta_doc = atlas_build.build_mapping_delta(runtime_doc, runtime_events_path=ctx.export_paths["runtime_events"])
    atlas_build.write_outputs(
        atlas_doc,
        summary_doc,
        atlas_path=paths["atlas"],
        summary_path=paths["summary"],
        summary_md_path=paths["summary_md"],
        delta_path=paths["delta"],
        delta_doc=delta_doc,
    )
    atlas_runtime.write_consumption_receipt(
        paths["receipt"],
        world_id=runtime_doc.get("world_id"),
        packet_ctx=ctx,
        exports_used=atlas_runtime.REQUIRED_EXPORTS,
        outputs={
            "runtime_results": paths["runtime_results"],
            "atlas": paths["atlas"],
            "summary": paths["summary"],
            "summary_md": paths["summary_md"],
            "mapping_delta": paths["delta"],
        },
    )

    if not paths["delta"].exists():
        raise FileNotFoundError(f"missing mapping_delta: {paths['delta']}")

    milestone = _load_json(args.milestone)
    candidates = milestone.get("candidates") or []
    claim_keys = {entry.get("claim_key") for entry in candidates if entry.get("claim_key")}
    if not claim_keys:
        raise ValueError("active milestone contains no claim keys")

    packet_relpath = path_utils.to_repo_relative(packet_path, repo_root=repo_root)
    mapping_delta_relpath = path_utils.to_repo_relative(paths["delta"], repo_root=repo_root)
    updated = _update_decisions(
        args.decisions,
        claim_keys=claim_keys,
        run_id=ctx.run_id,
        artifact_digest=ctx.artifact_index_sha256,
        packet_relpath=packet_relpath,
        atlas_run_id=ctx.run_id,
        mapping_delta_relpath=mapping_delta_relpath,
        allow_missing=args.allow_missing_decisions,
    )

    if not args.skip_frontier:
        _run_script(FRONTIER_SCRIPT, ["--atlas", str(paths["atlas"])])
    if not args.skip_tranche:
        _run_script(TRANCHE_SCRIPT, [])

    atlas_relpath = path_utils.to_repo_relative(paths["atlas"], repo_root=repo_root)
    print(f"[+] atlas_run_id={ctx.run_id}")
    print(f"[+] updated_decisions={updated}")
    print(f"[+] atlas={atlas_relpath}")


if __name__ == "__main__":
    main()
