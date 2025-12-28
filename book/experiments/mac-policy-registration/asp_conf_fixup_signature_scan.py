#!/usr/bin/env python3
"""Find mac_policy_conf candidates via fixup slots pointing at ASP strings."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from book.api import path_utils


def _load_world_id(repo_root: Path) -> Optional[str]:
    baseline = repo_root / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"
    if not baseline.exists():
        return None
    try:
        data = json.loads(baseline.read_text())
    except Exception:
        return None
    return data.get("world_id")


def _parse_addr(value) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    if text.startswith("0x-"):
        return -int(text[3:], 16)
    if text.startswith("-0x"):
        return -int(text[3:], 16)
    if text.startswith("0x"):
        return int(text, 16)
    try:
        return int(text, 0)
    except Exception:
        return None


def _u64(value: int) -> int:
    return value & ((1 << 64) - 1)


def _find_interval(intervals: List[Dict[str, object]], vmaddr: int) -> Optional[Dict[str, object]]:
    lo = 0
    hi = len(intervals) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start = intervals[mid]["start"]
        end = intervals[mid]["end"]
        if vmaddr < start:
            hi = mid - 1
        elif vmaddr >= end:
            lo = mid + 1
        else:
            return intervals[mid]
    return None


def _load_intervals(fileset_index: Path) -> List[Dict[str, object]]:
    data = json.loads(fileset_index.read_text())
    intervals = []
    for item in data.get("segment_intervals", []):
        start = item.get("start")
        end = item.get("end")
        if start is None or end is None:
            continue
        intervals.append(
            {
                "start": int(start),
                "end": int(end),
                "entry_id": item.get("entry_id"),
                "segment_name": item.get("segment_name"),
                "is_exec": item.get("is_exec"),
            }
        )
    return sorted(intervals, key=lambda rec: rec["start"])


def _extract_asp_strings(instances: Path) -> Dict[str, object]:
    data = json.loads(instances.read_text())
    for inst in data.get("instances", []):
        mpc = inst.get("mpc") or {}
        if mpc.get("mpc_fullname") != "Apple System Policy" and mpc.get("mpc_name") != "ASP":
            continue
        recon = inst.get("mpc_reconstructed") or {}
        fields = recon.get("fields") or {}
        name_val = _parse_addr((fields.get("mpc_name") or {}).get("value"))
        fullname_val = _parse_addr((fields.get("mpc_fullname") or {}).get("value"))
        mpc_offset = _parse_addr((recon.get("base") or {}).get("offset"))
        rel_ops = ((fields.get("mpc_ops") or {}).get("store_value") or {}).get("relative_to_mpc_base")
        rel_delta = _parse_addr((rel_ops or {}).get("delta"))
        return {
            "mpc_name": mpc.get("mpc_name"),
            "mpc_fullname": mpc.get("mpc_fullname"),
            "name_ptr": name_val,
            "fullname_ptr": fullname_val,
            "mpc_offset": mpc_offset,
            "mpc_ops_offset": _parse_addr(mpc.get("mpc_ops_offset")),
            "ops_relative_to_mpc": rel_delta,
        }
    return {}


def _build_fixup_index(
    fixups_path: Path,
) -> Tuple[Dict[int, List[Dict[str, object]]], Dict[int, Dict[str, object]], Dict[int, List[Dict[str, object]]]]:
    by_target: Dict[int, List[Dict[str, object]]] = {}
    by_location: Dict[int, Dict[str, object]] = {}
    by_decoded_target: Dict[int, List[Dict[str, object]]] = {}
    with fixups_path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            resolved = rec.get("resolved_unsigned")
            if resolved is None and "r" in rec:
                resolved = rec.get("r")
            vmaddr = rec.get("vmaddr")
            if vmaddr is None and "v" in rec:
                vmaddr = rec.get("v")
            if vmaddr is None:
                continue
            vmaddr = int(vmaddr)
            if resolved is not None:
                try:
                    resolved = int(resolved)
                except Exception:
                    resolved = None
            if resolved is not None:
                by_target.setdefault(resolved, []).append(rec)
            by_location[vmaddr] = rec
            if rec.get("pointer_format") == 8:
                decoded = rec.get("decoded") or {}
                target = decoded.get("target")
                if target is not None:
                    by_decoded_target.setdefault(int(target), []).append(rec)
    return by_target, by_location, by_decoded_target


def main() -> int:
    parser = argparse.ArgumentParser(description="Find ASP mac_policy_conf candidates via fixup slots.")
    parser.add_argument("--fixups", required=True, help="kc_fixups.jsonl path")
    parser.add_argument("--fileset-index", required=True, help="kc_fileset_index.json path")
    parser.add_argument("--instances", required=True, help="mac_policy_register_instances.json path")
    parser.add_argument("--out", required=True, help="Output JSON path")
    parser.add_argument(
        "--allow-unresolved",
        action="store_true",
        help="Also match fixups by decoded target bits when resolved_unsigned is unavailable.",
    )
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    world_id = _load_world_id(repo_root)

    fixups_path = Path(args.fixups)
    fileset_index_path = Path(args.fileset_index)
    instances_path = Path(args.instances)
    out_path = Path(args.out)

    asp_strings = _extract_asp_strings(instances_path)
    intervals = _load_intervals(fileset_index_path)
    by_target, by_location, by_decoded_target = _build_fixup_index(fixups_path)

    name_ptr = asp_strings.get("name_ptr")
    fullname_ptr = asp_strings.get("fullname_ptr")
    mpc_offset = asp_strings.get("mpc_offset")
    mpc_ops_offset = asp_strings.get("mpc_ops_offset") or 0x20
    ops_rel = asp_strings.get("ops_relative_to_mpc")

    resolved_candidates: List[Dict[str, object]] = []
    target_candidates: List[Dict[str, object]] = []
    summary = {
        "resolved_name_ptr_matches": 0,
        "resolved_fullname_ptr_matches": 0,
        "resolved_candidate_count": 0,
        "target_name_matches": 0,
        "target_fullname_matches": 0,
        "target_candidate_count": 0,
    }
    if name_ptr is None or fullname_ptr is None:
        status = {"resolved": "blocked_missing_strings", "target": "blocked_missing_strings"}
    else:
        name_fixups = by_target.get(name_ptr, [])
        full_fixups = by_target.get(fullname_ptr, [])
        summary["resolved_name_ptr_matches"] = len(name_fixups)
        summary["resolved_fullname_ptr_matches"] = len(full_fixups)
        full_locations = {int(rec["vmaddr"]) for rec in full_fixups}
        for rec in name_fixups:
            base = int(rec["vmaddr"])
            if (base + 8) not in full_locations:
                continue
            base_interval = _find_interval(intervals, base)
            ops_field_addr = base + int(mpc_ops_offset)
            ops_fixup = by_location.get(ops_field_addr)
            ops_fixup_resolved = ops_fixup.get("resolved_unsigned") if ops_fixup else None
            x0_base = None
            if mpc_offset is not None:
                x0_base = base - int(mpc_offset)
            ops_base = None
            if ops_rel is not None:
                ops_base = base + int(ops_rel)
            resolved_candidates.append(
                {
                    "mpc_base": base,
                    "name_slot": base,
                    "fullname_slot": base + 8,
                    "name_ptr": name_ptr,
                    "fullname_ptr": fullname_ptr,
                    "match_mode": "resolved_unsigned",
                    "mpc_offset": mpc_offset,
                    "mpc_ops_offset": mpc_ops_offset,
                    "ops_relative_to_mpc": ops_rel,
                    "x0_base": x0_base,
                    "ops_base_from_relative": ops_base,
                    "ops_field_slot": ops_field_addr,
                    "ops_fixup_resolved": ops_fixup_resolved,
                    "mpc_segment": {
                        "entry_id": base_interval.get("entry_id") if base_interval else None,
                        "segment_name": base_interval.get("segment_name") if base_interval else None,
                        "is_exec": base_interval.get("is_exec") if base_interval else None,
                    },
                    "ops_field_segment": {
                        "entry_id": ops_fixup.get("owner_entry") if ops_fixup else None,
                        "segment_name": ops_fixup.get("owner_segment") if ops_fixup else None,
                    },
                }
            )
        summary["resolved_candidate_count"] = len(resolved_candidates)
        status = {"resolved": "ok" if resolved_candidates else "no_adjacent_fixup_slots"}

        if args.allow_unresolved:
            name_target = _u64(name_ptr) & 0x3FFFFFFF
            fullname_target = _u64(fullname_ptr) & 0x3FFFFFFF
            name_decoded = by_decoded_target.get(name_target, [])
            full_decoded = by_decoded_target.get(fullname_target, [])
            summary["target_name_matches"] = len(name_decoded)
            summary["target_fullname_matches"] = len(full_decoded)
            full_decoded_locations = {int(rec["vmaddr"]) for rec in full_decoded}
            for rec in name_decoded:
                base = int(rec["vmaddr"])
                if (base + 8) not in full_decoded_locations:
                    continue
                base_interval = _find_interval(intervals, base)
                ops_field_addr = base + int(mpc_ops_offset)
                ops_fixup = by_location.get(ops_field_addr)
                ops_fixup_resolved = ops_fixup.get("resolved_unsigned") if ops_fixup else None
                x0_base = None
                if mpc_offset is not None:
                    x0_base = base - int(mpc_offset)
                ops_base = None
                if ops_rel is not None:
                    ops_base = base + int(ops_rel)
                target_candidates.append(
                    {
                        "mpc_base": base,
                        "name_slot": base,
                        "fullname_slot": base + 8,
                        "name_target": name_target,
                        "fullname_target": fullname_target,
                        "match_mode": "decoded_target",
                        "mpc_offset": mpc_offset,
                        "mpc_ops_offset": mpc_ops_offset,
                        "ops_relative_to_mpc": ops_rel,
                        "x0_base": x0_base,
                        "ops_base_from_relative": ops_base,
                        "ops_field_slot": ops_field_addr,
                        "ops_fixup_resolved": ops_fixup_resolved,
                        "mpc_segment": {
                            "entry_id": base_interval.get("entry_id") if base_interval else None,
                            "segment_name": base_interval.get("segment_name") if base_interval else None,
                            "is_exec": base_interval.get("is_exec") if base_interval else None,
                        },
                        "ops_field_segment": {
                            "entry_id": ops_fixup.get("owner_entry") if ops_fixup else None,
                            "segment_name": ops_fixup.get("owner_segment") if ops_fixup else None,
                        },
                    }
                )
            summary["target_candidate_count"] = len(target_candidates)
            status["target"] = "ok" if target_candidates else "no_adjacent_target_slots"
        else:
            status["target"] = "disabled"

    output = {
        "meta": {
            "world_id": world_id,
            "fixups": path_utils.to_repo_relative(fixups_path, repo_root),
            "fileset_index": path_utils.to_repo_relative(fileset_index_path, repo_root),
            "instances": path_utils.to_repo_relative(instances_path, repo_root),
        },
        "asp_strings": asp_strings,
        "summary": summary,
        "status": status,
        "candidates_resolved": resolved_candidates,
        "candidates_target": target_candidates,
    }
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True))
    print("Wrote", path_utils.to_repo_relative(out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
