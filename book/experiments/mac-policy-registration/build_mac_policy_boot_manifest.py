#!/usr/bin/env python3
"""Build a mac-policy boot manifest from recovered registration instances."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional

from book.api import path_utils


def _load_world_id(repo_root: Path) -> Optional[str]:
    baseline = repo_root / "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
    if not baseline.exists():
        return None
    data = json.loads(baseline.read_text())
    return data.get("world_id")


def _slots_owner_hist(slots: List[Dict[str, object]]) -> Dict[str, int]:
    counter: Counter[str] = Counter()
    for slot in slots:
        owner = slot.get("owner_entry")
        if owner:
            counter[str(owner)] += 1
    return dict(counter)


def _normalize_slot(slot: Dict[str, object]) -> Dict[str, object]:
    keep = {
        "slot_offset",
        "absolute_this_offset",
        "resolved",
        "owner_entry",
        "source",
        "hook_field_name",
        "external_hook_name",
        "external_source",
        "external_note",
    }
    return {k: v for k, v in slot.items() if k in keep and v is not None}


def _derive_ops_slots(inst: Dict[str, object]) -> Dict[str, object]:
    mpc = inst.get("mpc") or {}
    asp_chain = inst.get("asp_store_chain") or {}
    slots: List[Dict[str, object]] = []
    mode = None
    layout_meta = None
    layout_slots = (mpc.get("ops_layout_slots") or {}).get("hooks") or []
    if layout_slots:
        mode = "ops_layout"
        slots = [_normalize_slot(slot) for slot in layout_slots]
        layout_meta = (mpc.get("ops_layout_slots") or {}).get("layout_meta")
    elif asp_chain.get("ops_slots_merged"):
        mode = "object_relative_store_chain"
        slots = [_normalize_slot(slot) for slot in asp_chain.get("ops_slots_merged") or []]
    else:
        exec_slots = (mpc.get("ops_exec_slots") or {}).get("slots") or []
        if exec_slots:
            mode = "ops_pointer_scan"
            for slot in exec_slots:
                slots.append(
                    _normalize_slot(
                        {
                            "slot_offset": slot.get("slot_offset"),
                            "resolved": slot.get("resolved"),
                            "owner_entry": slot.get("owner_entry"),
                            "source": "ops_pointer_scan",
                        }
                    )
                )
    hist = _slots_owner_hist(slots)
    owner_top = max(hist.items(), key=lambda item: item[1])[0] if hist else None
    return {
        "mode": mode,
        "slots": slots,
        "owner_histogram": hist,
        "owner_top": owner_top,
        "layout_meta": layout_meta,
        "external_offset_crosscheck": asp_chain.get("offset_crosscheck") if asp_chain else None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build mac policy boot manifest.")
    parser.add_argument("--instances", required=True, help="mac_policy_register_instances.json path")
    parser.add_argument("--out", required=True, help="Output manifest JSON path")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    instances_path = path_utils.ensure_absolute(Path(args.instances), repo_root)
    out_path = path_utils.ensure_absolute(Path(args.out), repo_root)

    instances = json.loads(instances_path.read_text())
    world_id = _load_world_id(repo_root)

    policies = []
    for inst in instances.get("instances", []):
        mpc = inst.get("mpc") or {}
        call_site = inst.get("call_site") or {}
        policy_name = mpc.get("mpc_name")
        policy_fullname = mpc.get("mpc_fullname")
        mpc_provenance = "reconstructed_store" if inst.get("mpc_reconstructed") else "static_decode"
        ops_evidence = _derive_ops_slots(inst)
        handlep = inst.get("handlep") or {}
        policies.append(
            {
                "policy": {"name": policy_name, "fullname": policy_fullname},
                "call_site": {
                    "address": (call_site.get("address") if call_site else None),
                    "caller_function": (call_site.get("caller_function") if call_site else None),
                    "caller_fileset_entry": (call_site.get("caller_fileset_entry") if call_site else None),
                },
                "mpc_provenance": mpc_provenance,
                "mpc_ops_ptr": (mpc.get("mpc_ops_ptr") or {}).get("resolved"),
                "handlep": {
                    "addr": handlep.get("handlep_addr"),
                    "addr_is_offset": handlep.get("handlep_addr_is_offset"),
                    "offset_from_mpc": handlep.get("handlep_offset_from_mpc"),
                    "storage_kind": handlep.get("handlep_storage_kind"),
                    "owner_entry": handlep.get("handlep_owner_entry"),
                    "block": handlep.get("handlep_block"),
                },
                "ops_evidence": ops_evidence,
            }
        )

    out = {
        "meta": {
            "world_id": world_id,
            "build_id": (instances.get("meta") or {}).get("build_id"),
            "mac_policy_register": (instances.get("meta") or {}).get("mac_policy_register"),
            "instances_path": path_utils.to_repo_relative(instances_path, repo_root),
        },
        "policies": policies,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2, sort_keys=True))
    print("Wrote", path_utils.to_repo_relative(out_path, repo_root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
