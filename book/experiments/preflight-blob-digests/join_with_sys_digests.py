#!/usr/bin/env python3
"""
Join the repo blob inventory with canonical sys:* digests and the preflight
apply-gate digest corpus.

Static only: no compile/apply.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile_tools import identity as identity_mod  # type: ignore


SCHEMA_VERSION = 1

DEFAULT_INVENTORY = REPO_ROOT / "book/experiments/preflight-blob-digests/out/repo_sb_bin_inventory.json"
DEFAULT_SYS_DIGESTS = REPO_ROOT / "book/graph/mappings/system_profiles/digests.json"
DEFAULT_PREFLIGHT_IR = (
    REPO_ROOT / "book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json"
)


def _rel(path: Path) -> str:
    return to_repo_relative(path, REPO_ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _index_inventory(inv: Dict[str, Any]) -> Dict[str, List[str]]:
    digest_to_paths: Dict[str, List[str]] = {}
    for row in inv.get("rows") or []:
        if not isinstance(row, dict):
            continue
        sha = row.get("sha256")
        p = row.get("path")
        if isinstance(sha, str) and isinstance(p, str):
            digest_to_paths.setdefault(sha, []).append(p)
    for sha in list(digest_to_paths.keys()):
        digest_to_paths[sha] = sorted(set(digest_to_paths[sha]))
    return digest_to_paths


def _load_sys_contract_digests(sys_digests: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    profiles = sys_digests.get("profiles") or {}
    if not isinstance(profiles, dict):
        return out
    for profile_id, entry in profiles.items():
        if not isinstance(entry, dict):
            continue
        contract = entry.get("contract") or {}
        if not isinstance(contract, dict):
            continue
        sha = contract.get("blob_sha256")
        if isinstance(profile_id, str) and isinstance(sha, str):
            out[profile_id] = sha
    return out


def _load_apply_gate_digests(preflight_ir: Dict[str, Any]) -> set[str]:
    out: set[str] = set()
    for entry in preflight_ir.get("apply_gate_digests") or []:
        if isinstance(entry, dict) and isinstance(entry.get("blob_sha256"), str):
            out.add(entry["blob_sha256"])
    return out


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="join_with_sys_digests")
    ap.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    ap.add_argument("--sys-digests", type=Path, default=DEFAULT_SYS_DIGESTS)
    ap.add_argument("--preflight-ir", type=Path, default=DEFAULT_PREFLIGHT_IR)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    world_id = identity_mod.baseline_world_id()
    inv = _load_json(args.inventory)
    sys_d = _load_json(args.sys_digests)
    pf = _load_json(args.preflight_ir) if args.preflight_ir.exists() else {"apply_gate_digests": []}

    if inv.get("world_id") != world_id:
        raise ValueError("inventory world_id mismatch")
    sys_world = (sys_d.get("metadata") or {}).get("world_id")
    if sys_world != world_id:
        raise ValueError("system digests world_id mismatch")
    if pf.get("world_id") != world_id:
        raise ValueError("preflight digest IR world_id mismatch")

    digest_to_paths = _index_inventory(inv)
    sys_contract = _load_sys_contract_digests(sys_d)
    apply_gated = _load_apply_gate_digests(pf)

    sys_rows: List[Dict[str, Any]] = []
    for profile_id, sha in sorted(sys_contract.items()):
        paths = digest_to_paths.get(sha) or []
        sys_rows.append(
            {
                "profile_id": profile_id,
                "blob_sha256": sha,
                "present_in_repo": bool(paths),
                "repo_paths": paths,
                "preflight_digest_classification": (
                    "apply_gated_for_harness_identity" if sha in apply_gated else "unknown"
                ),
            }
        )

    metrics = {
        "inventory_files": int(inv.get("summary", {}).get("metrics", {}).get("files", 0)),
        "inventory_unique_digests": int(inv.get("summary", {}).get("metrics", {}).get("unique_digests", 0)),
        "apply_gate_digests": len(apply_gated),
        "inventory_unique_digests_marked_apply_gated": sum(1 for sha in digest_to_paths.keys() if sha in apply_gated),
        "sys_profiles": len(sys_rows),
        "sys_profiles_with_digest_in_repo": sum(1 for r in sys_rows if r["present_in_repo"]),
        "sys_profiles_marked_apply_gated_by_digest": sum(
            1 for r in sys_rows if r["preflight_digest_classification"] == "apply_gated_for_harness_identity"
        ),
    }

    payload = {
        "tool": "book/experiments/preflight-blob-digests",
        "schema_version": SCHEMA_VERSION,
        "world_id": world_id,
        "inputs": {
            "inventory": _rel(args.inventory),
            "system_profiles_digests": _rel(args.sys_digests),
            "preflight_blob_digests_ir": _rel(args.preflight_ir),
        },
        "metrics": metrics,
        "apply_gate_digest_hits": [
            {"blob_sha256": sha, "repo_paths": digest_to_paths.get(sha) or []}
            for sha in sorted(apply_gated)
        ],
        "sys_profiles": sys_rows,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
