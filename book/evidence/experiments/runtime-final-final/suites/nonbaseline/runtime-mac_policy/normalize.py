"""
Normalize raw mac_policy_register trace logs into runtime_mac_policy_registration.json.

Usage (example):
    python -m book.experiments.runtime_mac_policy.normalize \
        --raw book/evidence/experiments/runtime-final-final/suites/nonbaseline/runtime-mac_policy/out/raw/mac_policy.log \
        --out book/evidence/experiments/runtime-final-final/suites/nonbaseline/runtime-mac_policy/out/runtime_mac_policy_registration.json \
        --runtime-world-id runtime-mac-policy-dev

The raw log format is intentionally simple: lines starting with "EVENT" followed
by key=value pairs (e.g., "EVENT mpc=0x1 handlep=0x2 xd=0x0"). Unknown tokens
are ignored. Pointer-like values are preserved as strings; empty fields default
to null/empty lists in the JSON.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Dict, Iterable, List, Optional

from book.api import path_utils


def sha256_hex(path: pathlib.Path) -> Optional[str]:
    if not path or not path.exists():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_event_line(line: str) -> Optional[Dict[str, str]]:
    """Parse a single EVENT line of the form: EVENT key=value key2=value2."""
    stripped = line.strip()
    if not stripped or not stripped.startswith("EVENT"):
        return None
    tokens = stripped.split()
    fields: Dict[str, str] = {}
    for token in tokens[1:]:
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def parse_raw_log(lines: Iterable[str]) -> List[Dict]:
    events: List[Dict] = []
    for line in lines:
        fields = parse_event_line(line)
        if fields is None:
            continue
        slots = fields.get("slots")
        raw_slots = []
        if slots:
            raw_slots = [slot.strip() for slot in slots.split(",") if slot.strip()]
        ops_sample_raw = fields.get("ops_sample")
        ops_sample = []
        if ops_sample_raw:
            for idx, val in enumerate(ops_sample_raw.split(",")):
                val = val.strip()
                if not val:
                    continue
                ops_sample.append({"index": idx, "addr": val, "image": None, "segment": None, "offset": None})
        event = {
            "target_addr": fields.get("target"),
            "target_image": fields.get("target_image"),
            "target_symbol": fields.get("target_symbol"),
            "caller_pc": fields.get("caller"),
            "caller_image": fields.get("caller_image"),
            "caller_classification": fields.get("caller_class"),
            "args": {
                "mpc": fields.get("mpc"),
                "handlep": fields.get("handlep"),
                "xd": fields.get("xd"),
            },
            "timestamp_ns": None,
            "mpc_region": None,
            "mpc_raw_slots": raw_slots,
            "mpc_decoded": {
                "name": None,
                "fullname": None,
                "labelnames": None,
                "labelname_count": None,
                "ops": None,
                "loadtime_flags": None,
                "field_or_label_slot": None,
                "runtime_flags": None,
                "extra": [],
            },
            "mpc_name_str": None,
            "mpc_fullname_str": None,
            "mpc_ops_ptr": fields.get("mpc_ops"),
            "mpc_ops_sample": ops_sample,
            "alignment_status": None,
            "matched_indices": [],
            "notes": fields.get("note"),
        }
        events.append(event)
    return events


def build_output(
    events: List[Dict],
    runtime_world_id: str,
    os_build: Optional[str],
    kernel_version: Optional[str],
    bootkc_uuid: Optional[str],
    bootkc_hash: Optional[str],
    sandbox_kext_uuid: Optional[str],
    sandbox_kext_hash: Optional[str],
    kaslr_slide: Optional[str],
    sip_config: Optional[str],
    tracing_config: Optional[str],
    static_refs: Dict[str, Optional[str]],
) -> Dict:
    return {
        "runtime_world_id": runtime_world_id,
        "os_build": os_build,
        "kernel_version": kernel_version,
        "bootkc_uuid": bootkc_uuid,
        "bootkc_hash": bootkc_hash,
        "sandbox_kext_uuid": sandbox_kext_uuid,
        "sandbox_kext_hash": sandbox_kext_hash,
        "kaslr_slide": kaslr_slide,
        "sip_config": sip_config,
        "tracing_config": tracing_config,
        "static_reference": static_refs,
        "events": events,
    }


def resolve_default_static_refs(repo_root: pathlib.Path) -> Dict[str, Optional[str]]:
    op_table = repo_root / "book/evidence/graph/mappings/op_table/op_table_signatures.json"
    vocab_ops = repo_root / "book/evidence/graph/mappings/vocab/ops.json"
    vocab_filters = repo_root / "book/evidence/graph/mappings/vocab/filters.json"
    return {
        "op_table_hash": sha256_hex(op_table),
        "vocab_ops_hash": sha256_hex(vocab_ops),
        "vocab_filters_hash": sha256_hex(vocab_filters),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize mac_policy_register DTrace logs.")
    parser.add_argument("--raw", required=True, help="Path to raw DTrace log file.")
    parser.add_argument("--out", required=True, help="Output JSON path.")
    parser.add_argument("--runtime-world-id", required=True, help="Runtime world identifier.")
    parser.add_argument("--os-build", default=None, help="OS build string.")
    parser.add_argument("--kernel-version", default=None, help="Kernel version string.")
    parser.add_argument("--bootkc-uuid", default=None, help="BootKC UUID.")
    parser.add_argument("--bootkc-hash", default=None, help="BootKC hash.")
    parser.add_argument("--sandbox-kext-uuid", default=None, help="Sandbox kext UUID.")
    parser.add_argument("--sandbox-kext-hash", default=None, help="Sandbox kext hash.")
    parser.add_argument("--kaslr-slide", default=None, help="KASLR slide (hex string).")
    parser.add_argument("--sip-config", default=None, help="SIP/AMFI configuration.")
    parser.add_argument("--tracing-config", default=None, help="Tracing configuration details.")
    parser.add_argument(
        "--no-static-ref",
        action="store_true",
        help="Skip computing static reference hashes (use null).",
    )
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    raw_path = path_utils.ensure_absolute(repo_root / args.raw)
    out_path = path_utils.ensure_absolute(repo_root / args.out)

    with raw_path.open() as f:
        events = parse_raw_log(f.readlines())

    static_refs = {"op_table_hash": None, "vocab_ops_hash": None, "vocab_filters_hash": None}
    if not args.no_static_ref:
        static_refs = resolve_default_static_refs(repo_root)

    output = build_output(
        events=events,
        runtime_world_id=args.runtime_world_id,
        os_build=args.os_build,
        kernel_version=args.kernel_version,
        bootkc_uuid=args.bootkc_uuid,
        bootkc_hash=args.bootkc_hash,
        sandbox_kext_uuid=args.sandbox_kext_uuid,
        sandbox_kext_hash=args.sandbox_kext_hash,
        kaslr_slide=args.kaslr_slide,
        sip_config=args.sip_config,
        tracing_config=args.tracing_config,
        static_refs=static_refs,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(output, f, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
