#!/usr/bin/env python3
"""
Normalize lifecycle-oriented probe outputs into mapping-grade artifacts.

Inputs (current):
- book/graph/concepts/validation/out/metadata.json
- book/graph/concepts/validation/out/lifecycle/entitlements.json
- book/graph/concepts/validation/out/lifecycle/extensions_dynamic.md (status only)

Outputs:
- book/graph/mappings/runtime/lifecycle.json (manifest)
- book/graph/mappings/runtime/lifecycle_traces/*.jsonl (per-scenario normalized rows)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[4]
OUT_MANIFEST = REPO_ROOT / "book/graph/mappings/runtime/lifecycle.json"
OUT_TRACES = REPO_ROOT / "book/graph/mappings/runtime/lifecycle_traces"
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE_PATH = REPO_ROOT / BASELINE_REF


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def load_baseline_world() -> str:
    if not BASELINE_PATH.exists():
        raise FileNotFoundError(f"missing baseline: {BASELINE_PATH}")
    data = json.loads(BASELINE_PATH.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def status_entry(scenario_id: str, status: str, notes: str, traces: List[str], source_log: Optional[str]) -> Dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "status": status,
        "notes": notes,
        "trace_path": traces[0] if traces else None,
        "trace_count": len(traces),
        "source_log": source_log,
    }


def write_trace(path: Path, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = "\n".join(json.dumps(r, sort_keys=True) for r in rows)
    path.write_text(lines + "\n")


def normalize_entitlements(meta: Dict[str, Any]) -> (Dict[str, Any], List[Dict[str, Any]]):
    ent_path = REPO_ROOT / "book/graph/concepts/validation/out/lifecycle/entitlements.json"
    if not ent_path.exists():
        return status_entry("entitlements-evolution", "blocked", "missing entitlements.json", [], None), []
    ent = load_json(ent_path)
    rows = [
        {
            "scenario_id": "entitlements-evolution",
            "executable": ent.get("executable"),
            "signing_identifier": ent.get("signing_identifier"),
            "entitlements_present": ent.get("entitlements_present"),
            "notes": ent.get("notes"),
            "source_log": str(ent_path.relative_to(REPO_ROOT)),
        }
    ]
    trace_rel = f"book/graph/mappings/runtime/lifecycle_traces/entitlements-evolution.jsonl"
    write_trace(REPO_ROOT / trace_rel, rows)
    status = "partial" if not ent.get("entitlements_present") else "ok"
    return status_entry("entitlements-evolution", status, ent.get("notes") or "", [trace_rel], str(ent_path.relative_to(REPO_ROOT))), rows


def normalize_extensions(meta: Dict[str, Any]) -> (Dict[str, Any], List[Dict[str, Any]]):
    md_path = REPO_ROOT / "book/graph/concepts/validation/out/lifecycle/extensions_dynamic.md"
    if not md_path.exists():
        return status_entry("extensions-dynamic", "blocked", "missing extensions_dynamic.md", [], None), []
    notes = md_path.read_text().strip().splitlines()
    row = {
        "scenario_id": "extensions-dynamic",
        "status": "blocked",
        "notes": "\n".join(notes[:6]),
        "source_log": str(md_path.relative_to(REPO_ROOT)),
    }
    trace_rel = f"book/graph/mappings/runtime/lifecycle_traces/extensions-dynamic.jsonl"
    write_trace(REPO_ROOT / trace_rel, [row])
    return status_entry("extensions-dynamic", "blocked", "extensions demo crashes / NULL tokens (see source_log)", [trace_rel], str(md_path.relative_to(REPO_ROOT))), [row]


def main() -> None:
    world_id = load_baseline_world()
    meta = load_json(REPO_ROOT / "book/graph/concepts/validation/out/metadata.json")
    manifest = {
        "world_id": world_id,
        "sip_status": meta.get("sip_status"),
        "profile_format_variant": meta.get("profile_format_variant"),
        "scenarios": [],
    }

    ent_status, _ = normalize_entitlements(meta)
    ext_status, _ = normalize_extensions(meta)

    manifest["scenarios"].extend([ent_status, ext_status])

    OUT_TRACES.mkdir(parents=True, exist_ok=True)
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_MANIFEST}")


if __name__ == "__main__":
    main()
