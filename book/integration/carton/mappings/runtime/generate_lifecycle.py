#!/usr/bin/env python3
"""
Normalize lifecycle-oriented probe outputs into mapping-grade artifacts and align
them with static expectations.

Inputs (current):
- book/evidence/carton/validation/out/metadata.json
- book/evidence/carton/validation/out/lifecycle/entitlements.json
- book/evidence/carton/validation/out/lifecycle/extensions_dynamic.md (status only)

Outputs:
- book/integration/carton/bundle/relationships/mappings/runtime/lifecycle.json (manifest/status)
- book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_story.json (expected vs observed per scenario)
- book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_coverage.json (status + mismatch summaries)
- book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_traces/*.jsonl (per-scenario normalized rows)
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, asdict
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional


REPO_ROOT = Path(__file__).resolve().parents[5]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import world as world_mod  # noqa: E402

OUT_MANIFEST = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle.json"
OUT_STORY = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_story.json"
OUT_COVERAGE = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_coverage.json"
OUT_TRACES = REPO_ROOT / "book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_traces"
ENTITLEMENTS_PATH = REPO_ROOT / "book/evidence/carton/validation/out/lifecycle/entitlements.json"
EXTENSIONS_PATH = REPO_ROOT / "book/evidence/carton/validation/out/lifecycle/extensions_dynamic.md"


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def sha256_path(path: Path) -> str:
    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_baseline_world() -> tuple[str, str]:
    data, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    world_id = world_mod.require_world_id(data, world_path=resolution.entry.world_path)
    world_path = world_mod.world_path_for_metadata(resolution, repo_root=REPO_ROOT)
    return world_id, world_path


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


def normalize_entitlements(meta: Dict[str, Any]) -> (Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]):
    if not ENTITLEMENTS_PATH.exists():
        return status_entry("entitlements-evolution", "blocked", "missing entitlements.json", [], None), [], {}
    ent = load_json(ENTITLEMENTS_PATH)
    expected_present = True  # static expectation: signed payloads should expose entitlements
    observed_present = ent.get("entitlements_present")
    classification = "missing" if observed_present is None else ("present_ok" if observed_present == expected_present else "mismatch_disallowed")
    mismatches = []
    if classification != "present_ok":
        mismatches.append(
            {
                "expectation_id": "entitlements-evolution:present",
                "expected": expected_present,
                "actual": observed_present,
                "tags": ["missing_entitlements"],
            }
        )
    rows = [
        {
            "scenario_id": "entitlements-evolution",
            "executable": ent.get("executable"),
            "signing_identifier": ent.get("signing_identifier"),
            "entitlements_present": ent.get("entitlements_present"),
            "notes": ent.get("notes"),
            "source_log": str(ENTITLEMENTS_PATH.relative_to(REPO_ROOT)),
        }
    ]
    trace_rel = f"book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_traces/entitlements-evolution.jsonl"
    write_trace(REPO_ROOT / trace_rel, rows)
    status = "ok" if classification == "present_ok" else "partial"
    return status_entry(
        "entitlements-evolution", status, ent.get("notes") or "", [trace_rel], str(ENTITLEMENTS_PATH.relative_to(REPO_ROOT))
    ), rows, {
        "scenario_id": "entitlements-evolution",
        "kind": "entitlements",
        "expected": {"entitlements_present": expected_present},
        "observed": {"entitlements_present": observed_present},
        "classification": classification,
        "mismatches": mismatches,
        "static_ref": str(ENTITLEMENTS_PATH.relative_to(REPO_ROOT)),
    }


def normalize_extensions(meta: Dict[str, Any]) -> (Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]):
    if not EXTENSIONS_PATH.exists():
        return status_entry("extensions-dynamic", "blocked", "missing extensions_dynamic.md", [], None), [], {}
    raw = EXTENSIONS_PATH.read_text()
    notes = raw.strip().splitlines()
    expected_token = True
    # Current probe notes include a stable `token_issued=<bool>` marker in the
    # header; parse it conservatively.
    observed_token = "token_issued=true" in raw
    classification = "issued_ok" if observed_token else "mismatch_disallowed"
    mismatches = []
    if observed_token != expected_token:
        mismatches = [
            {
                "expectation_id": "extensions-dynamic:token",
                "expected": expected_token,
                "actual": observed_token,
                "tags": ["extension_failure"],
            }
        ]
    row = {
        "scenario_id": "extensions-dynamic",
        "status": "ok" if observed_token else "blocked",
        "notes": "\n".join(notes[:6]),
        "source_log": str(EXTENSIONS_PATH.relative_to(REPO_ROOT)),
    }
    trace_rel = f"book/integration/carton/bundle/relationships/mappings/runtime/lifecycle_traces/extensions-dynamic.jsonl"
    write_trace(REPO_ROOT / trace_rel, [row])
    return status_entry(
        "extensions-dynamic",
        "ok" if observed_token else "blocked",
        "extensions token not issued (see source_log)" if not observed_token else "extensions token issued (see source_log)",
        [trace_rel],
        str(EXTENSIONS_PATH.relative_to(REPO_ROOT)),
    ), [row], {
        "scenario_id": "extensions-dynamic",
        "kind": "extensions",
        "expected": {"token_issued": expected_token},
        "observed": {"token_issued": observed_token},
        "classification": classification,
        "mismatches": mismatches,
        "static_ref": str(EXTENSIONS_PATH.relative_to(REPO_ROOT)),
        "notes": row["notes"],
    }


def main() -> None:
    world_id, world_path = load_baseline_world()
    meta = load_json(REPO_ROOT / "book/evidence/carton/validation/out/metadata.json")
    manifest = {
        "world_id": world_id,
        "sip_status": meta.get("sip_status"),
        "profile_format_variant": meta.get("profile_format_variant"),
        "scenarios": [],
    }

    ent_status, _, ent_story = normalize_entitlements(meta)
    ext_status, _, ext_story = normalize_extensions(meta)

    manifest["scenarios"].extend([ent_status, ext_status])

    inputs = [
        str(ENTITLEMENTS_PATH.relative_to(REPO_ROOT)),
        str(EXTENSIONS_PATH.relative_to(REPO_ROOT)),
        "book/evidence/carton/validation/out/metadata.json",
        world_path,
    ]
    overall_status = "partial" if any(s.get("status") != "ok" for s in manifest["scenarios"]) else "ok"
    manifest["metadata"] = {
        "world_id": world_id,
        "inputs": inputs,
        "input_hashes": {
            str(ENTITLEMENTS_PATH.relative_to(REPO_ROOT)): sha256_path(ENTITLEMENTS_PATH),
            str(EXTENSIONS_PATH.relative_to(REPO_ROOT)): sha256_path(EXTENSIONS_PATH),
        },
        "status": overall_status,
        "notes": "Lifecycle probes normalized; blocked/partial scenarios retained with source logs.",
    }

    # Story (expected vs observed)
    story_scenarios = {s["scenario_id"]: s for s in (ent_story, ext_story) if s.get("scenario_id")}
    story = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "input_hashes": manifest["metadata"]["input_hashes"],
            "status": manifest["metadata"]["status"],
            "notes": "Lifecycle story derived from validation outputs; expected vs observed per scenario.",
        },
        "scenarios": story_scenarios,
    }

    # Coverage: per-scenario status + mismatch summaries
    coverage_entries = {}
    disallowed = []
    tag_counts = {}
    for scenario in story["scenarios"].values():
        mismatches = scenario.get("mismatches") or []
        tag_bucket = {}
        for m in mismatches:
            for tag in m.get("tags") or []:
                tag_bucket[tag] = tag_bucket.get(tag, 0) + 1
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        status = "ok" if scenario.get("classification") == "present_ok" else "partial"
        if status != "ok":
            disallowed.extend(mismatches)
        coverage_entries[scenario["scenario_id"]] = {
            "scenario_id": scenario["scenario_id"],
            "kind": scenario.get("kind"),
            "status": status,
            "classification": scenario.get("classification"),
            "mismatches": mismatches,
            "mismatch_summary": {
                "total_mismatches": len(mismatches),
                "tags": tag_bucket,
            },
            "static_ref": scenario.get("static_ref"),
        }

    coverage_status = "ok" if not disallowed else "partial"
    coverage = {
        "metadata": {
            "world_id": world_id,
            "inputs": inputs,
            "input_hashes": manifest["metadata"]["input_hashes"],
            "status": coverage_status,
            "notes": "Lifecycle coverage derived from lifecycle_story; mismatches are not currently gated.",
            "mismatch_summary": {
                "total_mismatches": sum((len(s.get("mismatches") or []) for s in story["scenarios"].values())),
                "total_disallowed_mismatches": len(disallowed),
                "tags": tag_counts,
            },
        },
        "coverage": coverage_entries,
    }

    OUT_TRACES.mkdir(parents=True, exist_ok=True)
    OUT_MANIFEST.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    OUT_STORY.write_text(json.dumps(story, indent=2, sort_keys=True))
    OUT_COVERAGE.write_text(json.dumps(coverage, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT_MANIFEST}")
    print(f"[+] wrote {OUT_STORY}")
    print(f"[+] wrote {OUT_COVERAGE}")


if __name__ == "__main__":
    main()
