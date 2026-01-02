#!/usr/bin/env python3
"""
Generate ops_coverage.json summarizing structural/runtime evidence per operation.

Structural evidence is implied by presence in ops.json (harvested vocab).
Runtime evidence is set when an operation appears in expected matrices from runtime-checks,
runtime-adversarial, or golden-triple profiles.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Set
import sys

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import evidence_tiers  # noqa: E402
from book.api import world as world_mod  # noqa: E402

OPS_JSON = REPO_ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"
OUT_JSON = REPO_ROOT / "book" / "graph" / "mappings" / "vocab" / "ops_coverage.json"
RUNTIME_COVERAGE = REPO_ROOT / "book" / "graph" / "mappings" / "runtime" / "runtime_coverage.json"

RUNTIME_MATRICES = [
    REPO_ROOT
    / "book"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "runtime-checks"
    / "out"
    / "expected_matrix.json",
    REPO_ROOT
    / "book"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "runtime-adversarial"
    / "out"
    / "expected_matrix.json",
    REPO_ROOT / "book" / "profiles" / "golden-triple" / "expected_matrix.json",
]


def load_runtime_ops() -> Set[str]:
    if RUNTIME_COVERAGE.exists():
        data = json.loads(RUNTIME_COVERAGE.read_text())
        coverage = data.get("coverage") or {}
        return {name for name, entry in coverage.items() if (entry.get("counts") or {}).get("runtime_signatures")}

    ops: Set[str] = set()
    for path in RUNTIME_MATRICES:
        if not path.exists():
            continue
        data = json.loads(path.read_text())
        for prof in (data.get("profiles") or {}).values():
            for probe in prof.get("probes") or []:
                op = probe.get("operation")
                if op:
                    ops.add(op)
    return ops


def load_world_id(vocab: Dict[str, object]) -> str:
    world_id = (vocab.get("metadata") or {}).get("world_id")
    if world_id:
        return world_id
    world_doc, resolution = world_mod.load_world(repo_root=REPO_ROOT)
    return world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)


def main() -> int:
    assert OPS_JSON.exists(), f"missing ops.json at {OPS_JSON}"
    vocab = json.loads(OPS_JSON.read_text())
    ops_list = vocab.get("ops") or []
    runtime_ops = load_runtime_ops()
    world_id = load_world_id(vocab)

    coverage: Dict[str, Dict[str, object]] = {}
    for entry in ops_list:
        name = entry["name"]
        op_id = entry["id"]
        coverage[name] = {
            "id": op_id,
            "structural_evidence": True,
            "runtime_evidence": name in runtime_ops,
            "notes": "",
        }

    inputs = [str(OPS_JSON.relative_to(REPO_ROOT))]
    if RUNTIME_COVERAGE.exists():
        inputs.append(str(RUNTIME_COVERAGE.relative_to(REPO_ROOT)))
    for path in RUNTIME_MATRICES:
        inputs.append(str(path.relative_to(REPO_ROOT)))

    OUT_JSON.write_text(
        json.dumps(
            {
                "metadata": {
                    "world_id": world_id,
                    "inputs": inputs,
                    "status": "ok",
                    "tier": evidence_tiers.evidence_tier_for_artifact(
                        path=OUT_JSON,
                    ),
                    "source_jobs": [
                        "vocab:sonoma-14.4.1",
                        "experiment:runtime-checks",
                        "experiment:runtime-adversarial",
                        "profiles:golden-triple",
                    ],
                    "notes": "Runtime evidence is derived from runtime coverage when present, else from expected matrices; structural evidence is implied by vocab presence.",
                },
                "coverage": coverage,
            },
            indent=2,
        )
    )
    print(f"[+] wrote {OUT_JSON} (runtime_ops={sorted(runtime_ops)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
