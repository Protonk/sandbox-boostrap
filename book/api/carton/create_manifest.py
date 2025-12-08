#!/usr/bin/env python3
"""
Create the CARTON manifest for Sonoma 14.4.1.

Outputs:
- book/api/carton/CARTON.json
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List, Dict

ROOT = Path(__file__).resolve().parents[3]
BASELINE_REF = "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
BASELINE = ROOT / BASELINE_REF

FILES = [
    "book/graph/mappings/vocab/ops.json",
    "book/graph/mappings/vocab/filters.json",
    "book/graph/mappings/runtime/runtime_signatures.json",
    "book/graph/mappings/system_profiles/digests.json",
    "book/graph/mappings/carton/operation_coverage.json",
    "book/graph/mappings/carton/operation_index.json",
    "book/graph/mappings/carton/profile_layer_index.json",
    "book/graph/mappings/carton/filter_index.json",
    "book/graph/mappings/carton/concept_index.json",
    "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json",
    "book/graph/concepts/validation/out/experiments/field2/field2_ir.json",
    "book/graph/concepts/validation/out/experiments/system-profile-digest/digests_ir.json",
    "book/graph/concepts/validation/out/vocab_status.json",
    "book/graph/concepts/validation/out/validation_status.json",
]

OUT_PATH = ROOT / "book/api/carton/CARTON.json"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_baseline() -> Dict[str, str]:
    if not BASELINE.exists():
        raise SystemExit(f"missing baseline: {BASELINE}")
    data = json.loads(BASELINE.read_text())
    world_id = data.get("world_id")
    if not world_id:
        raise SystemExit("world_id missing from baseline")
    return {"host": BASELINE_REF, "world_id": world_id}


def main() -> None:
    baseline = load_baseline()
    rows: List[Dict[str, str]] = []
    for rel in FILES:
        p = ROOT / rel
        rows.append({"path": rel, "sha256": sha256(p)})

    manifest = {
        "name": "CARTON",
        "world_id": baseline["world_id"],
        "files": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(manifest, indent=2))
    print(f"[+] wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
