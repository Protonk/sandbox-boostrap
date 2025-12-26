#!/usr/bin/env python3
"""
Generate runtime_callout_oracle.json from normalized runtime IR + adversarial outputs.

This is the sandbox_check oracle lane: seatbelt-callout markers only, kept
separate from syscall outcomes.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils
from book.api.runtime_tools.core import models
from book.api.runtime_tools.core import normalize as runtime_normalize
from book.api.runtime_tools.mapping import views as runtime_views

RUNTIME_IR = ROOT / "book/graph/concepts/validation/out/experiments/runtime-checks/runtime_results.normalized.json"
ADV_EXPECTED = ROOT / "book/experiments/runtime-adversarial/out/expected_matrix.json"
ADV_RESULTS = ROOT / "book/experiments/runtime-adversarial/out/runtime_results.json"
BASELINE = ROOT / "book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json"
OUT = ROOT / "book/graph/mappings/runtime/runtime_callout_oracle.json"


def load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def baseline_world() -> str:
    data = load_json(BASELINE)
    world_id = data.get("world_id")
    if not world_id:
        raise RuntimeError("world_id missing from baseline")
    return world_id


def load_runtime_observations(runtime_ir: Dict[str, Any]) -> List[models.RuntimeObservation]:
    observations: List[models.RuntimeObservation] = []
    for entry in runtime_ir.get("events") or []:
        if not isinstance(entry, dict):
            continue
        try:
            observations.append(models.RuntimeObservation(**entry))
        except TypeError:
            continue
    return observations


def main() -> None:
    if not RUNTIME_IR.exists():
        raise SystemExit(f"missing runtime IR: {RUNTIME_IR}")

    world_id = baseline_world()
    runtime_ir = load_json(RUNTIME_IR)
    observations = load_runtime_observations(runtime_ir)

    adv_present = ADV_EXPECTED.exists() and ADV_RESULTS.exists()
    if adv_present:
        observations.extend(runtime_normalize.normalize_matrix_paths(ADV_EXPECTED, ADV_RESULTS, world_id=world_id))

    doc = runtime_views.build_callout_oracle(observations)

    inputs: List[Path] = [RUNTIME_IR]
    if adv_present:
        inputs.extend([ADV_EXPECTED, ADV_RESULTS])
    input_rel = [path_utils.to_repo_relative(p, ROOT) for p in inputs]
    input_hashes = {path_utils.to_repo_relative(p, ROOT): sha256_path(p) for p in inputs if p.exists()}

    source_jobs = ["experiment:runtime-checks"]
    if adv_present:
        source_jobs.append("experiment:runtime-adversarial")

    meta = doc.get("meta", {})
    meta.update(
        {
            "world_id": world_id,
            "inputs": input_rel,
            "input_hashes": input_hashes,
            "source_jobs": source_jobs,
            "status": meta.get("status", "partial"),
            "notes": "Sandbox_check oracle lane derived from seatbelt-callout markers.",
        }
    )
    if not doc.get("rows"):
        meta["notes"] = meta.get("notes", "") + " No callout markers observed in inputs."
    doc["meta"] = meta

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2, sort_keys=True))
    print(f"[+] wrote {OUT}")


if __name__ == "__main__":
    main()
