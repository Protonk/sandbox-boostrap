from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT_DIR = Path(__file__).resolve().parent / "out"
OUT_DIR.mkdir(exist_ok=True)

LOCAL_RESULTS = OUT_DIR / "runtime_results.json"
RUNTIME_RESULTS_SRC = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "runtime_results.json"

if LOCAL_RESULTS.exists():
    runtime_results_path = LOCAL_RESULTS
elif RUNTIME_RESULTS_SRC.exists():
    runtime_results_path = RUNTIME_RESULTS_SRC
else:
    raise FileNotFoundError("No runtime_results.json found in local out/ or runtime-adversarial/out/. Run harvest_runtime_artifacts.py after runtime-adversarial.")

with runtime_results_path.open() as f:
    data = json.load(f)

summary = {}
for profile_id, record in data.items():
    for probe in record.get("probes", []):
        op = probe.get("operation")
        op_entry = summary.setdefault(op, {"probes": 0, "matches": 0, "mismatches": 0, "examples": []})
        op_entry["probes"] += 1
        if probe.get("match"):
            op_entry["matches"] += 1
        else:
            op_entry["mismatches"] += 1
            op_entry.setdefault("mismatch_details", []).append({
                "profile": profile_id,
                "expectation_id": probe.get("expectation_id"),
                "expected": probe.get("expected"),
                "actual": probe.get("actual"),
                "path": probe.get("path"),
            })
        if len(op_entry["examples"]) < 5:
            op_entry["examples"].append({
                "profile": profile_id,
                "expectation_id": probe.get("expectation_id"),
                "expected": probe.get("expected"),
                "actual": probe.get("actual"),
                "match": probe.get("match"),
            })

(output_path := OUT_DIR / "op_runtime_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(f"Wrote {output_path}")
