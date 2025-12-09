from __future__ import annotations
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
RUNTIME_RESULTS = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "runtime_results.json"
OUT_DIR = Path(__file__).resolve().parent / "out"
OUT_DIR.mkdir(exist_ok=True)

with RUNTIME_RESULTS.open() as f:
    results = json.load(f)

pairs = [
    ("adv:struct_flat", "adv:struct_nested", "structural variants of same intent (read/write)"),
    ("adv:mach_simple_allow", "adv:mach_simple_variants", "mach global-name literal vs regex variants"),
    ("adv:mach_local_literal", "adv:mach_local_regex", "mach local-name literal vs regex variants"),
]

summary = {}
for a, b, label in pairs:
    ra = results.get(a)
    rb = results.get(b)
    if not ra or not rb:
        summary[label] = {"status": "missing", "details": f"missing results for {a} or {b}"}
        continue

    mismatches = []
    def key(probe: dict) -> str:
        exp_id = probe.get("expectation_id", "")
        # Strip leading profile prefix (adv:profile:) to align similar probes across variants
        parts = exp_id.split(":")
        return parts[-1] if parts else exp_id

    probes_a = {key(p): p for p in ra.get("probes", [])}
    probes_b = {key(p): p for p in rb.get("probes", [])}

    common = set(probes_a) & set(probes_b)
    aligned = []
    for exp_id in sorted(common):
        pa = probes_a[exp_id]
        pb = probes_b[exp_id]
        same = (pa.get("actual") == pb.get("actual") == pa.get("expected") == pb.get("expected")) and pa.get("match") and pb.get("match")
        aligned.append({
            "expectation_id": exp_id,
            "profile_a": a,
            "profile_b": b,
            "expected": pa.get("expected"),
            "actual_a": pa.get("actual"),
            "actual_b": pb.get("actual"),
            "both_match": same,
        })
        if not same:
            mismatches.append(exp_id)

    summary[label] = {
        "profiles": [a, b],
        "aligned_expectations": aligned,
        "mismatches": mismatches,
    }

# Include known divergence case
path_edges = results.get("adv:path_edges")
if path_edges:
    summary["path_edges"] = {
        "profiles": ["adv:path_edges"],
        "mismatches": [p for p in path_edges.get("probes", []) if not p.get("match")],
        "note": "expected allow on /tmp variants denied (VFS canonicalization likely)",
    }

(output_path := OUT_DIR / "graph_shape_semantics_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
print(f"Wrote {output_path}")
