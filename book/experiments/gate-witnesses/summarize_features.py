#!/usr/bin/env python3
"""
Summarize minimized apply-gate witnesses into a derived-only feature view.

This is not a semantic tool: it is a structural diff/projection over the
checked-in witness SBPL pairs under out/witnesses/.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.runtime import events as runtime_events  # type: ignore


TOOL_PATH = ROOT / "book" / "tools" / "preflight" / "gate_minimizer.py"
OUT_ROOT = ROOT / "book" / "experiments" / "gate-witnesses" / "out"
WITNESS_ROOT = OUT_ROOT / "witnesses"


def _load_gate_minimizer_module():
    spec = importlib.util.spec_from_file_location("gate_minimizer", TOOL_PATH)
    if not spec or not spec.loader:
        raise RuntimeError(f"failed to load gate_minimizer module spec: {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def _is_string_atom(atom_value: str) -> bool:
    return atom_value.startswith('"') and atom_value.endswith('"')


def _extract_features(mod, sbpl_text: str) -> Dict[str, Any]:
    forms = mod.parse_sbpl(sbpl_text)
    ops: Set[str] = set()
    list_operators: Set[str] = set()
    string_literals: Set[str] = set()

    def walk(expr):
        if isinstance(expr, mod.Atom):
            if _is_string_atom(expr.value):
                string_literals.add(expr.value)
            return
        if isinstance(expr, mod.ListExpr):
            op = mod._list_operator(expr)
            if op:
                list_operators.add(op)
                if op in {"allow", "deny"} and len(expr.items) >= 2 and isinstance(expr.items[1], mod.Atom):
                    ops.add(expr.items[1].value)
            for child in expr.items:
                walk(child)

    for form in forms:
        walk(form)

    return {
        "ops": sorted(ops),
        "list_operators": sorted(list_operators),
        "string_literals": sorted(string_literals),
        "string_literal_count": len(string_literals),
    }


def _signature(features: Dict[str, Any]) -> str:
    payload = json.dumps(
        {"ops": features.get("ops", []), "list_operators": features.get("list_operators", [])},
        sort_keys=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def main() -> int:
    mod = _load_gate_minimizer_module()
    if not WITNESS_ROOT.exists():
        raise SystemExit(f"missing witness root: {WITNESS_ROOT}")

    witnesses: List[Dict[str, Any]] = []

    for dirpath in sorted(p for p in WITNESS_ROOT.iterdir() if p.is_dir()):
        failing_path = dirpath / "minimal_failing.sb"
        neighbor_path = dirpath / "passing_neighbor.sb"
        run_path = dirpath / "run.json"
        if not failing_path.exists() or not neighbor_path.exists() or not run_path.exists():
            continue

        failing_text = failing_path.read_text(encoding="utf-8")
        neighbor_text = neighbor_path.read_text(encoding="utf-8")
        run_doc = json.loads(run_path.read_text(encoding="utf-8"))

        failing = _extract_features(mod, failing_text)
        neighbor = _extract_features(mod, neighbor_text)

        delta_ops = sorted(set(failing["ops"]) - set(neighbor["ops"]))
        delta_operators = sorted(set(failing["list_operators"]) - set(neighbor["list_operators"]))
        delta_literals = sorted(set(failing["string_literals"]) - set(neighbor["string_literals"]))

        witnesses.append(
            {
                "target": dirpath.name,
                "input": run_doc.get("input"),
                "input_sha256": run_doc.get("input_sha256"),
                "minimal_failing": failing,
                "passing_neighbor": neighbor,
                "delta": {
                    "ops": delta_ops,
                    "list_operators": delta_operators,
                    "string_literals": delta_literals,
                },
                "confirm": run_doc.get("confirm"),
                "signature": _signature({"ops": delta_ops, "list_operators": delta_operators}),
            }
        )

    clusters: Dict[str, List[str]] = {}
    for w in witnesses:
        clusters.setdefault(w["signature"], []).append(w["target"])

    feature_summary = {
        "world_id": runtime_events.WORLD_ID,
        "witnesses": witnesses,
    }
    clusters_doc = {
        "world_id": runtime_events.WORLD_ID,
        "clusters": [{"signature": sig, "targets": sorted(targets)} for sig, targets in sorted(clusters.items())],
    }

    OUT_ROOT.mkdir(parents=True, exist_ok=True)
    (OUT_ROOT / "feature_summary.json").write_text(json.dumps(feature_summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (OUT_ROOT / "clusters.json").write_text(json.dumps(clusters_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] wrote {OUT_ROOT / 'feature_summary.json'}")
    print(f"[+] wrote {OUT_ROOT / 'clusters.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
