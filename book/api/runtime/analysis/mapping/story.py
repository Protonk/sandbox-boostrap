"""
Joined runtime story helpers.

Builds a per-op runtime view that joins the canonical op mapping with scenario
summaries and light static vocab context. Also provides small adapters that
emit legacy views (runtime signatures, coverage) for consumers that still
expect the older shapes.

Story views are for humans. They explain how observations line up
with the static vocab without asserting new semantics.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from book.api import path_utils
from book.api.runtime.contracts import models
from book.api.runtime.analysis.mapping import build as mapping_build

REPO_ROOT = path_utils.find_repo_root(Path(__file__))
OPS_VOCAB = REPO_ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "vocab" / "ops.json"


def _load_json(path: Path) -> Dict[str, Any]:
    path = path_utils.ensure_absolute(path, REPO_ROOT)
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_vocab(path: Path = OPS_VOCAB) -> Dict[str, Dict[str, Any]]:
    doc = _load_json(path)
    vocab = {}
    for entry in doc.get("ops", []) or []:
        name = entry.get("name")
        if name:
            vocab[name] = entry
    return vocab


def build_story(
    op_mapping_path: Path | str,
    scenario_mapping_path: Path | str,
    vocab_path: Path | str = OPS_VOCAB,
    world_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Join op-level runtime mapping with scenario summaries and vocab context.
    """

    op_doc = _load_json(Path(op_mapping_path))
    scenario_doc = _load_json(Path(scenario_mapping_path))
    vocab = _load_vocab(path_utils.ensure_absolute(Path(vocab_path), REPO_ROOT))

    resolved_world = (
        world_id
        or (op_doc.get("meta") or {}).get("world_id")
        or (scenario_doc.get("meta") or {}).get("world_id")
    )

    scenarios = scenario_doc.get("scenarios") or {}
    story_ops: Dict[str, Dict[str, Any]] = {}

    for op_name, body in (op_doc.get("ops") or {}).items():
        vocab_entry = vocab.get(op_name) or {}
        op_id = body.get("op_id") or vocab_entry.get("id")
        scenario_entries = []
        for scenario_id in body.get("scenarios") or []:
            scenario_body = scenarios.get(scenario_id) or {}
            scenario_entries.append(
                {
                    "scenario_id": scenario_id,
                    "profile_id": scenario_body.get("profile_id"),
                    "status": (scenario_body.get("results") or {}).get("status"),
                    "results": scenario_body.get("results") or {},
                    "expectations": scenario_body.get("expectations") or [],
                    "mismatches": scenario_body.get("mismatches") or [],
                }
            )
        # Use op_id when available to keep story keys stable across renames.
        key = str(op_id) if op_id is not None else op_name
        story_ops[key] = {
            "op_id": op_id,
            "op_name": op_name,
            "coverage_status": body.get("coverage_status"),
            "probes": body.get("probes"),
            "matches": body.get("matches"),
            "mismatches": body.get("mismatches"),
            "examples": body.get("examples") or [],
            "scenarios": scenario_entries,
            "static": {"vocab_entry": vocab_entry},
        }

    meta = mapping_build.mapping_metadata(
        resolved_world or models.WORLD_ID,
        notes="joined runtime story",
    )
    return {"meta": meta, "ops": story_ops}


def write_story(doc: Mapping[str, Any], out_path: Path | str) -> Path:
    """Write the runtime story document and return its path."""
    out_path = path_utils.ensure_absolute(Path(out_path), REPO_ROOT)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(doc, indent=2))
    return out_path


def story_to_signatures(story_doc: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Emit a legacy-ish runtime_signatures view from a runtime story.
    Each scenario becomes a signature id keyed by scenario_id.
    """

    signatures: Dict[str, Any] = {}
    ops = story_doc.get("ops") or {}
    for entry in ops.values():
        op_name = entry.get("op_name")
        op_id = entry.get("op_id")
        for scenario in entry.get("scenarios") or []:
            sid = scenario.get("scenario_id")
            if not sid:
                continue
            mismatch_by_eid = {m.get("expectation_id"): m for m in scenario.get("mismatches") or [] if m.get("expectation_id")}
            probes = []
            for expect in scenario.get("expectations") or []:
                eid = expect.get("expectation_id")
                mismatch = mismatch_by_eid.get(eid) or {}
                probes.append(
                    {
                        "expectation_id": eid,
                        "operation": expect.get("operation"),
                        "target": expect.get("target"),
                        "expected": expect.get("expected"),
                        "actual": mismatch.get("actual", expect.get("expected")),
                        "match": not bool(mismatch),
                    }
                )
            signatures[sid] = {
                "signature_id": sid,
                "profile": scenario.get("profile_id"),
                "operation": op_name,
                "op_id": op_id,
                "probes": probes,
            }

    meta = {
        "world_id": (story_doc.get("meta") or {}).get("world_id"),
        "source": "runtime_story",
        "status": (story_doc.get("meta") or {}).get("status", "partial"),
    }
    return {"metadata": meta, "signatures": signatures}


def story_to_coverage(story_doc: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Emit a lightweight operation coverage view (runtime only) from a runtime story.
    """

    coverage: Dict[str, Any] = {}
    ops = story_doc.get("ops") or {}
    for entry in ops.values():
        op_name = entry.get("op_name")
        scenarios = [s.get("scenario_id") for s in entry.get("scenarios") or [] if s.get("scenario_id")]
        coverage[op_name] = {
            "op_id": entry.get("op_id"),
            "runtime_signatures": scenarios,
            "counts": {"runtime_signatures": len(scenarios)},
            "coverage_status": entry.get("coverage_status"),
        }
    meta = {
        "world_id": (story_doc.get("meta") or {}).get("world_id"),
        "status": (story_doc.get("meta") or {}).get("status", "partial"),
        "source": "runtime_story",
    }
    return {"metadata": meta, "coverage": coverage}
