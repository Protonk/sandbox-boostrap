"""
Lightweight validation job: check that observed tags in the canonical corpus
have declared u16 roles and layouts, summarize vocab resolution vs misses, and
record fallback usage. Strictness is scoped to the Sonoma canonical corpus only
(system profiles + blessed samples) and stays out of the decoder path.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Any

from book.api.profile import decoder
from book.api.profile import digests as digests_mod
from book.api.path_utils import find_repo_root, to_repo_relative
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
TAG_LAYOUTS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json"
TAG_U16_ROLES_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/tag_layouts/tag_u16_roles.json"
FILTERS_PATH = ROOT / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json"
META_PATH = ROOT / "book/evidence/graph/concepts/validation/out/metadata.json"
STATUS_PATH = ROOT / "book/evidence/graph/concepts/validation/out/tag_roles/status.json"
IR_PATH = ROOT / "book/evidence/graph/concepts/validation/out/tag_roles/ir.json"

# Canonical corpus for this host.
_CANONICAL = digests_mod.canonical_system_profile_blobs(ROOT)
CANONICAL_BLOBS = [
    ("sys:airlock", _CANONICAL["airlock"]),
    ("sys:bsd", _CANONICAL["bsd"]),
    ("sample", _CANONICAL["sample"]),
]


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def _load_tag_layout_tags() -> set[int]:
    if not TAG_LAYOUTS_PATH.exists():
        return set()
    data = load_json(TAG_LAYOUTS_PATH)
    tags = set()
    for entry in data.get("tags", []):
        try:
            tags.add(int(entry["tag"]))
        except Exception:
            continue
    return tags


def _load_tag_roles() -> Dict[int, str]:
    if not TAG_U16_ROLES_PATH.exists():
        return {}
    data = load_json(TAG_U16_ROLES_PATH)
    roles: Dict[int, str] = {}
    for entry in data.get("roles", []):
        try:
            roles[int(entry["tag"])] = str(entry["u16_role"])
        except Exception:
            continue
    return roles


@dataclass
class ProfileSummary:
    name: str
    tags_seen: Dict[int, int]
    missing_roles: List[int]
    missing_layouts: List[int]
    vocab_hits: int
    vocab_misses: int
    fallback_nodes: int


def run_tag_role_layout_job():
    for required in [TAG_LAYOUTS_PATH, TAG_U16_ROLES_PATH, FILTERS_PATH]:
        if not required.exists():
            raise FileNotFoundError(f"missing required input: {required}")

    layouts = _load_tag_layout_tags()
    roles = _load_tag_roles()
    meta = load_json(META_PATH) if META_PATH.exists() else {}

    summaries: List[ProfileSummary] = []
    missing_roles_total = 0
    missing_layout_total = 0
    fallback_total = 0
    vocab_hits_total = 0
    vocab_misses_total = 0

    for name, path in CANONICAL_BLOBS:
        if not path.exists():
            raise FileNotFoundError(f"missing canonical blob: {path}")
        dec = decoder.decode_profile(path.read_bytes())
        tags_seen: Dict[int, int] = {int(k): v for k, v in dec.tag_counts.items()}
        missing_roles = sorted(t for t in tags_seen if t not in roles)
        missing_layouts = sorted(
            t for t in tags_seen if roles.get(t) not in ("none/meta", "blocked", None) and t not in layouts
        )
        vocab_hits = 0
        vocab_misses = 0
        fallback_nodes = 0
        for node in dec.nodes:
            provenance = node.get("layout_provenance")
            if provenance and provenance != "mapping":
                fallback_nodes += 1
            if node.get("u16_role") == "filter_vocab_id":
                if node.get("filter_out_of_vocab"):
                    vocab_misses += 1
                else:
                    vocab_hits += 1
        summaries.append(
            ProfileSummary(
                name=name,
                tags_seen=tags_seen,
                missing_roles=missing_roles,
                missing_layouts=missing_layouts,
                vocab_hits=vocab_hits,
                vocab_misses=vocab_misses,
                fallback_nodes=fallback_nodes,
            )
        )
        missing_roles_total += len(missing_roles)
        missing_layout_total += len(missing_layouts)
        fallback_total += fallback_nodes
        vocab_hits_total += vocab_hits
        vocab_misses_total += vocab_misses

    IR_PATH.parent.mkdir(parents=True, exist_ok=True)
    summaries_dict = [
        {
            "profile": s.name,
            "tags_seen": s.tags_seen,
            "missing_roles": s.missing_roles,
            "missing_layouts": s.missing_layouts,
            "vocab_hits": s.vocab_hits,
            "vocab_misses": s.vocab_misses,
            "fallback_nodes": s.fallback_nodes,
        }
        for s in summaries
    ]
    ir = {
        "host": meta.get("os", {}),
        "profiles": summaries_dict,
        "inputs": [rel(TAG_LAYOUTS_PATH), rel(TAG_U16_ROLES_PATH)],
    }
    IR_PATH.write_text(json.dumps(ir, indent=2))

    status_payload = {
        "job_id": "structure:tag_roles",
        "status": "ok" if (missing_roles_total == 0 and missing_layout_total == 0) else "partial",
        "tier": "mapped",
        "host": meta.get("os", {}),
        "inputs": [rel(p) for _, p in CANONICAL_BLOBS] + [rel(TAG_LAYOUTS_PATH), rel(TAG_U16_ROLES_PATH)],
        "outputs": [rel(IR_PATH)],
        "metrics": {
            "profiles": len(CANONICAL_BLOBS),
            "missing_roles_total": missing_roles_total,
            "missing_layout_total": missing_layout_total,
            "fallback_nodes_total": fallback_total,
            "vocab_hits_total": vocab_hits_total,
            "vocab_misses_total": vocab_misses_total,
        },
        "notes": "Checked tag roles/layout coverage and vocab resolution on the Sonoma canonical corpus without enforcing hard bounds in the decoder.",
        "tags": ["structure", "tag", "layout", "role", "smoke"],
    }
    STATUS_PATH.write_text(json.dumps(status_payload, indent=2))
    return {
        "status": status_payload["status"],
        "tier": "mapped",
        "metrics": status_payload["metrics"],
        "outputs": status_payload["outputs"] + [rel(STATUS_PATH)],
    }


registry.register(
    ValidationJob(
        id="structure:tag_roles",
        inputs=[rel(p) for _, p in CANONICAL_BLOBS] + [rel(TAG_LAYOUTS_PATH), rel(TAG_U16_ROLES_PATH)],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["structure", "tag", "layout", "role", "smoke"],
        description="Check tag roles/layout coverage and vocab resolution on the Sonoma canonical corpus.",
        example_command="python -m book.graph.concepts.validation --job structure:tag_roles",
        runner=run_tag_role_layout_job,
    )
)
