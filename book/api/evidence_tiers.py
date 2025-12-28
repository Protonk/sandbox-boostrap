"""
Evidence tier adapters for the repo-wide tiering overhaul.

Phase 3 makes the canonical 3-tier vocabulary mandatory:
- bedrock
- mapped
- hypothesis

The legacy tier/status vocabulary (ok/partial/brittle/blocked/...) must not be
used as evidence tiering. It may still exist as an operational/health signal in
artifacts, but consumers must key on `tier`.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Set

from book.api.path_utils import find_repo_root, to_repo_relative

EvidenceTier = Literal["bedrock", "mapped", "hypothesis"]

EVIDENCE_TIERS: tuple[EvidenceTier, ...] = ("bedrock", "mapped", "hypothesis")
LEGACY_TIER_TERMS: tuple[str, ...] = (
    "mapped-but-partial",
    "substrate-only",
    "ok-unchanged",
    "ok-changed",
)


def normalize_evidence_tier(value: Any) -> EvidenceTier | None:
    """
    Normalize an evidence-tier-like value to the canonical 3-tier vocabulary.

    Accepts:
    - Canonical tiers: bedrock/mapped/hypothesis
    """
    if not isinstance(value, str):
        return None
    v = value.strip().lower()
    if not v:
        return None
    if v in EVIDENCE_TIERS:
        return v  # type: ignore[return-value]
    return None


@lru_cache(maxsize=1)
def bedrock_mapping_paths() -> Set[str]:
    """
    Return the repo-relative mapping paths declared bedrock for this world.
    """
    repo_root = find_repo_root(Path(__file__))
    registry = repo_root / "book" / "graph" / "concepts" / "BEDROCK_SURFACES.json"
    if not registry.exists():
        return set()
    try:
        data = json.loads(registry.read_text())
    except Exception:
        return set()
    out: Set[str] = set()
    for surface in data.get("surfaces", []) or []:
        if not isinstance(surface, dict):
            continue
        for p in surface.get("mapping_paths", []) or []:
            if isinstance(p, str) and p:
                out.add(p)
    return out


def is_bedrock_mapping_path(path: str | Path) -> bool:
    repo_root = find_repo_root(Path(__file__))
    p = Path(path)
    if not p.is_absolute():
        p = repo_root / p
    rel = to_repo_relative(p, repo_root)
    return rel in bedrock_mapping_paths()


def evidence_tier_for_artifact(
    *,
    path: str | Path | None = None,
    tier: Any = None,
    strict: bool = True,
) -> EvidenceTier:
    """
    Compute the canonical evidence tier for an artifact.

    Rules:
    - Bedrock registry membership wins when `path` is provided.
    - Otherwise `tier` is required.
    """
    normalized = normalize_evidence_tier(tier)

    if path is not None and is_bedrock_mapping_path(path):
        if normalized and normalized != "bedrock":
            raise ValueError(f"bedrock mapping path must have tier=bedrock ({path})")
        return "bedrock"

    if normalized is None:
        if strict:
            raise ValueError(f"missing/invalid evidence tier ({tier!r}) for {path or 'artifact'}")
        return "hypothesis"

    if path is not None and normalized == "bedrock":
        raise ValueError(f"non-bedrock artifact cannot claim tier=bedrock ({path})")

    return normalized
