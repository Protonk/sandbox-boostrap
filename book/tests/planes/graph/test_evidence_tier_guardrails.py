from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, List

from book.api import evidence_tiers


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))

# Deprecated vocabulary that should not appear in agent-facing docs or as `tier` values.
LEGACY_TERMS = set(evidence_tiers.LEGACY_TIER_TERMS)


def git_ls_files(run_cmd) -> List[str]:
    result = run_cmd(["git", "ls-files"], cwd=ROOT, check=True, label="git ls-files")
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return [rel for rel in files if (ROOT / rel).exists()]


def read_text(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8", errors="replace")


def iter_tier_values(obj: Any) -> Iterable[Any]:
    if isinstance(obj, dict):
        for key, value in obj.items():
            # Some artifacts embed a schema dictionary that describes the allowed
            # tier vocabulary as a type string (e.g., "bedrock|mapped|hypothesis").
            # That is not an evidence-tier value and should not be validated here.
            if key == "schema":
                continue
            if key == "tier":
                yield value
            yield from iter_tier_values(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from iter_tier_values(value)


def test_no_legacy_terms_in_markdown(run_cmd):
    for rel in git_ls_files(run_cmd):
        if not rel.endswith(".md"):
            continue
        text = read_text(rel).lower()
        for term in LEGACY_TERMS:
            assert term not in text, f"{rel} contains deprecated evidence-tier term {term!r}"


def test_tier_fields_use_only_canonical_vocab(run_cmd):
    for rel in git_ls_files(run_cmd):
        if not rel.endswith(".json"):
            continue

        text = read_text(rel)
        if '"tier"' not in text:
            continue

        try:
            doc = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"{rel} contains '\"tier\"' but is not valid JSON: {exc}") from exc

        for value in iter_tier_values(doc):
            assert isinstance(value, str), f"{rel} has non-string tier value: {value!r}"
            normalized = evidence_tiers.normalize_evidence_tier(value)
            assert normalized is not None, f"{rel} has non-canonical tier value: {value!r}"
            assert value == normalized, f"{rel} tier value must be canonical casing: {value!r}"
            assert normalized in evidence_tiers.EVIDENCE_TIERS, f"{rel} tier not in canonical set: {value!r}"
