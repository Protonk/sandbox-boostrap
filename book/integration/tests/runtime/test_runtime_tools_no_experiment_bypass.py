from __future__ import annotations

import re
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
EXPERIMENTS = ROOT / "book" / "evidence" / "experiments"

CODE_SUFFIXES = {".py"}

# This is a *narrow* guardrail: plan-based experiments should not grow new
# bespoke harness runners or normalize their own decision-stage streams.
# Keep the allowlist explicit and small so new bypasses are visible.
FORBIDDEN_PATTERNS = {
    "harness_runner": re.compile(r"\bbook\.api\.runtime\.execution\.harness\.runner\b"),
    "normalize_observations": re.compile(r"\bwrite_(matrix|metadata)_observations\b"),
}

ALLOWLIST = {
    # Fixture prep is a narrow helper; do not allow runner imports elsewhere.
    "harness_runner": {Path("book/evidence/experiments/runtime-final-final/suites/vfs-canonicalization/prepare_fixtures.py")},
    "normalize_observations": {Path("book/evidence/experiments/runtime-final-final/suites/metadata-runner/run_metadata.py")},
}


def _iter_experiment_code() -> list[Path]:
    if not EXPERIMENTS.exists():
        return []
    paths: list[Path] = []
    for path in EXPERIMENTS.rglob("*"):
        if path.is_file() and path.suffix in CODE_SUFFIXES:
            paths.append(path)
    return sorted(paths)


def _first_match_line(text: str, match: re.Match[str]) -> int:
    return text.count("\n", 0, match.start()) + 1


def test_no_new_experiment_runtime_bypasses():
    violations: list[str] = []
    for path in _iter_experiment_code():
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for kind, pattern in FORBIDDEN_PATTERNS.items():
            if rel in ALLOWLIST.get(kind, set()):
                continue
            match = pattern.search(text)
            if not match:
                continue
            line = _first_match_line(text, match)
            violations.append(f"{rel}:{line} contains forbidden {kind} usage")

    assert not violations, "runtime bypass risk:\n" + "\n".join(violations)
