from __future__ import annotations

import copy
from pathlib import Path

from book.api.runtime.plans import loader as runtime_plan


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
HARDENED_PLAN = (
    ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "hardened-runtime"
    / "plan.json"
)


def test_plan_digest_is_deterministic_and_sensitive():
    doc = runtime_plan.load_plan(HARDENED_PLAN)
    d1 = runtime_plan.plan_digest(doc)
    d2 = runtime_plan.plan_digest(doc)
    assert d1 == d2

    mutated = copy.deepcopy(doc)
    mutated["profiles"] = list(mutated.get("profiles") or []) + ["nonexistent:profile"]
    assert runtime_plan.plan_digest(mutated) != d1
