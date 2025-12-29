from __future__ import annotations

import copy
from pathlib import Path

from book.api.runtime import plan as runtime_plan


ROOT = Path(__file__).resolve().parents[2]
HARDENED_PLAN = ROOT / "book" / "experiments" / "hardened-runtime" / "plan.json"


def test_plan_digest_is_deterministic_and_sensitive():
    doc = runtime_plan.load_plan(HARDENED_PLAN)
    d1 = runtime_plan.plan_digest(doc)
    d2 = runtime_plan.plan_digest(doc)
    assert d1 == d2

    mutated = copy.deepcopy(doc)
    mutated["profiles"] = list(mutated.get("profiles") or []) + ["nonexistent:profile"]
    assert runtime_plan.plan_digest(mutated) != d1

