"""Contract fixture helpers for PolicyWitness tooling."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

from book.api import path_utils
from book.api.witness.paths import REPO_ROOT


CONTRACT_DIR = REPO_ROOT / "book" / "tools" / "witness" / "fixtures" / "contract"
POLICY_WITNESS_HELP = CONTRACT_DIR / "policy-witness.help.txt"
SANDBOX_LOG_OBSERVER_HELP = CONTRACT_DIR / "sandbox-log-observer.help.txt"
OBSERVER_SAMPLE = CONTRACT_DIR / "observer.sample.json"


def read_text(path: Path) -> str:
    return path.read_text()


def load_observer_sample() -> Dict[str, object]:
    payload = json.loads(OBSERVER_SAMPLE.read_text())
    if not isinstance(payload, dict):
        raise ValueError("observer sample payload is not a dict")
    return payload


def repo_relative(path: Path) -> str:
    return path_utils.to_repo_relative(path, REPO_ROOT)
