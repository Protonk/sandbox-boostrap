from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

from book.api.profile import identity as identity_mod


ALLOWED_CLASSES = {
    "strong_true",
    "weak_true",
    "unknown",
    "weak_false",
    "strong_false",
}


@pytest.mark.system
def test_inside_tool_json_contract(run_cmd):
    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    res = run_cmd(
        [sys.executable, "book/tools/inside/inside.py", "--json"],
        env=env,
        check=True,
        label="inside tool json",
    )
    payload = json.loads(res.stdout)

    assert payload["tool"] == "inside"
    assert payload["schema_version"] == 1
    assert payload["world_id"] == identity_mod.baseline_world_id()

    for key in ("policywitness_bin", "sbpl_wrapper", "sbpl_profile"):
        assert key in payload
        assert not Path(payload[key]).is_absolute()
    assert "log_bin" in payload

    signals = payload["signals"]
    for sid in ("S0", "S1", "S2", "S3", "S4", "S5", "S6"):
        assert sid in signals
        signal = signals[sid]
        assert signal["result_class"] in ALLOWED_CLASSES
        assert signal["strength"] in {"strong", "weak", "unknown"}
        assert signal["direction"] in {True, False, None}

    assert not Path(signals["S3"]["policywitness_bin"]).is_absolute()
    assert not Path(signals["S4"]["wrapper"]).is_absolute()
    assert not Path(signals["S4"]["profile"]).is_absolute()

    assert signals["S6"].get("axis") == "app_sandbox"

    summary = payload["summary"]
    assert summary["confidence"] in {"high", "medium", "low"}
    assert summary["harness_constrained"] in {True, False, None}
    assert isinstance(summary.get("triggers"), list)
