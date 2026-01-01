from __future__ import annotations

import json
import os
import shutil
import sys
import textwrap
from pathlib import Path

import pytest


def _run_inside_json(run_cmd, env, cmd_prefix=None):
    cmd = [sys.executable, "book/tools/inside/inside.py", "--json"]
    if cmd_prefix:
        cmd = cmd_prefix + cmd
    res = run_cmd(cmd, env=env, check=True, label="inside tool json")
    return json.loads(res.stdout)


@pytest.mark.system
def test_inside_two_mode_matrix(run_cmd, tmp_path: Path):
    if shutil.which("sandbox-exec") is None:
        pytest.skip("sandbox-exec not available")

    env = dict(os.environ)
    env["PYTHONPATH"] = "."

    _run_inside_json(run_cmd, env)

    profile_text = textwrap.dedent(
        """
        (version 1)
        (allow default)
        (deny mach-lookup (global-name "com.yourteam.policy-witness.ProbeService_minimal"))
        """
    ).strip() + "\n"
    profile_path = tmp_path / "inside_sandbox.sb"
    profile_path.write_text(profile_text)

    sandbox_cmd = [
        "sandbox-exec",
        "-f",
        str(profile_path),
        "--",
    ]

    payload = _run_inside_json(run_cmd, env, cmd_prefix=sandbox_cmd)
    s0 = payload["signals"]["S0"]
    assert s0["strength"] == "strong"
    assert s0["direction"] is True

    summary = payload["summary"]
    assert summary["harness_constrained"] is True
    assert summary["confidence"] == "high"
