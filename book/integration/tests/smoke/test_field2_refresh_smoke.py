import os
import sys

import pytest


@pytest.mark.smoke
@pytest.mark.system
def test_field2_refresh_help(run_cmd):
    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    res = run_cmd(
        [sys.executable, "book/evidence/experiments/field2-final-final/field2-atlas/field2_refresh.py", "--help"],
        env=env,
        check=True,
        label="field2 refresh help",
    )
    text = f"{res.stdout}{res.stderr}".lower()
    assert "packet" in text


@pytest.mark.system
def test_field2_refresh_requires_packet(run_cmd):
    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    res = run_cmd(
        [sys.executable, "book/evidence/experiments/field2-final-final/field2-atlas/field2_refresh.py"],
        env=env,
        check=False,
        label="field2 refresh missing packet",
    )
    text = f"{res.stdout}{res.stderr}".lower()
    assert res.returncode != 0
    assert "packet" in text
