import os
import sys

import pytest


@pytest.mark.smoke
@pytest.mark.system
def test_inside_tool_help(run_cmd):
    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    res = run_cmd(
        [sys.executable, "book/tools/inside/inside.py", "--help"],
        env=env,
        check=True,
        label="inside tool help",
    )
    text = f"{res.stdout}{res.stderr}".lower()
    assert "usage" in text
