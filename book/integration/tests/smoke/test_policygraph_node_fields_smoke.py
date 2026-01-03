import json
import os
import sys

import pytest


@pytest.mark.smoke
@pytest.mark.system
def test_policygraph_node_fields_describe(run_cmd):
    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    res = run_cmd(
        [sys.executable, "book/tools/policy/policygraph_node_fields.py", "--describe"],
        env=env,
        check=True,
        label="policygraph node fields describe",
    )
    payload = (res.stdout or res.stderr).strip()
    doc = json.loads(payload)
    assert doc["tool"] == "policygraph_node_fields"
    assert doc["world_id"] == "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
    assert "tag_layouts" in doc["inputs"]
    assert "policygraph_node_arg16.json" in doc["outputs"]["arg16"]
