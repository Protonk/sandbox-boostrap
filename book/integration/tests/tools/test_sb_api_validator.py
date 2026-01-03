from __future__ import annotations

import json
import pytest

from book.api.witness import keepalive
from book.api.witness.paths import WITNESS_HOLD_OPEN, WITNESS_SB_API_VALIDATOR


@pytest.mark.system
def test_sb_api_validator_json_contract(run_cmd):
    assert WITNESS_SB_API_VALIDATOR.exists(), "missing sb_api_validator binary"
    assert WITNESS_HOLD_OPEN.exists(), "missing hold_open helper"

    with keepalive.KeepaliveService(stage="operation", lane="oracle") as service:
        result = service.client.start_target(mode="spawn", wait_spec="fifo:auto", ready_timeout_s=5.0)
        target = result.get("target")
        assert isinstance(target, dict)
        pid = target.get("pid")
        assert isinstance(pid, int), "hold_open did not report a pid"

        cmd = [
            str(WITNESS_SB_API_VALIDATOR),
            "--json",
            str(pid),
            "file-read*",
            "PATH",
            "/etc/hosts",
        ]
        res = run_cmd(cmd, check=True, label="sb_api_validator json")
        payload = json.loads(res.stdout)
        target_id = target.get("target_id")
        if isinstance(target_id, str):
            service.client.release(target_id=target_id)

    assert payload["kind"] == "sb_api_validator_result"
    assert payload["schema_version"] == 1
    assert payload["pid"] == pid
    assert payload["operation"] == "file-read*"
    assert payload["filter_type"] == "PATH"
    assert payload["filter_value"] == "/etc/hosts"
    assert isinstance(payload.get("rc"), int)
    assert isinstance(payload.get("errno"), int)
