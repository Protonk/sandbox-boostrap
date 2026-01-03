from __future__ import annotations

import pytest

from book.api.witness import keepalive
from book.api.witness.paths import WITNESS_CLI, WITNESS_HOLD_OPEN
from book.api.witness.protocol import WaitSpec


@pytest.mark.system
def test_keepalive_hold_open():
    assert WITNESS_HOLD_OPEN.exists(), "missing hold_open helper"
    with keepalive.spawn_hold_open(wait_spec="fifo:auto", hold_open_timeout_s=5.0) as handle:
        assert handle.record.pid
        assert handle.record.mode == keepalive.KEEPALIVE_MODE_HOLD_OPEN
        if handle.record.wait_mode and handle.record.wait_path:
            assert handle.trigger_wait() is None
        assert handle.is_alive() is True


@pytest.mark.system
def test_keepalive_policywitness_session():
    assert WITNESS_CLI.exists(), "missing PolicyWitness CLI (book/tools/witness/PolicyWitness.app)"
    try:
        with keepalive.open_policywitness_session(
            profile_id="minimal",
            plan_id="test:keepalive",
            wait_spec=WaitSpec.fifo_auto(),
        ) as handle:
            assert handle.record.pid
            assert handle.record.mode == keepalive.KEEPALIVE_MODE_POLICYWITNESS
            if handle.record.wait_mode and handle.record.wait_path:
                assert handle.trigger_wait() is None
            assert handle.is_alive() is True
    except RuntimeError as exc:
        details = exc.args[1] if len(exc.args) > 1 and isinstance(exc.args[1], dict) else {}
        stdout = str(details.get("stdout") or "")
        if "Sandbox restriction" in stdout or "failed at lookup with error 159" in stdout:
            return
        raise
