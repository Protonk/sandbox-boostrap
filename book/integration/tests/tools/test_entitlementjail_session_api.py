from pathlib import Path

import pytest

from book.api.entitlementjail import logging as ej_logging
from book.api.entitlementjail.logging import extract_details
from book.api.entitlementjail.paths import EJ
from book.api.entitlementjail.protocol import WaitSpec
from book.api.entitlementjail.session import open_session


@pytest.mark.system
def test_entitlementjail_xpc_session_multi_probe(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    assert EJ.exists(), "missing EntitlementJail CLI (book/tools/entitlement/EntitlementJail.app)"

    monkeypatch.setattr(ej_logging, "LOG_OBSERVER_MODE", "disabled")
    correlation_id = "test-entitlementjail-session"
    try:
        session = open_session(
            profile_id="minimal",
            plan_id="test:entitlementjail:session",
            correlation_id=correlation_id,
            wait_spec=WaitSpec.fifo_auto(),
            wait_timeout_ms=15000,
        )
    except RuntimeError as exc:
        details = exc.args[1] if len(exc.args) > 1 and isinstance(exc.args[1], dict) else {}
        stdout = str(details.get("stdout") or "")
        if "Sandbox restriction" in stdout or "failed at lookup with error 159" in stdout:
            return
        raise
    try:
        assert session.pid() is not None
        assert session.wait_path()
        assert session.wait_mode() == "fifo"
        trigger_error = session.trigger_wait(timeout_s=2.0)
        assert trigger_error is None, f"wait trigger failed: {trigger_error}"
        assert session.wait_for_trigger_received(timeout_s=2.0) is not None

        probe_log = tmp_path / "capabilities_snapshot.json"
        probe_record = session.run_probe_with_observer(
            probe_id="capabilities_snapshot",
            log_path=probe_log,
            plan_id="test:entitlementjail:session",
            row_id="capabilities_snapshot",
        )
        assert probe_record.get("observer_status") == "not_requested"
        assert probe_log.exists()
        snapshot = probe_record.get("stdout_json")
        assert isinstance(snapshot, dict)
        assert snapshot.get("kind") == "probe_response"
        details = extract_details(snapshot)
        assert isinstance(details, dict)
        assert details.get("correlation_id") == correlation_id

        session.send_command({"command": "run_probe", "probe_id": "probe_catalog", "argv": []})
        catalog = session.next_event(kind="probe_response", timeout_s=10.0)
        assert isinstance(catalog, dict)
        assert catalog.get("kind") == "probe_response"
    finally:
        session.close()
