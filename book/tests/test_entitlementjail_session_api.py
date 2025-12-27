from pathlib import Path

import pytest

from book.api.entitlementjail.logging import extract_details
from book.api.entitlementjail.paths import EJ
from book.api.entitlementjail.session import XpcSession


@pytest.mark.system
def test_entitlementjail_xpc_session_multi_probe(tmp_path: Path):
    assert EJ.exists(), "missing EntitlementJail CLI (book/tools/entitlement/EntitlementJail.app)"

    correlation_id = "test-entitlementjail-session"
    with XpcSession(
        profile_id="minimal",
        plan_id="test:entitlementjail:session",
        correlation_id=correlation_id,
        wait_spec="fifo:auto",
        wait_timeout_ms=15000,
    ) as session:
        assert session.pid() is not None
        trigger_error = session.trigger_wait(timeout_s=2.0)
        assert trigger_error is None, f"wait trigger failed: {trigger_error}"
        assert session.wait_for_trigger_received(timeout_s=2.0) is not None

        snapshot = session.run_probe(probe_id="capabilities_snapshot")
        assert snapshot.get("kind") == "probe_response"
        details = extract_details(snapshot)
        assert isinstance(details, dict)
        assert details.get("correlation_id") == correlation_id

        catalog = session.run_probe(probe_id="probe_catalog")
        assert catalog.get("kind") == "probe_response"
