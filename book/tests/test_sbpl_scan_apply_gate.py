from __future__ import annotations

from book.api.profile_tools import sbpl_scan


def test_scan_apply_message_filter_deny_detects_signature():
    sbpl = '(version 2)\n(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))\n'
    rec = sbpl_scan.classify_enterability_for_harness_identity(sbpl)
    assert rec["classification"] == "likely_apply_gated_for_harness_identity"
    assert rec["signature"] == "deny_message_filter"
    assert rec["findings"] and rec["findings"][0]["denied_operation"] == "mach-message-send"


def test_scan_apply_message_filter_allow_only_does_not_trigger():
    sbpl = '(version 2)\n(allow mach-bootstrap (apply-message-filter (allow mach-message-send)))\n'
    rec = sbpl_scan.classify_enterability_for_harness_identity(sbpl)
    assert rec["classification"] == "no_known_apply_gate_signature"
    assert rec["signature"] is None
    assert rec["findings"] == []

