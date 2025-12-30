from __future__ import annotations

from book.api.profile import sbpl_scan


def test_sbpl_scan_apply_gate_signature_classification():
    deny_sbpl = '(version 2)\n(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))\n'
    deny = sbpl_scan.classify_enterability_for_harness_identity(deny_sbpl)
    assert deny["classification"] == "likely_apply_gated_for_harness_identity"
    assert deny["signature"] == "deny_message_filter"
    assert deny["findings"] and deny["findings"][0]["denied_operation"] == "mach-message-send"

    allow_sbpl = '(version 2)\n(allow mach-bootstrap (apply-message-filter (allow mach-message-send)))\n'
    allow = sbpl_scan.classify_enterability_for_harness_identity(allow_sbpl)
    assert allow["classification"] == "no_known_apply_gate_signature"
    assert allow["signature"] is None
    assert allow["findings"] == []
