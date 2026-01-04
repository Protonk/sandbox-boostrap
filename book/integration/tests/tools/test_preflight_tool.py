from __future__ import annotations

import json
from pathlib import Path

from book.api.profile import identity as identity_mod
from book.tools.preflight import preflight as preflight_mod


def test_preflight_sbpl_text_and_cli_report_apply_gate_signature(tmp_path: Path):
    sbpl = '(version 2)\n(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))\n'

    rec = preflight_mod.preflight_sbpl_text(sbpl)
    assert rec.world_id == identity_mod.baseline_world_id()
    assert rec.classification == "likely_apply_gated_for_harness_identity"
    assert rec.signature == "deny_message_filter"
    assert rec.findings and rec.findings[0]["denied_operation"] == "mach-message-send"
    assert rec.signature_meta and "pointers" in rec.signature_meta

    payload = rec.to_json()
    assert payload["tool"] == "book/tools/preflight"
    assert payload["preflight_schema_version"] == preflight_mod.PREFLIGHT_SCHEMA_VERSION

    sbpl_path = tmp_path / "gated.sb"
    sbpl_path.write_text(sbpl)
    out = tmp_path / "out.json"
    rc = preflight_mod.main(["scan", str(sbpl_path), "--out", str(out)])
    assert rc == 2
    cli_payload = json.loads(out.read_text())
    assert cli_payload[0]["preflight_schema_version"] == preflight_mod.PREFLIGHT_SCHEMA_VERSION
    assert cli_payload[0]["classification"] == "likely_apply_gated_for_harness_identity"


def test_preflight_reports_invalid_inputs():
    rec = preflight_mod.preflight_sbpl_text("(version 2\n(allow")
    assert rec.classification == "invalid"
    assert rec.error

    rec = preflight_mod.preflight_path(Path("does_not_exist.sb"))
    assert rec.classification == "invalid"
    assert rec.error == "missing"


def test_preflight_blob_digest_classification_cases():
    cases = [
        (
            Path(
                "book/evidence/syncretic/validation/out/experiments/gate-witnesses/forensics/"
                "mach_bootstrap_deny_message_send/minimal_failing.sb.bin"
            ),
            "likely_apply_gated_for_harness_identity",
            "apply_gate_blob_digest",
            True,
        ),
        (
            Path("book/evidence/syncretic/validation/fixtures/blobs/sample.sb.bin"),
            "no_known_apply_gate_signature",
            None,
            False,
        ),
        (
            Path("book/evidence/syncretic/validation/fixtures/blobs/airlock.sb.bin"),
            "likely_apply_gated_for_harness_identity",
            "apply_gate_blob_digest",
            True,
        ),
    ]

    for blob, classification, signature, matched in cases:
        rec = preflight_mod.preflight_path(blob)
        assert rec.classification == classification
        assert rec.signature == signature
        assert rec.findings and rec.findings[0]["matched"] is matched
