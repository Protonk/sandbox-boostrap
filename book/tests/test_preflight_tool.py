from __future__ import annotations

import json
from pathlib import Path

from book.api.profile_tools import identity as identity_mod
from book.tools.preflight import preflight as preflight_mod


def test_preflight_sbpl_text_flags_deny_message_filter_signature():
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


def test_preflight_sbpl_text_invalid_is_reported():
    sbpl = "(version 2\n(allow"
    rec = preflight_mod.preflight_sbpl_text(sbpl)
    assert rec.classification == "invalid"
    assert rec.error


def test_preflight_cli_exit_code_and_output(tmp_path):
    sbpl_path = tmp_path / "gated.sb"
    sbpl_path.write_text('(version 2)\n(allow mach-bootstrap (apply-message-filter (deny mach-message-send)))\n')
    out = tmp_path / "out.json"
    rc = preflight_mod.main(["scan", str(sbpl_path), "--out", str(out)])
    assert rc == 2
    payload = json.loads(out.read_text())
    assert payload[0]["preflight_schema_version"] == preflight_mod.PREFLIGHT_SCHEMA_VERSION
    assert payload[0]["classification"] == "likely_apply_gated_for_harness_identity"


def test_preflight_missing_path_is_invalid():
    rec = preflight_mod.preflight_path(Path("does_not_exist.sb"))
    assert rec.classification == "invalid"
    assert rec.error == "missing"
