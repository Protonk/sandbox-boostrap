import json

import pytest

from book.api.witness import client
from book.api.witness.paths import WITNESS_CLI


@pytest.mark.system
def test_witness_quarantine_lab_bundle_id_resolution(run_cmd, monkeypatch: pytest.MonkeyPatch):
    assert WITNESS_CLI.exists(), "missing PolicyWitness CLI (book/tools/witness/PolicyWitness.app)"

    res = run_cmd(
        [str(WITNESS_CLI), "show-profile", "quarantine_default"],
        check=True,
        label="policy-witness show-profile quarantine_default",
    )
    stdout_json = json.loads(res.stdout or "{}")
    profile = stdout_json.get("data", {}).get("profile", {})
    variants = [entry for entry in profile.get("variants", []) if isinstance(entry, dict)]

    base_bundle_id = next(entry["bundle_id"] for entry in variants if entry.get("variant") == "base")
    injectable_bundle_id = next(entry["bundle_id"] for entry in variants if entry.get("variant") == "injectable")

    assert client.extract_profile_bundle_id(stdout_json) == base_bundle_id
    assert client.extract_profile_bundle_id(stdout_json, variant="base") == base_bundle_id
    assert client.extract_profile_bundle_id(stdout_json, variant="injectable") == injectable_bundle_id

    captured = {}

    def fake_show_profile(profile_id: str, *, timeout_s=None):
        return {"stdout_json": stdout_json}

    def fake_wrap(cmd, *, cwd=None, timeout_s=None, repo_root=None):
        captured["cmd"] = cmd
        return {"stdout": "{}", "stderr": "", "exit_code": 0, "stdout_json": {"result": {"exit_code": 0}}}

    monkeypatch.setattr(client, "show_profile", fake_show_profile)
    monkeypatch.setattr(client.exec_record, "run_json_command", fake_wrap)

    payload = client.quarantine_lab(
        profile_id="quarantine_default",
        payload_class="text",
        payload_args=["--dir", "tmp"],
        variant="injectable",
    )

    assert "error" not in payload
    assert payload.get("bundle_id") == injectable_bundle_id
    assert captured.get("cmd", [None, None, None])[2] == injectable_bundle_id
