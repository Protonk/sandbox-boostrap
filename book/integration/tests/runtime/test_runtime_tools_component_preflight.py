"""
Component tests for runtime preflight integration.

These tests exercise harness-side preflight classification without requiring
clean channel execution.
"""

from __future__ import annotations

import json
from pathlib import Path

from book.api.runtime.execution.harness import runner


def test_runtime_preflight_blocks_known_apply_gate_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_PREFLIGHT", "1")
    monkeypatch.delenv("SANDBOX_LORE_PREFLIGHT_FORCE", raising=False)

    witness = Path("book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/minimal_failing.sb")
    assert witness.exists(), "gate-witness SBPL fixture missing"

    matrix = {
        "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
        "profiles": {
            "preflight:test": {
                "blob": str(witness),
                "mode": "sbpl",
                "probes": [
                    {"name": "noop", "operation": "process-exec", "target": None, "expected": "allow"},
                ],
            }
        },
    }
    matrix_path = tmp_path / "expected_matrix.json"
    matrix_path.write_text(json.dumps(matrix, indent=2))

    out_path = runner.run_matrix(matrix_path, out_dir=tmp_path)
    results = json.loads(out_path.read_text())

    entry = results["preflight:test"]
    assert entry["status"] == "blocked"
    preflight = entry.get("preflight") or {}
    assert preflight.get("classification") == "likely_apply_gated_for_harness_identity"
    assert preflight.get("signature") == "deny_message_filter"

    probes = entry.get("probes") or []
    assert len(probes) == 1
    rr = probes[0].get("runtime_result") or {}
    assert rr.get("status") == "blocked"
    assert rr.get("failure_stage") == "preflight"
    assert rr.get("failure_kind") == "preflight_apply_gate_signature"


def test_runtime_preflight_blocks_known_apply_gate_blob_digest(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_PREFLIGHT", "1")
    monkeypatch.delenv("SANDBOX_LORE_PREFLIGHT_FORCE", raising=False)

    witness_blob = Path(
        "book/evidence/graph/concepts/validation/out/experiments/gate-witnesses/forensics/"
        "mach_bootstrap_deny_message_send/minimal_failing.sb.bin"
    )
    assert witness_blob.exists(), "gate-witness SBPL blob fixture missing"

    matrix = {
        "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
        "profiles": {
            "preflight:blob": {
                "blob": str(witness_blob),
                "mode": "blob",
                "probes": [
                    {"name": "noop", "operation": "process-exec", "target": None, "expected": "allow"},
                ],
            }
        },
    }
    matrix_path = tmp_path / "expected_matrix.json"
    matrix_path.write_text(json.dumps(matrix, indent=2))

    out_path = runner.run_matrix(matrix_path, out_dir=tmp_path)
    results = json.loads(out_path.read_text())

    entry = results["preflight:blob"]
    assert entry["status"] == "blocked"
    preflight = entry.get("preflight") or {}
    assert preflight.get("classification") == "likely_apply_gated_for_harness_identity"
    assert preflight.get("signature") == "apply_gate_blob_digest"

    probes = entry.get("probes") or []
    assert len(probes) == 1
    rr = probes[0].get("runtime_result") or {}
    assert rr.get("status") == "blocked"
    assert rr.get("failure_stage") == "preflight"
    assert rr.get("failure_kind") == "preflight_apply_gate_signature"


def test_runtime_profile_can_force_apply_even_when_preflight_flags_signature(tmp_path, monkeypatch):
    monkeypatch.setenv("SANDBOX_LORE_PREFLIGHT", "1")
    monkeypatch.delenv("SANDBOX_LORE_PREFLIGHT_FORCE", raising=False)

    witness = Path("book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses/mach_bootstrap_deny_message_send/minimal_failing.sb")
    assert witness.exists(), "gate-witness SBPL fixture missing"

    calls = {"count": 0}

    def fake_run_probe(profile, probe, profile_mode, wrapper_preflight):
        calls["count"] += 1
        return {"command": ["true"], "exit_code": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(runner, "run_probe", fake_run_probe)

    matrix = {
        "world_id": "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5",
        "profiles": {
            "preflight:forced": {
                "blob": str(witness),
                "mode": "sbpl",
                "preflight": {"mode": "force"},
                "probes": [
                    {"name": "noop", "operation": "process-exec", "target": None, "expected": "allow"},
                ],
            }
        },
    }
    matrix_path = tmp_path / "expected_matrix.json"
    matrix_path.write_text(json.dumps(matrix, indent=2))

    out_path = runner.run_matrix(matrix_path, out_dir=tmp_path)
    results = json.loads(out_path.read_text())

    assert calls["count"] == 1
    entry = results["preflight:forced"]
    assert entry["status"] == "ok"
    preflight = entry.get("preflight") or {}
    assert preflight.get("classification") == "likely_apply_gated_for_harness_identity"
    assert preflight.get("signature") == "deny_message_filter"
