from __future__ import annotations

from book.api.runtime.contracts import models
from book.api.runtime.contracts import normalize as runtime_normalize


def test_metadata_runner_preflight_blocked_row_normalizes_into_contract_shape():
    runtime_doc = {
        "world_id": models.WORLD_ID,
        "runner_info": {"entrypoint": "metadata_runner"},
        "results": [
            {
                "profile_id": "preflight:test",
                "operation": "file-read-metadata",
                "requested_path": "/tmp/foo",
                "syscall": "lstat",
                "attr_payload": "cmn",
                "status": "blocked",
                "failure_stage": "preflight",
                "failure_kind": "preflight_apply_gate_signature",
                "preflight": {
                    "classification": "likely_apply_gated_for_harness_identity",
                    "signature": "deny_message_filter",
                },
                "stderr": "",
            }
        ],
    }

    observations = runtime_normalize.normalize_metadata_results(runtime_doc)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.runtime_status == "blocked"
    assert obs.failure_stage == "preflight"
    assert obs.failure_kind == "preflight_apply_gate_signature"
    assert obs.actual is None
    assert isinstance(obs.preflight, dict)
    assert obs.preflight.get("classification") == "likely_apply_gated_for_harness_identity"
