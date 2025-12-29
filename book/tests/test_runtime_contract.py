from __future__ import annotations

import pytest

from book.api.runtime.core import contract as rt_contract
from book.api.runtime.core import models
from book.api.runtime.core import normalize
from book.api.runtime.mapping.views import build_callout_vs_syscall


def _matrix_and_results_with_probe(stderr: str, runtime_result=None):
    expected_matrix = {
        "world_id": models.WORLD_ID,
        "profiles": {
            "p": {
                "probes": [
                    {
                        "name": "probe",
                        "operation": "file-read*",
                        "target": "/tmp/foo",
                        "expected": "deny",
                        "expectation_id": "p:probe",
                    }
                ]
            }
        },
    }
    runtime_results = {
        "p": {
            "probes": [
                {
                    "name": "probe",
                    "expectation_id": "p:probe",
                    "operation": "file-read*",
                    "path": "/tmp/foo",
                    "expected": "deny",
                    "actual": "deny",
                    "match": True,
                    "runtime_result": runtime_result or {"status": "errno", "errno": 1},
                    "stderr": stderr,
                    "stdout": "",
                    "command": ["/bin/cat", "/tmp/foo"],
                }
            ]
        }
    }
    return expected_matrix, runtime_results


def test_strip_tool_markers_removes_only_tool_lines():
    stderr_raw = "\n".join(
        [
            "human error line",
            '{"tool":"sbpl-preflight","marker_schema_version":1,"stage":"preflight","mode":"sbpl","policy":"enforce","profile":"p.sb","rc":0,"pid":123}',
            '{"tool":"sbpl-compile","marker_schema_version":1,"stage":"compile","api":"sandbox_compile_file","rc":0,"errno":0,"profile":"p.sb","profile_type":0,"bytecode_length":123}',
            '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","api":"sandbox_init","rc":-1,"errno":1,"errbuf":"Operation not permitted","err_class":"errno_eperm","err_class_source":"errno_only"}',
            '{"tool":"seatbelt-callout","marker_schema_version":2,"stage":"preflight","api":"sandbox_check_by_audit_token","operation":"file-read*","filter_type":0,"filter_type_name":"path","check_type":0,"varargs_count":1,"argument":"/tmp/foo","no_report":true,"token_status":"ok","token_mach_kr":0,"rc":1,"errno":0,"decision":"deny"}',
            '{"tool":"other","stage":"apply","rc":0}',
            "",
        ]
    )
    stripped = rt_contract.strip_tool_markers(stderr_raw)
    assert stripped == "human error line\n" + '{"tool":"other","stage":"apply","rc":0}' + "\n"


def test_upgrade_runtime_result_derives_apply_report_from_markers():
    stderr_raw = "\n".join(
        [
            '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","api":"sandbox_init","rc":-1,"errno":1,"errbuf":"Operation not permitted"}',
            "sandbox_init failed: Operation not permitted",
        ]
    )
    upgraded = rt_contract.upgrade_runtime_result({"status": "errno", "errno": 1, "failure_stage": "apply"}, stderr_raw)
    assert upgraded["runtime_result_schema_version"] == rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION
    assert upgraded["tool_marker_schema_version"] == rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION
    report = upgraded.get("apply_report") or {}
    assert report.get("api") == "sandbox_init"
    assert report.get("rc") == -1
    assert report.get("errno") == 1
    assert report.get("err_class") == "errno_eperm"
    assert report.get("err_class_source") == "errno_only"


def test_assert_no_tool_markers_in_stderr_rejects_markers():
    with pytest.raises(AssertionError):
        rt_contract.assert_no_tool_markers_in_stderr(
            '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","api":"sandbox_init","rc":-1,"errno":1}\n'
        )
    with pytest.raises(AssertionError):
        rt_contract.assert_no_tool_markers_in_stderr(
            '{"tool":"sbpl-compile","marker_schema_version":1,"stage":"compile","api":"sandbox_compile_file","rc":0,"errno":0}\n'
        )
    with pytest.raises(AssertionError):
        rt_contract.assert_no_tool_markers_in_stderr(
            '{"tool":"sbpl-preflight","marker_schema_version":1,"stage":"preflight","mode":"sbpl","policy":"enforce","profile":"p.sb","rc":2}\n'
        )


def test_normalize_runtime_results_strips_markers_and_derives_apply_report():
    stderr_raw = "\n".join(
        [
            '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","api":"sandbox_init","rc":0,"errno":0}',
            '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","api":"sandbox_init","rc":0}',
            "human stderr line",
            "",
        ]
    )
    expected_matrix, runtime_results = _matrix_and_results_with_probe(stderr_raw, runtime_result={"status": "success", "errno": None})
    obs = normalize.normalize_matrix(expected_matrix, runtime_results)
    assert len(obs) == 1
    rec = normalize.observation_to_dict(obs[0])
    assert "tool" not in (rec.get("stderr") or "")
    assert rec.get("stderr") == "human stderr line\n"
    report = rec.get("apply_report") or {}
    assert report.get("api") == "sandbox_init"
    assert report.get("rc") == 0
    assert report.get("err_class") == "ok"


def test_normalize_runtime_results_rejects_out_of_order_markers():
    # applied marker without apply marker
    stderr_raw = '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"applied","api":"sandbox_init","rc":0}\n'
    expected_matrix, runtime_results = _matrix_and_results_with_probe(stderr_raw)
    with pytest.raises(AssertionError):
        normalize.normalize_matrix(expected_matrix, runtime_results)


def test_normalize_runtime_results_rejects_unsupported_marker_schema_version():
    stderr_raw = '{"tool":"sbpl-apply","marker_schema_version":99,"stage":"apply","api":"sandbox_init","rc":0,"errno":0}\n'
    expected_matrix, runtime_results = _matrix_and_results_with_probe(stderr_raw)
    with pytest.raises(AssertionError):
        normalize.normalize_matrix(expected_matrix, runtime_results)


def test_normalize_runtime_results_rejects_preflight_stage_with_apply_markers():
    stderr_raw = '{"tool":"sbpl-apply","marker_schema_version":1,"stage":"apply","api":"sandbox_init","rc":-1,"errno":1}\n'
    runtime_result = {
        "status": "blocked",
        "errno": None,
        "failure_stage": "preflight",
        "failure_kind": "preflight_apply_gate_signature",
    }
    expected_matrix, runtime_results = _matrix_and_results_with_probe(stderr_raw, runtime_result=runtime_result)
    with pytest.raises(AssertionError):
        normalize.normalize_matrix(expected_matrix, runtime_results)

def test_seatbelt_callout_marker_requires_no_report_fields_and_is_non_classifying():
    # Contract tripwire: seatbelt-callout markers must carry explicit no_report
    # boolean and, when false, an explicit reason. Markers must never affect
    # failure_stage/failure_kind classification.
    stderr_raw = "\n".join(
        [
            '{"tool":"seatbelt-callout","marker_schema_version":2,"stage":"preflight","api":"sandbox_check_by_audit_token","operation":"file-read*","filter_type":0,"filter_type_name":"path","check_type":0,"varargs_count":1,"argument":"/tmp/foo","no_report":false,"no_report_reason":"symbol_missing","token_status":"ok","token_mach_kr":0,"rc":1,"errno":0,"decision":"deny"}',
            "human stderr line",
            "",
        ]
    )
    runtime_result = {"status": "errno", "errno": 1, "failure_stage": "probe", "failure_kind": "probe_syscall_errno"}
    expected_matrix, runtime_results = _matrix_and_results_with_probe(stderr_raw, runtime_result=runtime_result)

    markers = rt_contract.extract_seatbelt_callout_markers(stderr_raw)
    assert len(markers) == 1
    marker = markers[0]
    assert marker.get("no_report") in (True, False)
    if marker.get("no_report") is False:
        assert isinstance(marker.get("no_report_reason"), str) and marker.get("no_report_reason")

    obs = normalize.normalize_matrix(expected_matrix, runtime_results)
    rec = normalize.observation_to_dict(obs[0])
    assert rec.get("failure_stage") == "probe"
    assert rec.get("failure_kind") == "probe_syscall_errno"

def test_upgrade_seatbelt_callout_marker_adds_defaults_for_legacy_markers():
    stderr_raw = "\n".join(
        [
            '{"tool":"seatbelt-callout","marker_schema_version":1,"stage":"preflight","api":"sandbox_check_by_audit_token","operation":"file-read*","filter_type":0,"argument":"/tmp/foo","rc":1,"errno":0,"decision":"deny"}',
            "",
        ]
    )
    markers = rt_contract.extract_seatbelt_callout_markers(stderr_raw)
    assert len(markers) == 1
    marker = markers[0]
    assert marker.get("marker_schema_version") == 1
    assert marker.get("filter_type_name") == "path"
    assert marker.get("no_report") is None
    assert marker.get("no_report_reason") == "legacy"
    assert marker.get("check_type") is None
    assert marker.get("varargs_count") is None
    assert marker.get("token_status") is None
    assert marker.get("token_mach_kr") is None


def test_callout_vs_syscall_projection_is_derived_only():
    stderr_raw = "\n".join(
        [
            '{"tool":"seatbelt-callout","marker_schema_version":2,"stage":"pre_syscall","api":"sandbox_check_by_audit_token","operation":"file-read*","filter_type":0,"filter_type_name":"path","check_type":0,"varargs_count":1,"argument":"/tmp/foo","no_report":true,"token_status":"ok","token_mach_kr":0,"rc":1,"errno":0,"decision":"deny"}',
            "",
        ]
    )
    expected_matrix = {
        "world_id": models.WORLD_ID,
        "profiles": {
            "p": {
                "probes": [
                    {
                        "name": "probe",
                        "operation": "file-read*",
                        "target": "/tmp/foo",
                        "expected": "allow",
                        "expectation_id": "p:probe",
                    }
                ]
            }
        },
    }
    runtime_results = {
        "p": {
            "probes": [
                {
                    "name": "probe",
                    "expectation_id": "p:probe",
                    "operation": "file-read*",
                    "path": "/tmp/foo",
                    "expected": "allow",
                    "actual": "allow",
                    "match": True,
                    "runtime_result": {"status": "success", "errno": None},
                    "stderr": stderr_raw,
                    "stdout": "",
                    "command": ["/bin/cat", "/tmp/foo"],
                }
            ]
        }
    }

    obs = normalize.normalize_matrix(expected_matrix, runtime_results)
    table = build_callout_vs_syscall(obs)
    assert (table.get("counts") or {}).get("callout_deny_syscall_ok") == 1
    row = (table.get("rows") or [])[0]
    assert row.get("category") == "callout_deny_syscall_ok"


def test_normalized_event_runner_info_tool_build_id_matches_sha256():
    # Contract: when runner_info carries an entrypoint_sha256, tool_build_id matches.
    stderr_raw = ""
    runner_info = {"entrypoint": "SBPL-wrapper", "entrypoint_sha256": "deadbeef", "tool_build_id": "deadbeef"}
    expected_matrix, runtime_results = _matrix_and_results_with_probe(stderr_raw, runtime_result={"status": "errno", "errno": 1, "runner_info": runner_info})
    obs = normalize.normalize_matrix(expected_matrix, runtime_results)
    rec = normalize.observation_to_dict(obs[0])
    info = rec.get("runner_info") or {}
    assert info.get("tool_build_id") == info.get("entrypoint_sha256")
