from __future__ import annotations

import json
import shutil
from pathlib import Path

from book.api import path_utils
from book.api.frida import trace_v1
from book.api.frida.validate import validate_run_dir


def test_frida_hook_manifests_are_present_and_well_formed() -> None:
    repo_root = path_utils.find_repo_root()
    hooks_dir = repo_root / "book/api/frida/hooks"
    assert hooks_dir.is_dir()

    js_paths = sorted(p for p in hooks_dir.glob("*.js") if p.is_file())
    assert js_paths, "expected at least one hook under book/api/frida/hooks"

    for js_path in js_paths:
        manifest_path = js_path.with_suffix(".manifest.json")
        assert manifest_path.is_file(), f"missing manifest: {path_utils.to_repo_relative(manifest_path, repo_root)}"

        manifest = json.loads(manifest_path.read_text())
        assert manifest.get("schema_name") == "book.api.frida.hook_manifest"
        assert manifest.get("schema_version") == 1

        hook = manifest.get("hook")
        assert isinstance(hook, dict)
        assert isinstance(hook.get("id"), str) and hook.get("id")
        assert hook.get("script_path") == path_utils.to_repo_relative(js_path, repo_root)

        tes = manifest.get("trace_event_schema")
        assert isinstance(tes, dict)
        assert tes.get("schema_name") == trace_v1.TRACE_EVENT_SCHEMA_NAME
        assert tes.get("schema_version") == trace_v1.TRACE_EVENT_SCHEMA_VERSION

        rpc_exports = manifest.get("rpc_exports")
        assert isinstance(rpc_exports, list)
        assert all(isinstance(x, str) for x in rpc_exports)

        configure = manifest.get("configure")
        assert isinstance(configure, dict)
        supported = configure.get("supported")
        assert isinstance(supported, bool)
        if supported:
            assert "configure" in rpc_exports
        else:
            assert "configure" not in rpc_exports

        module_expectations = manifest.get("module_expectations")
        assert isinstance(module_expectations, list)
        for m in module_expectations:
            assert isinstance(m, dict)
            assert isinstance(m.get("name"), str) and m.get("name")


def test_frida_trace_validate_known_good_runs(tmp_path: Path) -> None:
    repo_root = path_utils.find_repo_root()
    inventory_path = repo_root / "book/api/frida/trace_inventory.json"
    inventory = json.loads(inventory_path.read_text())
    runs = inventory.get("runs")
    assert isinstance(runs, list)

    known_good = []
    for run in runs:
        if not isinstance(run, dict):
            continue
        kg = run.get("known_good")
        if not isinstance(kg, dict):
            continue
        if kg.get("validate_expected_ok") is True:
            known_good.append(run)

    assert known_good, "expected at least one known-good run in trace_inventory.json"

    for run in known_good:
        run_id = run.get("id")
        assert isinstance(run_id, str) and run_id

        run_dir_rel = run.get("run_dir")
        assert isinstance(run_dir_rel, str) and run_dir_rel
        src_dir = path_utils.ensure_absolute(run_dir_rel, repo_root)
        assert src_dir.is_dir(), f"missing run dir: {run_dir_rel}"

        dst_dir = tmp_path / run_id
        shutil.copytree(src_dir, dst_dir)

        report = validate_run_dir(dst_dir)
        assert report.get("ok") is True

        kg = run["known_good"]
        digests = kg.get("validate_digests")
        assert isinstance(digests, dict)

        out_digests = report.get("digests")
        assert isinstance(out_digests, dict)
        assert out_digests.get("events_jsonl_sha256") == digests.get("events_jsonl_sha256")
        assert out_digests.get("chrometrace_json_sha256") == digests.get("chrometrace_json_sha256")

        expected_query_digests = digests.get("query_result_digests")
        assert isinstance(expected_query_digests, dict)
        query_section = report.get("query")
        assert isinstance(query_section, dict)
        actual_direct = query_section.get("digests", {}).get("direct")
        assert isinstance(actual_direct, dict)
        for qname, qdigest in expected_query_digests.items():
            assert actual_direct.get(qname) == qdigest


def test_frida_fs_open_selftest_payload_fields_survive_normalization(tmp_path: Path) -> None:
    repo_root = path_utils.find_repo_root()
    src_dir = repo_root / "book/api/frida/fixtures/runs/00000000-0000-4000-8000-000000000002"
    assert src_dir.is_dir()

    dst_dir = tmp_path / "fs_open_selftest"
    shutil.copytree(src_dir, dst_dir)

    report = validate_run_dir(dst_dir)
    assert report.get("ok") is True

    events_path = dst_dir / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text().splitlines() if line.strip()]
    send_events = [e for e in events if e.get("source") == "agent" and e.get("kind") == "send"]
    assert send_events

    by_kind = {e.get("hook_payload_kind"): e.get("hook_payload") for e in send_events}

    fs_open = by_kind.get("fs-open")
    assert isinstance(fs_open, dict)
    for field in ("symbol", "path", "rv", "errno", "tid"):
        assert field in fs_open

    self_open = by_kind.get("self-open")
    assert isinstance(self_open, dict)
    for field in ("status", "path", "source"):
        assert field in self_open
