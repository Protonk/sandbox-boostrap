"""Headless validation harness for Frida trace runs (schema/query/export)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from book.api import path_utils
from book.api.frida import hook_manifest as hook_manifest_mod
from book.api.frida import normalize as frida_normalize
from book.api.frida import query as frida_query
from book.api.frida import schema_validate
from book.api.frida.export_chrometrace import export_run_dir, validate_chrometrace


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _digest_json(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _sha256_bytes(blob)


def _load_queries(repo_root: Path) -> List[Path]:
    qdir = repo_root / "book/api/frida/queries"
    return [p for p in sorted(qdir.glob("*.sql")) if p.is_file()]


def _check_seq(events: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    for i, ev in enumerate(events):
        if ev.get("seq") != i:
            return False, f"seq mismatch at index {i}"
    return True, None


def _check_run_id(meta_run_id: str, events: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    for i, ev in enumerate(events):
        if ev.get("run_id") != meta_run_id:
            return False, f"run_id mismatch at index {i}"
    return True, None


def _check_non_decreasing_t_ns(events: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
    last: Optional[int] = None
    for i, ev in enumerate(events):
        t_ns = ev.get("t_ns")
        if not isinstance(t_ns, int):
            return False, f"t_ns missing/invalid at index {i}"
        if last is not None and t_ns < last:
            return False, f"t_ns decreased at index {i}"
        last = t_ns
    return True, None


def _load_events(events_path: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    for line in events_path.read_text().splitlines():
        if not line.strip():
            continue
        ev = json.loads(line)
        if not isinstance(ev, dict):
            raise ValueError("event is not an object")
        events.append(ev)
    return events


def _validate_manifest_snapshot(meta: Dict[str, Any]) -> Dict[str, Any]:
    errors: List[str] = []
    script = meta.get("script")
    if not isinstance(script, dict):
        return {"ok": False, "status": "fail", "errors": ["meta.script missing/invalid"]}

    resolved_path = script.get("resolved_path")
    if not isinstance(resolved_path, str) or not resolved_path:
        errors.append("script.resolved_path missing/invalid")

    hook_sha256 = script.get("sha256")
    if not isinstance(hook_sha256, str) or len(hook_sha256) != 64:
        errors.append("script.sha256 missing/invalid (expected 64-hex)")

    manifest_path = script.get("manifest_path")
    if not isinstance(manifest_path, str) or not manifest_path:
        errors.append("script.manifest_path missing/invalid")

    manifest_sha256 = script.get("manifest_sha256")
    if not isinstance(manifest_sha256, str) or len(manifest_sha256) != 64:
        errors.append("script.manifest_sha256 missing/invalid (expected 64-hex)")

    manifest_error = script.get("manifest_error")
    if manifest_error is not None:
        errors.append("script.manifest_error present (manifest snapshot not ok)")

    manifest = script.get("manifest")
    if not isinstance(manifest, dict):
        errors.append("script.manifest missing/invalid (expected manifest object)")
        manifest = None

    if isinstance(manifest, dict):
        violations = schema_validate.validate_hook_manifest_v1(manifest)
        if violations:
            errors.append(f"hook manifest schema violations: {violations}")

        # Identity consistency: hook path in manifest should match the resolved script path.
        hook_obj = manifest.get("hook")
        hook_script_path = hook_obj.get("script_path") if isinstance(hook_obj, dict) else None
        if isinstance(resolved_path, str) and resolved_path and hook_script_path != resolved_path:
            errors.append("manifest.hook.script_path does not match meta.script.resolved_path")

        # Ensure the recorded manifest content hash matches the snapshot content.
        if isinstance(manifest_sha256, str) and len(manifest_sha256) == 64:
            computed = hook_manifest_mod.sha256_canonical_json(manifest)
            if computed != manifest_sha256:
                errors.append("script.manifest_sha256 does not match canonical hash of script.manifest")

    ok = not errors
    return {
        "ok": ok,
        "status": "pass" if ok else "fail",
        "errors": errors,
        "hook": {
            "resolved_path": resolved_path,
            "sha256": hook_sha256,
        },
        "manifest": {
            "path": manifest_path,
            "sha256": manifest_sha256,
        },
    }


def _find_first_runner_event(events: List[Dict[str, Any]], *, kind: str) -> Optional[Dict[str, Any]]:
    for ev in events:
        if ev.get("source") == "runner" and ev.get("kind") == kind:
            return ev
    return None


def _validate_config_snapshot(meta: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    errors: List[str] = []
    script = meta.get("script")
    if not isinstance(script, dict):
        return {"ok": False, "status": "fail", "errors": ["meta.script missing/invalid"]}

    config = script.get("config")
    if not isinstance(config, dict):
        errors.append("script.config missing/invalid (expected object)")
    else:
        if not isinstance(config.get("source"), dict):
            errors.append("script.config.source missing/invalid (expected object)")
        if not isinstance(config.get("value"), dict):
            errors.append("script.config.value missing/invalid (expected object)")

    config_validation = script.get("config_validation")
    if not isinstance(config_validation, dict):
        errors.append("script.config_validation missing/invalid (expected object)")
        config_validation_status = None
    else:
        config_validation_status = config_validation.get("status")
        if config_validation_status not in ("pass", "fail"):
            errors.append("script.config_validation.status must be 'pass' or 'fail'")

    configure = script.get("configure")
    if not isinstance(configure, dict):
        errors.append("script.configure missing/invalid (expected object)")
        configure_status = None
        configure_present = None
    else:
        configure_status = configure.get("status")
        if configure_status not in ("absent", "pass", "fail", "skipped"):
            errors.append("script.configure.status must be one of absent|pass|fail|skipped")
        configure_present = configure.get("present")
        if configure_present is not None and not isinstance(configure_present, bool):
            errors.append("script.configure.present must be boolean or null")
        result = configure.get("result")
        if result is not None and not isinstance(result, dict):
            errors.append("script.configure.result must be an object or null")
        error = configure.get("error")
        if error is not None and not isinstance(error, str):
            errors.append("script.configure.error must be a string or null")

    manifest = script.get("manifest")
    expected_present: Optional[bool] = None
    if not isinstance(manifest, dict):
        errors.append("script.manifest missing/invalid")
    else:
        rpc = manifest.get("rpc")
        if not isinstance(rpc, dict):
            errors.append("script.manifest.rpc missing/invalid")
        else:
            cfg = rpc.get("configure")
            if not isinstance(cfg, dict):
                errors.append("script.manifest.rpc.configure missing/invalid")
            else:
                present = cfg.get("present")
                if isinstance(present, bool):
                    expected_present = present
                else:
                    errors.append("script.manifest.rpc.configure.present missing/invalid")

    config_ev = _find_first_runner_event(events, kind="config-validation")
    if not isinstance(config_ev, dict):
        errors.append("missing runner event: kind=config-validation")
    configure_ev = _find_first_runner_event(events, kind="configure")
    if not isinstance(configure_ev, dict):
        errors.append("missing runner event: kind=configure")

    if config_validation_status == "fail":
        errors.append("config validation failed")

    if expected_present is True:
        if configure_status != "pass":
            errors.append("configure expected present but status != pass")
        if configure_present is not True:
            errors.append("configure expected present but present != true")
    elif expected_present is False:
        if configure_status != "absent":
            errors.append("configure expected absent but status != absent")
        if configure_present is not False:
            errors.append("configure expected absent but present != false")

    ok = not errors
    return {
        "ok": ok,
        "status": "pass" if ok else "fail",
        "errors": errors,
        "expected_configure_present": expected_present,
        "config_validation_status": config_validation_status,
        "configure_status": configure_status,
    }


def trace_product_semantics(meta: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute a pipeline-agnostic digest over trace-product semantics.

    This is used to prove that downstream tooling cannot distinguish authoring
    pipeline (hand-written vs generated vs TS-built) when only trace-product
    invariants are considered.

    Intentionally ignored:
    - run_id
    - seq
    - t_ns
    - pid
    - hook payload contents / kinds
    """
    errors: List[str] = []
    script = meta.get("script")
    if not isinstance(script, dict):
        errors.append("meta.script missing/invalid")
        script = {}

    manifest = script.get("manifest") if isinstance(script, dict) else None
    if not isinstance(manifest, dict):
        errors.append("meta.script.manifest missing/invalid")
        manifest = {}

    schema_name = events[0].get("schema_name") if events else None
    schema_version = events[0].get("schema_version") if events else None

    # Runner event signature stream (no time/pid).
    runner_sequence: List[Dict[str, Any]] = []
    agent_send_count = 0
    for ev in events:
        if not isinstance(ev, dict):
            continue
        source = ev.get("source")
        kind = ev.get("kind")
        if source == "runner":
            if kind == "stage":
                runner = ev.get("runner")
                stage = runner.get("stage") if isinstance(runner, dict) else None
                runner_sequence.append({"kind": "stage", "stage": stage})
            elif kind == "config-validation":
                runner = ev.get("runner")
                status = runner.get("status") if isinstance(runner, dict) else None
                runner_sequence.append({"kind": "config-validation", "status": status})
            elif kind == "configure":
                runner = ev.get("runner")
                status = runner.get("status") if isinstance(runner, dict) else None
                present = runner.get("present") if isinstance(runner, dict) else None
                runner_sequence.append({"kind": "configure", "status": status, "present": present})
            else:
                runner_sequence.append({"kind": kind})
        elif source == "agent" and kind == "send":
            agent_send_count += 1

    rpc_present = None
    rpc = manifest.get("rpc") if isinstance(manifest, dict) else None
    cfg = rpc.get("configure") if isinstance(rpc, dict) else None
    if isinstance(cfg, dict):
        rpc_present = cfg.get("present")

    config_validation_status = None
    configure_status = None
    configure_present = None
    cfg_val = script.get("config_validation") if isinstance(script, dict) else None
    if isinstance(cfg_val, dict):
        config_validation_status = cfg_val.get("status")
    cfg_rec = script.get("configure") if isinstance(script, dict) else None
    if isinstance(cfg_rec, dict):
        configure_status = cfg_rec.get("status")
        configure_present = cfg_rec.get("present")

    semantics = {
        "schema": {"schema_name": schema_name, "schema_version": schema_version},
        "meta": {
            "manifest": {
                "schema_name": manifest.get("schema_name") if isinstance(manifest, dict) else None,
                "schema_version": manifest.get("schema_version") if isinstance(manifest, dict) else None,
                "rpc_configure_present": rpc_present,
            },
            "config_validation_status": config_validation_status,
            "configure": {"status": configure_status, "present": configure_present},
        },
        "events": {"runner_sequence": runner_sequence, "agent_send_count": agent_send_count},
    }

    if agent_send_count < 1:
        errors.append("no agent send() events present")
    if rpc_present is True and configure_status != "pass":
        errors.append("manifest indicates configure present but configure status != pass")

    return {
        "ok": not errors,
        "status": "pass" if not errors else "fail",
        "errors": errors,
        "digest": _digest_json(semantics),
        "semantics": semantics,
    }


def trace_product_semantics_digest(run_dir: Path) -> Dict[str, Any]:
    """Convenience wrapper: normalize + load + compute semantics digest."""
    repo_root = path_utils.find_repo_root()
    run_dir_abs = path_utils.ensure_absolute(run_dir, repo_root)
    frida_normalize.normalize_run_dir(run_dir_abs)
    meta = json.loads((run_dir_abs / "meta.json").read_text())
    events = _load_events(run_dir_abs / "events.jsonl")
    return trace_product_semantics(meta, events)


def validate_run_dir(run_dir: Path) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    run_dir_abs = path_utils.ensure_absolute(run_dir, repo_root)

    normalize_report = frida_normalize.normalize_run_dir(run_dir_abs)

    meta_path = run_dir_abs / "meta.json"
    events_path = run_dir_abs / "events.jsonl"
    meta = json.loads(meta_path.read_text())
    events = _load_events(events_path)

    meta_run_id = meta.get("run_id")
    if not isinstance(meta_run_id, str) or not meta_run_id:
        raise SystemExit(f"meta.json missing run_id: {path_utils.to_repo_relative(meta_path, repo_root)}")

    manifest_snapshot = _validate_manifest_snapshot(meta)
    config_snapshot = _validate_config_snapshot(meta, events)

    schema_report = schema_validate.validate_events_jsonl(events_path)
    seq_ok, seq_err = _check_seq(events)
    rid_ok, rid_err = _check_run_id(meta_run_id, events)
    ts_ok, ts_err = _check_non_decreasing_t_ns(events)

    schema_invariants_ok = bool(
        schema_report.get("ok")
        and seq_ok
        and rid_ok
        and ts_ok
        and manifest_snapshot.get("ok")
        and config_snapshot.get("ok")
    )

    # Query invariants: canned queries must match between direct JSONL and cached index.
    queries = _load_queries(repo_root)
    query_results: Dict[str, Dict[str, Any]] = {}
    direct_digests: Dict[str, str] = {}
    index_digests: Dict[str, str] = {}
    mismatches: List[str] = []

    for qpath in queries:
        sql_text = qpath.read_text()
        direct = frida_query.query_run_dir(run_dir=run_dir_abs, sql=sql_text, use_index=False)
        direct_digests[qpath.name] = _digest_json(direct.get("result"))
        query_results[qpath.name] = {"direct": direct.get("result")}

    index_build = frida_query.build_index(run_dir=run_dir_abs)
    for qpath in queries:
        sql_text = qpath.read_text()
        idx = frida_query.query_run_dir(run_dir=run_dir_abs, sql=sql_text, use_index=True)
        index_digests[qpath.name] = _digest_json(idx.get("result"))
        query_results[qpath.name]["index"] = idx.get("result")
        if query_results[qpath.name]["direct"] != query_results[qpath.name]["index"]:
            mismatches.append(qpath.name)

    query_invariants_ok = (not mismatches) and bool(index_build.get("ok"))

    # Export invariants: deterministic export + structural validation.
    export_report_1 = export_run_dir(run_dir_abs)
    trace_path = run_dir_abs / "trace.chrometrace.json"
    trace_sha_1 = _sha256_file(trace_path)
    export_report_2 = export_run_dir(run_dir_abs)
    trace_sha_2 = _sha256_file(trace_path)
    export_deterministic = trace_sha_1 == trace_sha_2
    trace_validation = validate_chrometrace(trace_path)
    export_invariants_ok = bool(export_deterministic and trace_validation.get("ok"))

    semantics_report = trace_product_semantics(meta, events)

    ok = bool(schema_invariants_ok and query_invariants_ok and export_invariants_ok)
    return {
        "ok": ok,
        "run_dir": path_utils.to_repo_relative(run_dir_abs, repo_root),
        "run_id": meta_run_id,
        "digests": {
            "events_jsonl_sha256": _sha256_file(events_path),
            "chrometrace_json_sha256": trace_sha_2,
        },
        "schema": {
            "ok": schema_invariants_ok,
            "schema_report": schema_report,
            "seq_ok": seq_ok,
            "seq_error": seq_err,
            "run_id_ok": rid_ok,
            "run_id_error": rid_err,
            "t_ns_non_decreasing_ok": ts_ok,
            "t_ns_error": ts_err,
        },
        "manifest_snapshot": manifest_snapshot,
        "config_snapshot": config_snapshot,
        "query": {
            "ok": query_invariants_ok,
            "index_build": index_build,
            "queries": [p.name for p in queries],
            "mismatches": mismatches,
            "digests": {"direct": direct_digests, "index": index_digests},
        },
        "export": {
            "ok": export_invariants_ok,
            "export_report": export_report_1,
            "deterministic": export_deterministic,
            "trace_validation": trace_validation,
        },
        "normalize": normalize_report,
        "semantics": semantics_report,
    }


def validate_run_dirs(run_dirs: Iterable[Path]) -> Dict[str, Any]:
    repo_root = path_utils.find_repo_root()
    results: List[Dict[str, Any]] = []
    for run_dir in run_dirs:
        results.append(validate_run_dir(Path(run_dir)))
    ok = all(r.get("ok") for r in results)
    return {
        "ok": ok,
        "runs": results,
        "repo_root": path_utils.to_repo_relative(repo_root, repo_root),
    }
