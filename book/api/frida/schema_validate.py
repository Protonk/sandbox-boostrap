"""Headless schema checks for Frida trace products."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api.frida import trace_v1
from book.api import path_utils


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def validate_trace_event_v1(event: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(event, dict):
        return ["event must be a JSON object"]

    if event.get("schema_name") != trace_v1.TRACE_EVENT_SCHEMA_NAME:
        errors.append("schema_name mismatch")
    if event.get("schema_version") != trace_v1.TRACE_EVENT_SCHEMA_VERSION:
        errors.append("schema_version mismatch")

    run_id = event.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        errors.append("run_id must be a non-empty string")

    seq = event.get("seq")
    if not _is_int(seq) or seq < 0:
        errors.append("seq must be an int >= 0")

    t_ns = event.get("t_ns")
    if not _is_int(t_ns) or t_ns < 0:
        errors.append("t_ns must be an int >= 0")

    pid = event.get("pid")
    if pid is not None and (not _is_int(pid) or pid < 0):
        errors.append("pid must be an int >= 0 or null")

    source = event.get("source")
    if source not in ("runner", "agent"):
        errors.append("source must be 'runner' or 'agent'")

    kind = event.get("kind")
    if not isinstance(kind, str) or not kind:
        errors.append("kind must be a non-empty string")

    if source == "runner":
        runner = event.get("runner")
        if not isinstance(runner, dict):
            errors.append("runner event must include runner object")
        if "agent" in event:
            errors.append("runner event must not include agent")
        if "hook_payload" in event:
            errors.append("runner event must not include hook_payload")
    elif source == "agent":
        agent = event.get("agent")
        if not isinstance(agent, dict):
            errors.append("agent event must include agent object")
        if "runner" in event:
            errors.append("agent event must not include runner")
        hook_payload = event.get("hook_payload", None)
        if kind == "send" and "hook_payload" not in event:
            errors.append("send events must include hook_payload (may be null)")
        if "hook_payload" in event and kind != "send":
            errors.append("hook_payload is only valid for kind == 'send'")

        hook_payload_kind = event.get("hook_payload_kind", None)
        if hook_payload_kind is not None and not isinstance(hook_payload_kind, str):
            errors.append("hook_payload_kind must be a string or null")
        if isinstance(hook_payload, dict) and isinstance(hook_payload.get("kind"), str):
            expected = hook_payload["kind"]
            if hook_payload_kind is not None and hook_payload_kind != expected:
                errors.append("hook_payload_kind must match hook_payload.kind when present")

    return errors


def validate_events_jsonl(events_path: Path) -> Dict[str, Any]:
    errors: List[Dict[str, Any]] = []
    count = 0
    for idx, line in enumerate(events_path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        count += 1
        try:
            event = json.loads(line)
        except Exception as exc:
            errors.append({"line": idx, "error": f"invalid json: {type(exc).__name__}: {exc}"})
            continue
        ev_errors = validate_trace_event_v1(event)
        if ev_errors:
            errors.append({"line": idx, "error": "schema violations", "violations": ev_errors})
    return {"event_count": count, "ok": not errors, "errors": errors}


def _repo_rel(path: Path, repo_root: Path) -> str:
    return path_utils.to_repo_relative(path, repo_root)


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


HOOK_MANIFEST_SCHEMA_NAME = "book.api.frida.hook_manifest"
HOOK_MANIFEST_SCHEMA_VERSION = 1


def validate_hook_manifest_v1(manifest: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(manifest, dict):
        return ["manifest must be a JSON object"]

    allowed_top_keys = {
        "schema_name",
        "schema_version",
        "hook",
        "trace_event_schema",
        "rpc_exports",
        "configure",
        "module_expectations",
        "send_payload_kinds",
    }
    extra_top = sorted(set(manifest.keys()) - allowed_top_keys)
    if extra_top:
        errors.append(f"unexpected top-level keys: {extra_top}")

    if manifest.get("schema_name") != HOOK_MANIFEST_SCHEMA_NAME:
        errors.append("schema_name mismatch")
    if manifest.get("schema_version") != HOOK_MANIFEST_SCHEMA_VERSION:
        errors.append("schema_version mismatch")

    hook = manifest.get("hook")
    if not isinstance(hook, dict):
        errors.append("hook must be an object")
    else:
        allowed_hook_keys = {"id", "script_path", "summary"}
        extra_hook = sorted(set(hook.keys()) - allowed_hook_keys)
        if extra_hook:
            errors.append(f"hook has unexpected keys: {extra_hook}")
        hid = hook.get("id")
        if not isinstance(hid, str) or not hid:
            errors.append("hook.id must be a non-empty string")
        sp = hook.get("script_path")
        if not isinstance(sp, str) or not sp:
            errors.append("hook.script_path must be a non-empty string")
        elif sp.startswith("/"):
            errors.append("hook.script_path must be repo-relative, not absolute")
        summary = hook.get("summary")
        if summary is not None and not isinstance(summary, str):
            errors.append("hook.summary must be a string when present")

    tes = manifest.get("trace_event_schema")
    if not isinstance(tes, dict):
        errors.append("trace_event_schema must be an object")
    else:
        if tes.get("schema_name") != trace_v1.TRACE_EVENT_SCHEMA_NAME:
            errors.append("trace_event_schema.schema_name mismatch")
        if tes.get("schema_version") != trace_v1.TRACE_EVENT_SCHEMA_VERSION:
            errors.append("trace_event_schema.schema_version mismatch")

    rpc_exports = manifest.get("rpc_exports")
    if not isinstance(rpc_exports, list) or not all(isinstance(x, str) for x in rpc_exports):
        errors.append("rpc_exports must be a list of strings")

    configure = manifest.get("configure")
    if not isinstance(configure, dict):
        errors.append("configure must be an object")
    else:
        allowed_cfg_keys = {"supported", "input_schema"}
        extra_cfg = sorted(set(configure.keys()) - allowed_cfg_keys)
        if extra_cfg:
            errors.append(f"configure has unexpected keys: {extra_cfg}")
        supported = configure.get("supported")
        if not isinstance(supported, bool):
            errors.append("configure.supported must be boolean")
        input_schema = configure.get("input_schema")
        if not isinstance(input_schema, dict):
            errors.append("configure.input_schema must be an object (JSON Schema)")
        if isinstance(supported, bool) and isinstance(rpc_exports, list):
            if supported and "configure" not in rpc_exports:
                errors.append("configure.supported true but rpc_exports missing 'configure'")
            if (not supported) and "configure" in rpc_exports:
                errors.append("configure.supported false but rpc_exports includes 'configure'")

    module_expectations = manifest.get("module_expectations")
    if not isinstance(module_expectations, list):
        errors.append("module_expectations must be a list")
    else:
        for i, m in enumerate(module_expectations):
            if not isinstance(m, dict):
                errors.append(f"module_expectations[{i}] must be an object")
                continue
            allowed_mod_keys = {"name", "required"}
            extra_mod = sorted(set(m.keys()) - allowed_mod_keys)
            if extra_mod:
                errors.append(f"module_expectations[{i}] unexpected keys: {extra_mod}")
            name = m.get("name")
            if not isinstance(name, str) or not name:
                errors.append(f"module_expectations[{i}].name must be a non-empty string")
            req = m.get("required")
            if req is not None and not isinstance(req, bool):
                errors.append(f"module_expectations[{i}].required must be boolean when present")

    spk = manifest.get("send_payload_kinds")
    if spk is not None:
        if not isinstance(spk, list) or not all(isinstance(x, str) and x for x in spk):
            errors.append("send_payload_kinds must be a list of non-empty strings when present")

    return errors


def validate_hook_manifest_file(manifest_path: Path) -> Dict[str, Any]:
    raw = manifest_path.read_bytes()
    try:
        data = json.loads(raw)
    except Exception as exc:
        return {
            "ok": False,
            "path": str(manifest_path),
            "sha256": _sha256_bytes(raw),
            "error": f"invalid json: {type(exc).__name__}: {exc}",
            "violations": ["manifest must be valid JSON"],
        }
    violations = validate_hook_manifest_v1(data)
    return {
        "ok": not violations,
        "path": str(manifest_path),
        "sha256": _sha256_bytes(raw),
        "error": None,
        "violations": violations,
    }


def validate_hook_manifests_tree(hooks_dir: Path) -> Dict[str, Any]:
    reports: List[Dict[str, Any]] = []
    for path in sorted(hooks_dir.glob("*.manifest.json")):
        if not path.is_file():
            continue
        reports.append(validate_hook_manifest_file(path))
    ok = all(r.get("ok") for r in reports) and bool(reports)
    return {"ok": ok, "manifest_count": len(reports), "manifests": reports}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--examples",
        action="store_true",
        help="Validate the checked-in trace v1 examples JSON",
    )
    ap.add_argument(
        "--hook-manifests",
        action="store_true",
        help="Validate all hook manifests under book/api/frida/hooks/*.manifest.json",
    )
    ap.add_argument(
        "--events-jsonl",
        help="Validate a specific events.jsonl path against the trace v1 envelope",
    )
    ap.add_argument(
        "--run-dir",
        help="Validate <run_dir>/events.jsonl against the trace v1 envelope",
    )
    args = ap.parse_args(argv)

    repo_root = path_utils.find_repo_root()
    reports: List[Dict[str, Any]] = []

    if args.examples:
        examples_path = repo_root / "book/api/frida/schemas/trace_event_v1.examples.json"
        events = json.loads(examples_path.read_text())
        if not isinstance(events, list):
            raise SystemExit("examples file must be a JSON array")
        errors: List[Dict[str, Any]] = []
        for idx, ev in enumerate(events):
            ev_errors = validate_trace_event_v1(ev)
            if ev_errors:
                errors.append({"index": idx, "error": "schema violations", "violations": ev_errors})
        reports.append(
            {
                "kind": "examples",
                "path": _repo_rel(examples_path, repo_root),
                "event_count": len(events),
                "ok": not errors,
                "errors": errors,
            }
        )

    if args.hook_manifests:
        hooks_dir = repo_root / "book/api/frida/hooks"
        res = validate_hook_manifests_tree(hooks_dir)
        # Repo-relativize manifest paths for stable output.
        for m in res.get("manifests") or []:
            if isinstance(m, dict) and isinstance(m.get("path"), str):
                m["path"] = _repo_rel(Path(m["path"]), repo_root)
        reports.append(
            {
                "kind": "hook_manifests",
                "hooks_dir": _repo_rel(hooks_dir, repo_root),
                **res,
            }
        )

    events_path: Path | None = None
    if args.events_jsonl:
        events_path = path_utils.ensure_absolute(args.events_jsonl, repo_root)
    elif args.run_dir:
        run_dir = path_utils.ensure_absolute(args.run_dir, repo_root)
        events_path = run_dir / "events.jsonl"

    if events_path is not None:
        reports.append(
            {
                "kind": "events_jsonl",
                "path": _repo_rel(events_path, repo_root),
                **validate_events_jsonl(events_path),
            }
        )

    ok = all(r.get("ok") for r in reports) if reports else False
    out = {"ok": ok, "reports": reports}
    sys.stdout.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
