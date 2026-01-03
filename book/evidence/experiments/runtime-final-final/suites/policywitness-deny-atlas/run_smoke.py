#!/usr/bin/env python3
"""
Smoke pass for the PolicyWitness deny atlas experiment.

This script runs a minimal probe set across a small profile subset and writes:
- runs.jsonl (per-probe ledger)
- deny_atlas.json (summary rows)
- manifest.json (run metadata)
"""

from __future__ import annotations

import argparse
import json
import uuid
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from book.api import path_utils
from book.api.profile.identity import baseline_world_id
from book.api.witness import client, enforcement, outputs, observer as witness_observer


def _load_vocab(path: Path, key: str) -> Dict[str, int]:
    payload = json.loads(path.read_text())
    entries = payload.get(key, [])
    mapping: Dict[str, int] = {}
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            ident = entry.get("id")
            if isinstance(name, str) and isinstance(ident, int):
                mapping[name] = ident
    return mapping


def _extract_meta_lines(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [line for line in text.splitlines() if "MetaData:" in line]


def _extract_metadata_objects(lines: Iterable[str]) -> List[Dict[str, object]]:
    records: List[Dict[str, object]] = []
    for line in lines:
        if "MetaData:" not in line:
            continue
        _, tail = line.split("MetaData:", 1)
        start = tail.find("{")
        end = tail.rfind("}")
        if start == -1 or end == -1 or end <= start:
            continue
        blob = tail[start : end + 1].strip()
        try:
            payload = json.loads(blob)
        except Exception:
            continue
        if isinstance(payload, dict):
            records.append(payload)
    return records


def _parse_deny_line(line: str, filters_map: Dict[str, int]) -> Optional[Tuple[Dict[str, object], bool]]:
    marker = "deny("
    if marker not in line:
        return None
    tail = line.split(marker, 1)[1]
    if ")" not in tail:
        return None
    after = tail.split(")", 1)[1].strip()
    if not after:
        return None
    parts = after.split(maxsplit=1)
    if len(parts) != 2:
        return None
    operation, rest = parts[0], parts[1].strip()
    primary_filter = None
    target = rest
    inferred = False
    if ":" in rest:
        candidate, remainder = rest.split(":", 1)
        if candidate in filters_map:
            primary_filter = candidate
            target = remainder
    if primary_filter is None and operation.startswith("file-") and rest.startswith("/"):
        primary_filter = "path"
        inferred = True
    return (
        {
            "operation": operation,
            "primary-filter": primary_filter,
            "target": target,
        },
        inferred,
    )


def _parse_observer_metadata(
    observer_report: Optional[Dict[str, object]],
    filters_map: Dict[str, int],
) -> Tuple[Optional[Dict[str, object]], bool]:
    if not isinstance(observer_report, dict):
        return None, False
    data = observer_report.get("data")
    if not isinstance(data, dict):
        return None, False
    lines: List[str] = []
    deny_lines = data.get("deny_lines")
    if isinstance(deny_lines, list):
        for entry in deny_lines:
            if isinstance(entry, str):
                lines.append(entry)
    log_stdout = data.get("log_stdout")
    if isinstance(log_stdout, str):
        lines.extend(_extract_meta_lines(log_stdout))
    records = _extract_metadata_objects(lines)
    if records:
        return records[0], False
    if isinstance(deny_lines, list):
        for entry in deny_lines:
            if not isinstance(entry, str):
                continue
            parsed = _parse_deny_line(entry, filters_map)
            if parsed:
                meta, inferred = parsed
                return meta, inferred
    return None, False


def _pick_profiles(profile_ids: List[str], max_count: int) -> List[str]:
    preferred = ["minimal", "net_client", "temporary_exception"]
    picked: List[str] = []
    for prof in preferred:
        if prof in profile_ids and prof not in picked:
            picked.append(prof)
    for prof in profile_ids:
        if len(picked) >= max_count:
            break
        if prof not in picked:
            picked.append(prof)
    return picked


def _probe_set(
    home_dir: Path,
    *,
    include_stateful: bool,
    include_downloads_ladder: bool,
    run_id: str,
) -> List[Dict[str, object]]:
    probes: List[Dict[str, object]] = [
        {
            "label": "fs_op_deny_private_overrides",
            "probe_id": "fs_op",
            "probe_args": [
                "--op",
                "open_read",
                "--path",
                "/private/var/db/launchd.db/com.apple.launchd/overrides.plist",
                "--allow-unsafe-path",
            ],
        },
        {
            "label": "fs_op_allow_hosts",
            "probe_id": "fs_op",
            "probe_args": ["--op", "open_read", "--path", "/etc/hosts", "--allow-unsafe-path"],
        },
        {
            "label": "fs_op_allow_hosts_private",
            "probe_id": "fs_op",
            "probe_args": ["--op", "open_read", "--path", "/private/etc/hosts", "--allow-unsafe-path"],
        },
        {
            "label": "fs_op_allow_tmp_harness",
            "probe_id": "fs_op",
            "probe_args": ["--op", "open_read", "--path-class", "tmp", "--target", "specimen_file"],
        },
        {
            "label": "sandbox_check_hosts",
            "probe_id": "sandbox_check",
            "probe_args": ["--operation", "file-read-data", "--path", "/etc/hosts"],
        },
        {
            "label": "net_op_tcp_connect_control",
            "probe_id": "net_op",
            "probe_args": ["--op", "tcp_connect", "--host", "127.0.0.1", "--port", "9"],
        },
    ]

    safe_suffix = run_id.replace("-", "")[:12]
    if include_stateful:
        probes.append(
            {
                "label": "downloads_rw_probe",
                "probe_id": "downloads_rw",
                "probe_args": ["--name", f"atlas_{safe_suffix}.txt"],
            }
        )
        downloads_dir = home_dir / "Downloads"
        if downloads_dir.exists():
            probes.append(
                {
                    "label": "fs_op_listdir_home_downloads",
                    "probe_id": "fs_op",
                    "probe_args": ["--op", "listdir", "--path", str(downloads_dir), "--allow-unsafe-path"],
                }
            )
        documents_dir = home_dir / "Documents"
        if documents_dir.exists():
            probes.append(
                {
                    "label": "fs_op_listdir_home_documents",
                    "probe_id": "fs_op",
                    "probe_args": ["--op", "listdir", "--path", str(documents_dir), "--allow-unsafe-path"],
                }
            )

    if include_downloads_ladder:
        downloads_name = f"atlas_{safe_suffix}.txt"
        host_downloads = home_dir / "Downloads" / downloads_name
        probes.extend(
            [
                {
                    "label": "fs_op_create_pathclass_downloads",
                    "probe_id": "fs_op",
                    "probe_args": [
                        "--op",
                        "create",
                        "--path-class",
                        "downloads",
                        "--target",
                        "specimen_file",
                        "--name",
                        downloads_name,
                    ],
                },
                {
                    "label": "fs_op_create_direct_downloads",
                    "probe_id": "fs_op",
                    "probe_args": [
                        "--op",
                        "create",
                        "--path",
                        str(host_downloads),
                        "--allow-unsafe-path",
                    ],
                },
                {
                    "label": "fs_coordinated_write_pathclass_downloads",
                    "probe_id": "fs_coordinated_op",
                    "probe_args": [
                        "--op",
                        "write",
                        "--path-class",
                        "downloads",
                        "--target",
                        "specimen_file",
                    ],
                },
                {
                    "label": "sandbox_check_write_host_downloads",
                    "probe_id": "sandbox_check",
                    "probe_args": [
                        "--operation",
                        "file-write-create",
                        "--path",
                        str(host_downloads),
                    ],
                },
            ]
        )

    return probes


def _extract_result_fields(stdout_json: Optional[Dict[str, object]]) -> Dict[str, object]:
    if not isinstance(stdout_json, dict):
        return {}
    result = stdout_json.get("result")
    if not isinstance(result, dict):
        return {}
    normalized_outcome = result.get("normalized_outcome")
    errno = result.get("errno")
    return {
        "normalized_outcome": normalized_outcome if isinstance(normalized_outcome, str) else None,
        "errno": errno if isinstance(errno, int) else None,
    }


def _normalize_path_value(value: Optional[str], home_dir: Path) -> Optional[str]:
    if not isinstance(value, str):
        return None
    home_prefix = str(home_dir)
    if value.startswith(home_prefix + "/"):
        return "$HOME" + value[len(home_prefix) :]
    return value


def _normalize_args(args: Iterable[str], home_dir: Path) -> List[str]:
    return [_normalize_path_value(arg, home_dir) or arg for arg in args]


def _binding_status_and_limits(
    *,
    observed_deny: Optional[bool],
    op_id: Optional[int],
    filter_id: Optional[int],
    observer_present: bool,
    filter_inferred: bool,
) -> tuple[str, List[str]]:
    limits: List[str] = []
    if not observer_present:
        limits.append("observer_missing")
    if observed_deny is not True:
        limits.append("observed_deny_missing_or_false")
    if op_id is None:
        limits.append("operation_unmapped")
    if filter_id is None:
        limits.append("filter_unmapped")
    if filter_inferred:
        limits.append("filter_inferred")
    if observed_deny is True and op_id is not None and filter_id is not None:
        return "resolved", limits
    return "unresolved", limits


def main() -> None:
    parser = argparse.ArgumentParser(description="Smoke pass for policywitness-deny-atlas.")
    parser.add_argument("--out-root", default="book/evidence/experiments/runtime-final-final/suites/policywitness-deny-atlas/out")
    parser.add_argument("--max-profiles", type=int, default=3)
    parser.add_argument("--observer-mode", choices=["manual", "external", "capture"], default="manual")
    parser.add_argument("--capture-sandbox-logs", action="store_true")
    parser.add_argument("--manual-observer-last", default="30s")
    parser.add_argument("--include-stateful-probes", action="store_true")
    parser.add_argument("--include-downloads-ladder", action="store_true")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__))
    world_id = baseline_world_id(repo_root)

    out_root = path_utils.ensure_absolute(Path(args.out_root), repo_root)
    run_id = f"smoke-{uuid.uuid4()}"
    run_root = out_root / run_id
    run_root.mkdir(parents=True, exist_ok=True)
    output_spec = outputs.OutputSpec(bundle_root=out_root, bundle_run_id=run_id)
    home_dir = Path.home()

    ops_map = _load_vocab(repo_root / "book/integration/carton/bundle/relationships/mappings/vocab/ops.json", "ops")
    filters_map = _load_vocab(repo_root / "book/integration/carton/bundle/relationships/mappings/vocab/filters.json", "filters")

    profiles = client.list_profiles()
    profiles_data = profiles.get("stdout_json", {}).get("data", {})
    profiles_list = profiles_data.get("profiles", []) if isinstance(profiles_data, dict) else []
    profile_ids: List[str] = []
    for entry in profiles_list:
        if not isinstance(entry, dict):
            continue
        if entry.get("kind") != "probe":
            continue
        prof_id = entry.get("profile_id")
        if isinstance(prof_id, str) and prof_id not in profile_ids:
            profile_ids.append(prof_id)

    smoke_profiles = _pick_profiles(profile_ids, args.max_profiles)
    plan_id = f"policywitness-deny-atlas:smoke:{run_id}"

    runs_path = run_root / "runs.jsonl"
    atlas_records: List[Dict[str, object]] = []

    manual_last = args.manual_observer_last
    if isinstance(manual_last, str) and manual_last.strip().lower() in {"off", "none"}:
        manual_last = None

    observer_mode = args.observer_mode
    capture_logs = args.capture_sandbox_logs or observer_mode == "capture"

    with runs_path.open("w", encoding="utf-8") as runs_file:
        for profile_id in smoke_profiles:
            for probe in _probe_set(
                home_dir,
                include_stateful=args.include_stateful_probes,
                include_downloads_ladder=args.include_downloads_ladder,
                run_id=run_id,
            ):
                label = probe["label"]
                row_id = f"{profile_id}.{label}"
                run_args = probe["probe_args"]
                result = client.run_probe(
                    profile_id=profile_id,
                    probe_id=probe["probe_id"],
                    probe_args=run_args,
                    plan_id=plan_id,
                    row_id=row_id,
                    output=output_spec,
                    capture_sandbox_logs=capture_logs,
                    observer=observer_mode == "external",
                )
                result_json = result.to_json()
                observer_report = None
                observer_report_path = None
                observer_meta = None
                if observer_mode == "capture":
                    stdout_json = result.stdout_json or {}
                    data = stdout_json.get("data") if isinstance(stdout_json, dict) else None
                    if isinstance(data, dict):
                        capture = data.get("host_sandbox_log_capture")
                        if isinstance(capture, dict):
                            observer_report = capture.get("observer_report")
                elif observer_mode == "manual":
                    pid = witness_observer.extract_service_pid(result.stdout_json)
                    name = witness_observer.extract_process_name(result.stdout_json)
                    correlation_id = result.correlation_id or witness_observer.extract_correlation_id(
                        result.stdout_json
                    )
                    obs_dir = run_root / "manual_observer"
                    obs_path = obs_dir / f"{row_id}.observer.json"
                    observer_meta = witness_observer.run_sandbox_log_observer(
                        pid=pid,
                        process_name=name,
                        dest_path=obs_path,
                        last=manual_last or "30s",
                        plan_id=plan_id,
                        row_id=row_id,
                        correlation_id=correlation_id,
                    )
                    if isinstance(observer_meta, dict):
                        observer_report = observer_meta.get("report")
                        observer_report_path = observer_meta.get("log_path")
                elif isinstance(result.observer, dict):
                    observer_report = result.observer.get("report")
                    observer_report_path = result.observer_log_path

                meta, filter_inferred = _parse_observer_metadata(observer_report, filters_map)
                operation = None
                primary_filter = None
                target = None
                if isinstance(meta, dict):
                    op_value = meta.get("operation")
                    filter_value = meta.get("primary-filter")
                    target_value = meta.get("primary-filter-value") or meta.get("target")
                    operation = op_value if isinstance(op_value, str) else None
                    primary_filter = filter_value if isinstance(filter_value, str) else None
                    target = target_value if isinstance(target_value, str) else None

                op_id = ops_map.get(operation) if operation else None
                filter_id = filters_map.get(primary_filter) if primary_filter else None

                detail = enforcement.enforcement_detail(
                    stdout_json=result.stdout_json,
                    observer_report=observer_report,
                )
                detail_json = detail.to_json()

                binding_status, limits = _binding_status_and_limits(
                    observed_deny=detail_json.get("observed_deny"),
                    op_id=op_id,
                    filter_id=filter_id,
                    observer_present=observer_report is not None,
                    filter_inferred=filter_inferred,
                )

                result_fields = _extract_result_fields(result.stdout_json)
                record = {
                    "schema_version": 1,
                    "world_id": world_id,
                    "profile_id": profile_id,
                    "probe_id": probe["probe_id"],
                    "probe_args": _normalize_args(run_args, home_dir),
                    "plan_id": plan_id,
                    "row_id": row_id,
                    "stage": "operation",
                    "lane": "scenario",
                    "normalized_outcome": result_fields.get("normalized_outcome"),
                    "errno": result_fields.get("errno"),
                    "observed_deny": detail_json.get("observed_deny"),
                    "operation": operation,
                    "operation_id": op_id,
                    "filter": primary_filter,
                    "filter_id": filter_id,
                    "target": _normalize_path_value(target, home_dir),
                    "binding_status": binding_status,
                    "limits": limits,
                    "observer_mode": observer_mode,
                    "probe_log_path": result.log_path,
                    "observer_report_path": observer_report_path,
                }
                runs_file.write(
                    json.dumps(
                        {
                            "record": record,
                            "probe_result": result_json,
                            "observer_meta": observer_meta,
                        }
                    )
                    + "\n"
                )
                atlas_records.append(record)

    atlas = {
        "schema_version": 1,
        "world_id": world_id,
        "plan_id": plan_id,
        "records": atlas_records,
    }
    (run_root / "deny_atlas.json").write_text(json.dumps(atlas, indent=2, sort_keys=True) + "\n")

    manifest = {
        "schema_version": 1,
        "world_id": world_id,
        "run_id": run_id,
        "plan_id": plan_id,
        "profiles": smoke_profiles,
        "probe_set": _probe_set(
            home_dir,
            include_stateful=args.include_stateful_probes,
            include_downloads_ladder=args.include_downloads_ladder,
            run_id=run_id,
        ),
        "observer_mode": observer_mode,
        "manual_observer_last": manual_last,
        "capture_sandbox_logs": capture_logs,
        "include_stateful_probes": args.include_stateful_probes,
        "include_downloads_ladder": args.include_downloads_ladder,
        "runs_path": path_utils.to_repo_relative(runs_path, repo_root),
        "atlas_path": path_utils.to_repo_relative(run_root / "deny_atlas.json", repo_root),
        "probe_output_dir": path_utils.to_repo_relative(run_root, repo_root),
    }
    (run_root / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(path_utils.to_repo_relative(run_root, repo_root))


if __name__ == "__main__":
    main()
