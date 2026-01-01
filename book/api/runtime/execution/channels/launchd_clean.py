"""
Runtime launchd_clean channel runner (service contract).

This module provides the canonical "clean" execution channel for runtime
plan runs. It:
- Stages the repo under a per-run directory (default: /private/tmp/...).
- Uses launchctl to run a fresh Python worker in that staged repo so the worker
  starts from a clean (unsandboxed) process context on this host.
- Syncs the staged `out/<run_id>/...` bundle back into the original repo output
  root and records launchctl stdout/stderr and the job plist as diagnostics.

Assumptions:
- The plan run is driven through `python -m book.api.runtime run --plan ...`
  inside the staged repo with `PYTHONPATH` set to the staged repo root.
- The caller chooses the output root and holds any bundle-root lock; this module
  focuses only on staging and launchd execution.

Guarantees:
- The staged run has a stable provenance stamp via environment markers
  (`SANDBOX_LORE_LAUNCHD_CLEAN`, staging root, output root).
- Staged artifacts are copied back into the original output root without
  rewriting their contents (copy-only synchronization).

Refusals:
- This module does not interpret runtime evidence, does not validate bundles,
  and does not build mappings. It only produces a clean-provenance run.

macOS Seatbelt decisions depend on process state. Launchd gives us
a reliable way to start unsandboxed, which is critical for decision-stage runs.
"""

from __future__ import annotations

import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Iterable, Optional

from book.api import path_utils
from book.api.runtime.bundles import writer as bundle_writer

from .spec import ChannelSpec


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
LAUNCHCTL = Path("/bin/launchctl")
VENV_PYTHON = Path(".venv/bin/python")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _capture_command(
    argv: list[str],
    *,
    stdout_path: Optional[Path] = None,
    stderr_path: Optional[Path] = None,
) -> dict:
    result = subprocess.run(argv, capture_output=True, text=True)
    if stdout_path is not None:
        _write_text(stdout_path, result.stdout)
    if stderr_path is not None:
        _write_text(stderr_path, result.stderr)
    return {
        "argv": path_utils.relativize_command(argv, REPO_ROOT),
        "rc": result.returncode,
        "stdout_path": path_utils.to_repo_relative(stdout_path, REPO_ROOT) if stdout_path else None,
        "stderr_path": path_utils.to_repo_relative(stderr_path, REPO_ROOT) if stderr_path else None,
    }


def _build_plist(
    *,
    label: str,
    stdout_path: Path,
    stderr_path: Path,
    repo_root: Path,
    run_id: str,
    plan_path: Path,
    out_dir: Path,
    only_profiles: Optional[Iterable[str]],
    only_scenarios: Optional[Iterable[str]],
    limit_load_to_session_types: Optional[list[str]] = None,
) -> dict:
    # launchd workers must run with a Python that matches the repo's runtime
    # contract. The host /usr/bin/python3 is not reliable for this repo (it may be
    # an older toolchain python). Prefer the staged repo's venv python when present,
    # else fall back to the caller's interpreter.
    staged_venv_python = repo_root / VENV_PYTHON
    if staged_venv_python.exists():
        program = str(staged_venv_python)
    else:
        candidate = Path(sys.executable)
        # When the repo lives under Desktop/Documents, the launchd worker may not
        # have TCC access to the venv path. Prefer the resolved base interpreter
        # when the candidate lives under the repo root or user home.
        repo_root_abs = REPO_ROOT
        home_root = Path.home()
        if repo_root_abs in candidate.parents or home_root in candidate.parents:
            resolved = Path(os.path.realpath(candidate))
            if resolved.exists():
                candidate = resolved
        program = str(candidate)
    args = [program, "-m", "book.api.runtime", "run", "--plan", str(plan_path), "--out", str(out_dir)]
    args += ["--channel", "direct"]
    if only_profiles:
        for pid in only_profiles:
            args += ["--only-profile", pid]
    if only_scenarios:
        for sid in only_scenarios:
            args += ["--only-scenario", sid]
    env = {
        "PYTHONPATH": str(repo_root),
        "SANDBOX_LORE_RUN_ID": run_id,
        "SANDBOX_LORE_LAUNCHD_CLEAN": "1",
        "SANDBOX_LORE_CHANNEL": "launchd_clean",
        "SANDBOX_LORE_STAGE_USED": "1",
        "SANDBOX_LORE_STAGE_ROOT": str(repo_root),
        "SANDBOX_LORE_STAGE_OUTPUT_ROOT": str(out_dir),
    }
    # Forward opt-in debug knobs to the staged worker. These must remain
    # explicitly opt-in (unset by default) so promotability and lane semantics
    # are not accidentally influenced by the parent shell environment.
    for key in [
        "SANDBOX_LORE_SEATBELT_CALLOUT",
        "SANDBOX_LORE_SEATBELT_API",
        "SANDBOX_LORE_PREFLIGHT",
        "SANDBOX_LORE_PREFLIGHT_FORCE",
        "SANDBOX_LORE_FILE_PRECREATE",
        "SANDBOX_LORE_IOKIT_ORACLE_ONLY",
        "SANDBOX_LORE_IKIT_SELECTOR_LIST",
        "SANDBOX_LORE_IKIT_CALL_KIND",
        "SANDBOX_LORE_IKIT_CALL_IN_SCALARS",
        "SANDBOX_LORE_IKIT_CALL_IN_STRUCT_BYTES",
        "SANDBOX_LORE_IKIT_CALL_OUT_SCALARS",
        "SANDBOX_LORE_IKIT_CALL_OUT_STRUCT_BYTES",
        "SANDBOX_LORE_IKIT_SYNTH_CALL",
        "SANDBOX_LORE_IKIT_CAPTURE_CALLS",
        "SANDBOX_LORE_IKIT_REPLAY",
        "SANDBOX_LORE_IKIT_REPLAY_SPEC",
        "SANDBOX_LORE_IKIT_SWEEP",
        "SANDBOX_LORE_IKIT_MACH_CAPTURE",
        "SANDBOX_LORE_IKIT_METHOD0",
        "SANDBOX_LORE_IKIT_METHOD0_PAYLOAD_IN",
        "SANDBOX_LORE_IKIT_METHOD0_PAYLOAD_OUT",
        "SBL_IKIT_SKIP_SWEEP",
    ]:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    payload = {
        "Label": label,
        "ProgramArguments": args,
        "RunAtLoad": True,
        "WorkingDirectory": str(repo_root),
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
        "EnvironmentVariables": env,
    }
    if limit_load_to_session_types:
        payload["LimitLoadToSessionType"] = limit_load_to_session_types
    return payload


def _refresh_artifact_index(run_dir: Path, *, repo_root: Path, updated_paths: Iterable[Path]) -> None:
    index_path = run_dir / "artifact_index.json"
    if not index_path.exists():
        return
    index = json.loads(index_path.read_text(encoding="utf-8", errors="ignore"))
    updated = {path_utils.ensure_absolute(p, repo_root) for p in updated_paths}
    for entry in index.get("artifacts") or []:
        rel = entry.get("path")
        if not rel:
            continue
        path = path_utils.ensure_absolute(Path(rel), repo_root)
        if path not in updated or not path.exists():
            continue
        entry["file_size"] = path.stat().st_size
        entry["sha256"] = bundle_writer.sha256_path(path)
    bundle_writer.write_json_atomic(index_path, index)


def _wait_for_output(stdout_path: Path, stderr_path: Path, timeout: float) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        # Any output indicates the job has started and is reachable.
        if stdout_path.exists() and stdout_path.stat().st_size > 0:
            return True
        if stderr_path.exists() and stderr_path.stat().st_size > 0:
            return True
        time.sleep(0.5)
    return False


def _domain_label(domain: str) -> str:
    return domain.replace("/", "_")


def _check_domain(domain: str, launchctl_dest: Path, label: str) -> dict:
    tag = _domain_label(domain)
    stdout_path = launchctl_dest / f"{label}.launchctl_print.{tag}.stdout.txt"
    stderr_path = launchctl_dest / f"{label}.launchctl_print.{tag}.stderr.txt"
    return _capture_command([str(LAUNCHCTL), "print", domain], stdout_path=stdout_path, stderr_path=stderr_path)


def run_via_launchctl(
    *,
    plan_path: Path,
    out_dir: Path,
    channel_spec: ChannelSpec,
    only_profiles: Optional[Iterable[str]] = None,
    only_scenarios: Optional[Iterable[str]] = None,
    run_id: Optional[str] = None,
) -> None:
    """Stage the repo and run a plan via launchd for a clean process context."""
    if not LAUNCHCTL.exists():
        raise RuntimeError("launchctl missing")

    run_id = run_id or str(time.time_ns())
    label = f"{channel_spec.label_prefix}.{run_id}"
    stage_root = channel_spec.staging_base / label
    stage_root.parent.mkdir(parents=True, exist_ok=True)
    if stage_root.exists():
        shutil.rmtree(stage_root)

    # Stage only what the worker needs. This must stay conservative, but we
    # aggressively exclude large, non-essential trees to keep staging fast and
    # avoid exhausting `/private/tmp`.
    ignore = shutil.ignore_patterns(
        ".git",
        "__pycache__",
        "launchctl",
        "dumps",
        "out",
        ".venv",
        ".pytest_cache",
        ".tmp_pytest",
        ".swift-module-cache",
        ".module-cache",
        ".ghidra-user",
        ".DS_Store",
    )
    shutil.copytree(REPO_ROOT, stage_root, symlinks=False, ignore=ignore)

    dest_out = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    dest_out.mkdir(parents=True, exist_ok=True)
    run_dir = dest_out / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    launchctl_dest = run_dir / "launchctl"
    launchctl_dest.mkdir(parents=True, exist_ok=True)

    plan_rel = path_utils.to_repo_relative(plan_path, repo_root=REPO_ROOT)
    out_rel = path_utils.to_repo_relative(out_dir, repo_root=REPO_ROOT)
    staged_plan = stage_root / plan_rel
    staged_out = stage_root / out_rel
    staged_out.mkdir(parents=True, exist_ok=True)

    launchctl_dir = staged_out / "launchctl"
    launchctl_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = launchctl_dir / f"{label}.stdout.txt"
    stderr_path = launchctl_dir / f"{label}.stderr.txt"
    plist_path = launchctl_dir / f"{label}.plist"

    uid = os.getuid()
    gui_domain = f"gui/{uid}"
    user_domain = f"user/{uid}"
    domain_check = _check_domain(gui_domain, launchctl_dest, label)
    if domain_check["rc"] == 0:
        domain = gui_domain
        domain_reason = "gui_domain_available"
        session_types = None
    else:
        domain = user_domain
        domain_reason = "gui_domain_unavailable"
        session_types = ["Background"]

    plist = _build_plist(
        label=label,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        repo_root=stage_root,
        run_id=run_id,
        plan_path=staged_plan,
        out_dir=staged_out,
        only_profiles=only_profiles,
        only_scenarios=only_scenarios,
        limit_load_to_session_types=session_types,
    )
    plist_path.write_bytes(plistlib.dumps(plist))

    plist_dest = launchctl_dest / plist_path.name
    shutil.copy2(plist_path, plist_dest)
    lint_stdout = launchctl_dest / f"{label}.plutil_lint.stdout.txt"
    lint_stderr = launchctl_dest / f"{label}.plutil_lint.stderr.txt"
    plutil_lint = _capture_command(
        ["/usr/bin/plutil", "-lint", str(plist_path)],
        stdout_path=lint_stdout,
        stderr_path=lint_stderr,
    )

    bootstrap_stdout = launchctl_dest / f"{label}.bootstrap.stdout.txt"
    bootstrap_stderr = launchctl_dest / f"{label}.bootstrap.stderr.txt"
    bootstrap_cmd = [str(LAUNCHCTL), "bootstrap", domain, str(plist_path)]
    bootstrap = _capture_command(bootstrap_cmd, stdout_path=bootstrap_stdout, stderr_path=bootstrap_stderr)

    launchctl_cmds: list[dict] = [domain_check, plutil_lint, bootstrap]
    diagnostics = {
        "label": label,
        "run_id": run_id,
        "domain": domain,
        "domain_reason": domain_reason,
        "session_types": session_types,
        "plist_path": path_utils.to_repo_relative(plist_dest, REPO_ROOT),
        "launchctl_cmds": launchctl_cmds,
    }

    if bootstrap["rc"] != 0:
        log_stdout = launchctl_dest / f"{label}.launchd_logshow.stdout.txt"
        log_stderr = launchctl_dest / f"{label}.launchd_logshow.stderr.txt"
        log_show = _capture_command(
            [
                "/usr/bin/log",
                "show",
                "--last",
                "2m",
                "--predicate",
                'subsystem == "com.apple.xpc.launchd" || process == "launchd"',
            ],
            stdout_path=log_stdout,
            stderr_path=log_stderr,
        )
        diagnostics["log_show"] = log_show
        if plutil_lint["rc"] != 0:
            classification = "plist_invalid"
        elif domain_reason == "gui_domain_unavailable" and domain == user_domain:
            classification = "domain_session_mismatch"
        elif not os.access(plist_path, os.R_OK):
            classification = "plist_unreadable"
        else:
            classification = "bootstrap_failed"
        diagnostics["bootstrap_failure"] = {
            "classification": classification,
            "rc": bootstrap["rc"],
        }
        _write_json(launchctl_dest / "launchctl_diagnostics.json", diagnostics)
        raise RuntimeError(f"launchctl bootstrap failed: rc={bootstrap['rc']} ({classification})")

    _wait_for_output(stdout_path, stderr_path, timeout=60)
    bootout_stdout = launchctl_dest / f"{label}.bootout.stdout.txt"
    bootout_stderr = launchctl_dest / f"{label}.bootout.stderr.txt"
    bootout = _capture_command(
        [str(LAUNCHCTL), "bootout", domain, str(plist_path)],
        stdout_path=bootout_stdout,
        stderr_path=bootout_stderr,
    )
    launchctl_cmds.append(bootout)

    # Sync staged outputs back to repo.
    shutil.copytree(staged_out, dest_out, dirs_exist_ok=True, ignore=ignore)

    for path in (stdout_path, stderr_path, plist_path):
        if path.exists():
            shutil.copy2(path, launchctl_dest / path.name)
    _write_json(
        launchctl_dest / "launchctl_last_run.json",
        {"label": label, "run_id": run_id, "stage_root": str(stage_root)},
    )
    _write_json(launchctl_dest / "launchctl_diagnostics.json", diagnostics)

    status_path = run_dir / "run_status.json"
    if status_path.exists():
        status = json.loads(status_path.read_text())
        status["launchctl_diagnostics"] = path_utils.to_repo_relative(
            launchctl_dest / "launchctl_diagnostics.json",
            REPO_ROOT,
        )
        _write_json(status_path, status)
        _refresh_artifact_index(run_dir, repo_root=REPO_ROOT, updated_paths=[status_path])

    # Best-effort cleanup: staged repos are large and can exhaust /private/tmp
    # quickly during iterative work. Keep the bundle in the repo; discard the
    # staged tree after sync.
    try:
        shutil.rmtree(stage_root)
    except Exception:
        pass
