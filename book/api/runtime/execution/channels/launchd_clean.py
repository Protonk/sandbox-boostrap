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

from .spec import ChannelSpec


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
LAUNCHCTL = Path("/bin/launchctl")
VENV_PYTHON = Path(".venv/bin/python")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


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
) -> dict:
    # launchd workers must run with a Python that matches the repo's runtime
    # contract. The host /usr/bin/python3 is not reliable for this repo (it may be
    # an older toolchain python). Prefer the staged repo's venv python when present,
    # else fall back to the caller's interpreter.
    staged_venv_python = repo_root / VENV_PYTHON
    program = str(staged_venv_python if staged_venv_python.exists() else sys.executable)
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
    return {
        "Label": label,
        "ProgramArguments": args,
        "RunAtLoad": True,
        "WorkingDirectory": str(repo_root),
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
        "EnvironmentVariables": env,
    }


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
        ".venv",
        ".pytest_cache",
        ".tmp_pytest",
        ".swift-module-cache",
        ".module-cache",
        ".ghidra-user",
        ".DS_Store",
    )
    shutil.copytree(REPO_ROOT, stage_root, symlinks=False, ignore=ignore)

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
    )
    plist_path.write_bytes(plistlib.dumps(plist))

    domain = f"gui/{os.getuid()}"
    try:
        subprocess.run([str(LAUNCHCTL), "bootstrap", domain, str(plist_path)], check=True)
    except Exception as exc:
        raise RuntimeError(f"launchctl bootstrap failed: {exc}") from exc

    _wait_for_output(stdout_path, stderr_path, timeout=60)
    subprocess.run([str(LAUNCHCTL), "bootout", domain, str(plist_path)], check=False)

    # Sync staged outputs back to repo.
    dest_out = path_utils.ensure_absolute(out_dir, REPO_ROOT)
    dest_out.mkdir(parents=True, exist_ok=True)
    shutil.copytree(staged_out, dest_out, dirs_exist_ok=True, ignore=ignore)

    run_dir = dest_out / run_id
    if not run_dir.exists():
        run_dir.mkdir(parents=True, exist_ok=True)
    launchctl_dest = run_dir / "launchctl"
    launchctl_dest.mkdir(parents=True, exist_ok=True)
    for path in (stdout_path, stderr_path, plist_path):
        if path.exists():
            shutil.copy2(path, launchctl_dest / path.name)
    _write_json(
        launchctl_dest / "launchctl_last_run.json",
        {"label": label, "run_id": run_id, "stage_root": str(stage_root)},
    )

    # Best-effort cleanup: staged repos are large and can exhaust /private/tmp
    # quickly during iterative work. Keep the bundle in the repo; discard the
    # staged tree after sync.
    try:
        shutil.rmtree(stage_root)
    except Exception:
        pass
