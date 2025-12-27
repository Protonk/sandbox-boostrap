"""
Launchd clean channel runner for runtime_tools plans.
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
PYTHON = Path("/usr/bin/python3")


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
    program = str(PYTHON if PYTHON.exists() else sys.executable)
    args = [program, "-m", "book.api.runtime_tools", "run", "--plan", str(plan_path), "--out", str(out_dir)]
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
    if not LAUNCHCTL.exists():
        raise RuntimeError("launchctl missing")

    run_id = run_id or str(time.time_ns())
    label = f"{channel_spec.label_prefix}.{run_id}"
    stage_root = channel_spec.staging_base / label
    stage_root.parent.mkdir(parents=True, exist_ok=True)
    if stage_root.exists():
        shutil.rmtree(stage_root)

    ignore = shutil.ignore_patterns(".git", "__pycache__", "launchctl")
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

    launchctl_dest = dest_out / "launchctl"
    launchctl_dest.mkdir(parents=True, exist_ok=True)
    for path in (stdout_path, stderr_path, plist_path):
        if path.exists():
            shutil.copy2(path, launchctl_dest / path.name)
    _write_json(
        launchctl_dest / "launchctl_last_run.json",
        {"label": label, "run_id": run_id, "stage_root": str(stage_root)},
    )
