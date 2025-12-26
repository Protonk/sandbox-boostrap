#!/usr/bin/env python3
"""
Launch runtime-checks via launchctl to avoid inheriting a sandboxed parent.
"""
from __future__ import annotations

import argparse
import json
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils

LAUNCHCTL = Path("/bin/launchctl")
PYTHON = Path("/usr/bin/python3")
RUNNER = Path(__file__).with_name("run_probes.py")
OUT_ROOT = Path(__file__).with_name("out")
LAUNCHCTL_DIR = OUT_ROOT / "launchctl"
STAGING_BASE = Path("/private/tmp/sandbox-lore-launchctl")


def write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2))


def build_plist(
    label: str,
    stdout_path: Path,
    stderr_path: Path,
    seatbelt_callout: bool,
    repo_root: Path,
    runner_path: Path,
) -> Dict[str, Any]:
    program = str(PYTHON if PYTHON.exists() else sys.executable)
    args = [program, str(runner_path)]
    env = {"PYTHONPATH": str(repo_root)}
    if seatbelt_callout:
        env["SANDBOX_LORE_SEATBELT_CALLOUT"] = "1"
    return {
        "Label": label,
        "ProgramArguments": args,
        "RunAtLoad": True,
        "WorkingDirectory": str(repo_root),
        "StandardOutPath": str(stdout_path),
        "StandardErrorPath": str(stderr_path),
        "EnvironmentVariables": env,
    }


def wait_for_output(stdout_path: Path, stderr_path: Path, timeout: float) -> bool:
    start = time.time()
    while time.time() - start < timeout:
        if stdout_path.exists() and stdout_path.stat().st_size > 0:
            return True
        if stderr_path.exists() and stderr_path.stat().st_size > 0:
            return True
        time.sleep(0.5)
    return False


def stage_repo(label: str) -> Path:
    stage_root = STAGING_BASE / label
    if stage_root.exists():
        shutil.rmtree(stage_root)
    stage_root.mkdir(parents=True, exist_ok=True)
    agents = REPO_ROOT / "AGENTS.md"
    if agents.exists():
        shutil.copy2(agents, stage_root / "AGENTS.md")
    shutil.copytree(
        REPO_ROOT / "book",
        stage_root / "book",
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns("__pycache__", ".DS_Store"),
    )
    return stage_root


def sync_outputs(staged_out: Path, dest_out: Path, stdout_path: Path, stderr_path: Path) -> None:
    if staged_out.exists():
        shutil.copytree(
            staged_out,
            dest_out,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("launchctl"),
        )
    dest_launchctl = dest_out / "launchctl"
    dest_launchctl.mkdir(parents=True, exist_ok=True)
    if stdout_path.exists():
        shutil.copy2(stdout_path, dest_launchctl / stdout_path.name)
    if stderr_path.exists():
        shutil.copy2(stderr_path, dest_launchctl / stderr_path.name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run runtime-checks via launchctl")
    parser.add_argument("--label", help="launchctl label override")
    parser.add_argument("--timeout", type=float, default=10.0, help="wait for output (seconds)")
    parser.add_argument("--keep-job", action="store_true", help="keep job loaded after run")
    parser.add_argument("--no-seatbelt-callout", action="store_true", help="disable sandbox_check callouts")
    parser.add_argument("--no-stage", action="store_true", help="run from the repo root instead of staging to /private/tmp")
    parser.add_argument("--keep-stage", action="store_true", help="retain staged copy after run")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not LAUNCHCTL.exists():
        print("[!] launchctl missing")
        return 2
    if not RUNNER.exists():
        print("[!] run_probes.py missing")
        return 2

    label = args.label or f"sandbox-lore.runtime-checks.{os.getpid()}"
    stage_root: Path | None = None
    stage_used = not args.no_stage
    if stage_used:
        stage_root = stage_repo(label)
        repo_root = stage_root
        runner_path = stage_root / "book/experiments/runtime-checks/run_probes.py"
        job_out_dir = stage_root / "book/experiments/runtime-checks/out"
    else:
        repo_root = REPO_ROOT
        runner_path = RUNNER
        job_out_dir = OUT_ROOT

    job_launchctl = job_out_dir / "launchctl"
    job_launchctl.mkdir(parents=True, exist_ok=True)
    stdout_path = job_launchctl / f"{label}.stdout.txt"
    stderr_path = job_launchctl / f"{label}.stderr.txt"
    plist_path = job_launchctl / f"{label}.plist"
    LAUNCHCTL_DIR.mkdir(parents=True, exist_ok=True)

    seatbelt_callout = not args.no_seatbelt_callout
    plist = build_plist(
        label,
        stdout_path,
        stderr_path,
        seatbelt_callout=seatbelt_callout,
        repo_root=repo_root,
        runner_path=runner_path,
    )
    plist_path.write_bytes(plistlib.dumps(plist))

    target = f"gui/{os.getuid()}"
    result: Dict[str, Any] = {
        "label": label,
        "target": target,
        "plist": path_utils.to_repo_relative(plist_path, repo_root=REPO_ROOT),
        "stdout": path_utils.to_repo_relative(stdout_path, repo_root=REPO_ROOT),
        "stderr": path_utils.to_repo_relative(stderr_path, repo_root=REPO_ROOT),
        "seatbelt_callout": seatbelt_callout,
        "stage_used": stage_used,
        "stage_root": str(stage_root) if stage_root else None,
        "runner": path_utils.to_repo_relative(RUNNER, repo_root=REPO_ROOT),
        "commands": [],
    }

    bootstrap_cmd = [str(LAUNCHCTL), "bootstrap", target, str(plist_path)]
    result["commands"].append(bootstrap_cmd)
    boot = subprocess.run(bootstrap_cmd, capture_output=True, text=True)
    result["bootstrap"] = {"rc": boot.returncode, "stderr": boot.stderr, "stdout": boot.stdout}
    if boot.returncode != 0:
        write_json(LAUNCHCTL_DIR / "launchctl_last_run.json", result)
        print("[!] launchctl bootstrap failed")
        return 2

    kick_cmd = [str(LAUNCHCTL), "kickstart", "-k", f"{target}/{label}"]
    result["commands"].append(kick_cmd)
    kick = subprocess.run(kick_cmd, capture_output=True, text=True)
    result["kickstart"] = {"rc": kick.returncode, "stderr": kick.stderr, "stdout": kick.stdout}

    waited = wait_for_output(stdout_path, stderr_path, args.timeout)
    result["waited"] = waited

    if not args.keep_job:
        bootout_cmd = [str(LAUNCHCTL), "bootout", target, str(plist_path)]
        result["commands"].append(bootout_cmd)
        bootout = subprocess.run(bootout_cmd, capture_output=True, text=True)
        result["bootout"] = {"rc": bootout.returncode, "stderr": bootout.stderr, "stdout": bootout.stdout}

    if stage_used and stage_root:
        try:
            sync_outputs(job_out_dir, OUT_ROOT, stdout_path, stderr_path)
        except Exception as exc:
            result["stage_sync_error"] = str(exc)
        if not args.keep_stage:
            try:
                shutil.rmtree(stage_root)
            except Exception as exc:
                result["stage_cleanup_error"] = str(exc)

    write_json(LAUNCHCTL_DIR / "launchctl_last_run.json", result)
    print(f"[+] launchctl run recorded in {LAUNCHCTL_DIR / 'launchctl_last_run.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
