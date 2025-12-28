#!/usr/bin/env python3
from __future__ import annotations

"""
SBPL trace + shrink tool for the fixed Sonoma host baseline.

This script is a stable CLI wrapper around the shrink-trace experiment harness:
- trace: run a target under sandbox-exec, collect denials, and grow a profile
- shrink: minimize a permissive profile while enforcing repeatable success
- workflow: trace + shrink in one pass

Outputs are written to a standardized run directory with repo-relative paths
and a top-level run.json manifest. The intent is reproducible evidence, not
portable policy guarantees across macOS versions.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from book.api import path_utils

# Reader map:
# 1) small helpers (timestamps, env parsing, JSON/line counts)
# 2) run.json assembly (world_id + knobs + outputs)
# 3) environment + directory layout wiring
# 4) trace/shrink phase runners
# 5) CLI parsing + main orchestration


# Stable paths to experiment assets we reuse; keeps the tool thin and DRY.
@dataclass(frozen=True)
class ToolPaths:
    repo_root: Path
    experiment_root: Path
    build_fixture: Path
    trace_script: Path
    shrink_script: Path
    lint_script: Path
    preflight_tool: Path


# Emit ISO-8601 UTC timestamps for run.json timing.
def iso_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Parse integer env overrides without throwing on bad input.
def env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


# Anchor all experiment dependencies relative to repo root.
def resolve_paths(repo_root: Path) -> ToolPaths:
    experiment_root = repo_root / "book" / "experiments" / "shrink-trace"
    return ToolPaths(
        repo_root=repo_root,
        experiment_root=experiment_root,
        build_fixture=experiment_root / "scripts" / "build_fixture.sh",
        trace_script=experiment_root / "scripts" / "trace_instrumented.sh",
        shrink_script=experiment_root / "scripts" / "shrink_instrumented.sh",
        lint_script=experiment_root / "scripts" / "lint_profile.py",
        preflight_tool=repo_root / "book" / "tools" / "preflight" / "preflight.py",
    )


# Run a command with optional file capture for stdout/stderr (evidence-friendly).
def run_command(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: Path,
    stdout_path: Path | None = None,
    stderr_path: Path | None = None,
) -> int:
    stdout = None
    stderr = None
    if stdout_path is not None:
        stdout = stdout_path.open("w", encoding="utf-8")
    if stderr_path is not None:
        stderr = stderr_path.open("w", encoding="utf-8")
    try:
        result = subprocess.run(cmd, cwd=str(cwd), env=env, stdout=stdout, stderr=stderr, text=True)
        return result.returncode
    finally:
        if stdout is not None:
            stdout.close()
        if stderr is not None:
            stderr.close()


# Defensive JSON load: experiments tolerate partial outputs.
def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


# Count line-oriented metrics/log files without loading structured JSON.
def count_lines(path: Path) -> int | None:
    try:
        return sum(1 for _ in path.read_text().splitlines())
    except FileNotFoundError:
        return None


# Summarize shrink decisions from metrics.jsonl (removed vs kept).
def count_shrink_decisions(metrics_path: Path) -> tuple[int | None, int | None]:
    removed = None
    kept = None
    if not metrics_path.exists():
        return removed, kept
    removed = 0
    kept = 0
    for raw in metrics_path.read_text().splitlines():
        try:
            data = json.loads(raw)
        except Exception:
            continue
        if data.get("event") != "candidate":
            continue
        decision = data.get("decision", "")
        if decision == "removed":
            removed += 1
        elif decision.startswith("kept"):
            kept += 1
    return removed, kept


# Standardize exec results with repo-relative paths for downstream tooling.
def write_exec_json(path: Path, rc: int, stdout_path: Path, stderr_path: Path, profile_path: Path, repo_root: Path) -> None:
    data = {
        "return_code": int(rc),
        "stdout": path_utils.to_repo_relative(stdout_path, repo_root),
        "stderr": path_utils.to_repo_relative(stderr_path, repo_root),
        "profile": path_utils.to_repo_relative(profile_path, repo_root),
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


# Emit a concise shrink status record used by run.json and matrix summaries.
def write_shrink_status(
    path: Path,
    *,
    status: str,
    reason: str | None = None,
    pre_rc1: int | None = None,
    pre_rc2: int | None = None,
    post_fresh_rc: int | None = None,
    post_repeat_rc: int | None = None,
    removed: int | None = None,
    kept: int | None = None,
    preflight_rc: int | None = None,
) -> None:
    data: dict[str, Any] = {"status": status}
    if reason:
        data["reason"] = reason
    if pre_rc1 is not None:
        data["pre_shrink_rc1"] = pre_rc1
    if pre_rc2 is not None:
        data["pre_shrink_rc2"] = pre_rc2
    if post_fresh_rc is not None:
        data["post_shrink_fresh_rc"] = post_fresh_rc
    if post_repeat_rc is not None:
        data["post_shrink_repeat_rc"] = post_repeat_rc
    if preflight_rc is not None:
        data["preflight_rc"] = preflight_rc
    if removed is not None:
        data["removed"] = removed
    if kept is not None:
        data["kept"] = kept
    path.write_text(json.dumps(data, indent=2, sort_keys=True))


# Read world_id from the baseline file; empty string if missing.
def load_world_id(world_baseline: Path) -> str:
    if not world_baseline.exists():
        return ""
    try:
        data = json.loads(world_baseline.read_text())
    except Exception:
        return ""
    return data.get("world_id", "")


# Assemble a single manifest that points to all phase outputs.
def build_run_json(
    run_dir: Path,
    repo_root: Path,
    world_baseline: Path,
    knobs: dict[str, Any],
    timing: dict[str, Any],
) -> None:
    trace_dir = run_dir / "phases" / "trace"
    shrink_dir = run_dir / "phases" / "shrink"
    profiles_dir = run_dir / "profiles"
    bin_dir = run_dir / "artifacts" / "bin"

    trace_status = read_json(trace_dir / "status.json")
    shrink_status = read_json(shrink_dir / "status.json")

    trace_metrics = trace_dir / "metrics.jsonl"
    shrink_metrics = shrink_dir / "metrics.jsonl"
    trace_profile = profiles_dir / "trace.sb"
    shrunk_profile = profiles_dir / "shrunk.sb"
    bad_rules = trace_dir / "bad_rules.txt"

    # Line counts are cheap summaries for dashboards and matrix tables.
    iterations = count_lines(trace_metrics)
    trace_lines = count_lines(trace_profile)
    shrunk_lines = count_lines(shrunk_profile)
    bad_rules_count = count_lines(bad_rules)

    removed = shrink_status.get("removed")
    kept = shrink_status.get("kept")
    if (removed is None or kept is None) and shrink_metrics.exists():
        removed, kept = count_shrink_decisions(shrink_metrics)

    # run.json is the primary contract for consumers and tests.
    data = {
        "world_id": load_world_id(world_baseline),
        "knobs": knobs,
        "paths": {
            "run_dir": path_utils.to_repo_relative(run_dir, repo_root),
            "profiles": {
                "trace": path_utils.to_repo_relative(trace_profile, repo_root),
                "shrunk": path_utils.to_repo_relative(shrunk_profile, repo_root) if shrunk_profile.exists() else None,
            },
            "phases": {
                "trace": path_utils.to_repo_relative(trace_dir, repo_root),
                "shrink": path_utils.to_repo_relative(shrink_dir, repo_root),
            },
            "artifacts": {
                "bin_dir": path_utils.to_repo_relative(bin_dir, repo_root),
            },
        },
        "trace": {
            "status": trace_status.get("status", "unknown"),
            "status_path": path_utils.to_repo_relative(trace_dir / "status.json", repo_root),
            "metrics_path": path_utils.to_repo_relative(trace_metrics, repo_root),
            "iterations": iterations,
            "profile_lines": trace_lines,
            "bad_rules": bad_rules_count,
            "issue_dir": trace_status.get("issue_dir"),
        },
        "shrink": {
            "status": shrink_status.get("status", "unknown"),
            "status_path": path_utils.to_repo_relative(shrink_dir / "status.json", repo_root),
            "metrics_path": path_utils.to_repo_relative(shrink_metrics, repo_root),
            "removed": removed,
            "kept": kept,
            "profile_lines": shrunk_lines,
            "post_shrink_fresh_rc": shrink_status.get("post_shrink_fresh_rc"),
            "post_shrink_repeat_rc": shrink_status.get("post_shrink_repeat_rc"),
        },
        "timing": timing,
    }
    (run_dir / "run.json").write_text(json.dumps(data, indent=2, sort_keys=True))


# Compose an environment that keeps the experiment scripts deterministic.
def build_env(
    *,
    repo_root: Path,
    run_dir: Path,
    trace_dir: Path,
    shrink_dir: Path,
    bin_dir: Path,
    dyld_log_path: Path,
    knobs: dict[str, Any],
) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    if os.environ.get("PYTHONPATH"):
        env["PYTHONPATH"] = f"{repo_root}:{os.environ['PYTHONPATH']}"
    # These env vars are the integration surface expected by the scripts.
    env["OUT_DIR"] = str(run_dir)
    env["BIN_DIR"] = str(bin_dir)
    env["WORK_DIR"] = str(run_dir)
    env["TRACE_DIR"] = str(trace_dir)
    env["SHRINK_DIR"] = str(shrink_dir)
    env["DYLD_LOG_PATH"] = str(dyld_log_path)
    env["FIXTURE_BIN"] = str(knobs.get("fixture", ""))
    env["SEED_DYLD"] = str(knobs.get("seed_dyld", ""))
    env["DENY_SIGSTOP"] = str(knobs.get("deny_sigstop", ""))
    env["IMPORT_DYLD_SUPPORT"] = str(knobs.get("import_dyld_support", ""))
    env["DYLD_LOG"] = str(knobs.get("dyld_log", ""))
    env["ALLOW_FIXTURE_EXEC"] = str(knobs.get("allow_fixture_exec", ""))
    env["NETWORK_RULES"] = str(knobs.get("network_rules", ""))
    env["SUCCESS_STREAK"] = str(knobs.get("success_streak", ""))
    env["DENY_SCOPE"] = str(knobs.get("deny_scope", ""))
    # Prepend fixture binaries so sandbox-exec resolves them by name.
    env["PATH"] = f"{bin_dir}:{env.get('PATH', '')}"
    return env


# Canonical output layout for a run; every tool phase writes under this tree.
def ensure_dirs(run_dir: Path) -> dict[str, Path]:
    profile_dir = run_dir / "profiles"
    bin_dir = run_dir / "artifacts" / "bin"
    trace_dir = run_dir / "phases" / "trace"
    shrink_dir = run_dir / "phases" / "shrink"
    trace_validation = trace_dir / "validation"
    shrink_validation = shrink_dir / "validation"
    for path in (profile_dir, bin_dir, trace_dir, shrink_dir, trace_validation, shrink_validation):
        path.mkdir(parents=True, exist_ok=True)
    return {
        "profiles": profile_dir,
        "bin": bin_dir,
        "trace": trace_dir,
        "shrink": shrink_dir,
        "trace_validation": trace_validation,
        "shrink_validation": shrink_validation,
    }


# Trace phase: spawn the instrumented tracer to build trace.sb.
def run_trace_phase(
    *,
    paths: ToolPaths,
    run_dir: Path,
    env: dict[str, str],
    fixture: str,
    trace_profile: Path,
    trace_stdout: Path,
    trace_stderr: Path,
) -> int:
    return run_command(
        [str(paths.trace_script), fixture, str(trace_profile)],
        env=env,
        cwd=run_dir,
        stdout_path=trace_stdout,
        stderr_path=trace_stderr,
    )


# Run a minimal fixture to detect early loader failures outside main().
def sandbox_min_check(
    *,
    run_dir: Path,
    trace_profile: Path,
    env: dict[str, str],
    dyld_log: int,
    dyld_log_path: Path,
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    cmd = ["sandbox-exec", "-D", f"WORK_DIR={run_dir}", "-D", f"DYLD_LOG_PATH={dyld_log_path}", "-f", str(trace_profile), "sandbox_min"]
    check_env = env.copy()
    if dyld_log:
        # DYLD_PRINT_* output is directed to a path we explicitly allow.
        check_env["DYLD_PRINT_TO_FILE"] = str(dyld_log_path)
        check_env["DYLD_PRINT_LIBRARIES"] = "1"
        check_env["DYLD_PRINT_INITIALIZERS"] = "1"
    return run_command(cmd, env=check_env, cwd=run_dir, stdout_path=stdout_path, stderr_path=stderr_path)


# Execute a fixture under a specific profile, capturing stdout/stderr for evidence.
def run_profile_exec(
    *,
    run_dir: Path,
    env: dict[str, str],
    profile: Path,
    fixture: str,
    stdout_path: Path,
    stderr_path: Path,
) -> int:
    cmd = ["sandbox-exec", "-D", f"WORK_DIR={run_dir}", "-D", f"DYLD_LOG_PATH={env['DYLD_LOG_PATH']}", "-f", str(profile), fixture]
    return run_command(cmd, env=env, cwd=run_dir, stdout_path=stdout_path, stderr_path=stderr_path)


# Linting is a structural guardrail (rejects malformed network filters, etc.).
def lint_profile(lint_script: Path, repo_root: Path, profile: Path, out_path: Path) -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    if os.environ.get("PYTHONPATH"):
        env["PYTHONPATH"] = f"{repo_root}:{os.environ['PYTHONPATH']}"
    return run_command(
        ["python3", str(lint_script), str(profile)],
        env=env,
        cwd=repo_root,
        stdout_path=out_path,
        stderr_path=None,
    )


# Preflight avoids known apply-gate shapes before we attempt shrink.
def run_preflight(preflight_tool: Path, repo_root: Path, profile_rel: str, out_path: Path) -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    if os.environ.get("PYTHONPATH"):
        env["PYTHONPATH"] = f"{repo_root}:{os.environ['PYTHONPATH']}"
    return run_command(
        ["python3", str(preflight_tool), "scan", profile_rel],
        env=env,
        cwd=repo_root,
        stdout_path=out_path,
        stderr_path=None,
    )


# Shrink phase: enforce preflight + repeatable success before removing rules.
def run_shrink_phase(
    *,
    paths: ToolPaths,
    run_dir: Path,
    env: dict[str, str],
    fixture: str,
    trace_profile: Path,
    shrunk_profile: Path,
    trace_validation_dir: Path,
    shrink_validation_dir: Path,
    shrink_stdout: Path,
    shrink_stderr: Path,
    shrink_status_path: Path,
) -> int:
    # Preflight the traced profile against known apply-gate patterns.
    preflight_json = shrink_validation_dir / "preflight_scan.json"
    profile_rel = path_utils.to_repo_relative(trace_profile, paths.repo_root)
    preflight_rc = run_preflight(paths.preflight_tool, paths.repo_root, profile_rel, preflight_json)
    if preflight_rc != 0:
        write_shrink_status(
            shrink_status_path,
            status="preflight_failed",
            reason="preflight_failed",
            preflight_rc=preflight_rc,
        )
        return preflight_rc

    # Two-run validation: fresh state then repeat state.
    pre1_stdout = shrink_validation_dir / "pre_shrink_run1.stdout.txt"
    pre1_stderr = shrink_validation_dir / "pre_shrink_run1.stderr.txt"
    pre2_stdout = shrink_validation_dir / "pre_shrink_run2.stdout.txt"
    pre2_stderr = shrink_validation_dir / "pre_shrink_run2.stderr.txt"
    shutil.rmtree(run_dir / "out", ignore_errors=True)
    pre_rc1 = run_profile_exec(
        run_dir=run_dir,
        env=env,
        profile=trace_profile,
        fixture=fixture,
        stdout_path=pre1_stdout,
        stderr_path=pre1_stderr,
    )
    pre_rc2 = run_profile_exec(
        run_dir=run_dir,
        env=env,
        profile=trace_profile,
        fixture=fixture,
        stdout_path=pre2_stdout,
        stderr_path=pre2_stderr,
    )
    write_exec_json(
        shrink_validation_dir / "pre_shrink_run1.json",
        pre_rc1,
        pre1_stdout,
        pre1_stderr,
        trace_profile,
        paths.repo_root,
    )
    write_exec_json(
        shrink_validation_dir / "pre_shrink_run2.json",
        pre_rc2,
        pre2_stdout,
        pre2_stderr,
        trace_profile,
        paths.repo_root,
    )
    if pre_rc1 != 0 or pre_rc2 != 0:
        write_shrink_status(
            shrink_status_path,
            status="pre_shrink_failed",
            reason="pre_shrink_failed",
            pre_rc1=pre_rc1,
            pre_rc2=pre_rc2,
        )
        return 0

    # Lint the traced profile before shrinking to avoid cascading failures.
    lint_trace_out = trace_validation_dir / "lint.txt"
    lint_trace_rc = lint_profile(paths.lint_script, paths.repo_root, trace_profile, lint_trace_out)
    if lint_trace_rc != 0:
        write_shrink_status(
            shrink_status_path,
            status="lint_failed",
            reason="trace_profile",
            pre_rc1=pre_rc1,
            pre_rc2=pre_rc2,
        )
        return 0

    # Shrink script performs line-by-line removal with fresh+repeat checks.
    shrink_rc = run_command(
        [str(paths.shrink_script), fixture, str(trace_profile)],
        env=env,
        cwd=run_dir,
        stdout_path=shrink_stdout,
        stderr_path=shrink_stderr,
    )
    if shrink_rc != 0:
        write_shrink_status(
            shrink_status_path,
            status="shrink_failed",
            reason="shrink_failed",
            pre_rc1=pre_rc1,
            pre_rc2=pre_rc2,
        )
        return 0

    # Lint the shrunk profile before declaring success.
    lint_shrunk_out = shrink_validation_dir / "lint.txt"
    lint_shrunk_rc = lint_profile(paths.lint_script, paths.repo_root, shrunk_profile, lint_shrunk_out)
    if lint_shrunk_rc != 0:
        write_shrink_status(
            shrink_status_path,
            status="lint_failed",
            reason="shrunk_profile",
            pre_rc1=pre_rc1,
            pre_rc2=pre_rc2,
        )
        return 0

    # Final validation: the shrunk profile must satisfy the same two-state contract.
    post_fresh_stdout = shrink_validation_dir / "post_shrink_fresh.stdout.txt"
    post_fresh_stderr = shrink_validation_dir / "post_shrink_fresh.stderr.txt"
    post_repeat_stdout = shrink_validation_dir / "post_shrink_repeat.stdout.txt"
    post_repeat_stderr = shrink_validation_dir / "post_shrink_repeat.stderr.txt"
    shutil.rmtree(run_dir / "out", ignore_errors=True)
    post_fresh_rc = run_profile_exec(
        run_dir=run_dir,
        env=env,
        profile=shrunk_profile,
        fixture=fixture,
        stdout_path=post_fresh_stdout,
        stderr_path=post_fresh_stderr,
    )
    post_repeat_rc = run_profile_exec(
        run_dir=run_dir,
        env=env,
        profile=shrunk_profile,
        fixture=fixture,
        stdout_path=post_repeat_stdout,
        stderr_path=post_repeat_stderr,
    )
    write_exec_json(
        shrink_validation_dir / "post_shrink_fresh.json",
        post_fresh_rc,
        post_fresh_stdout,
        post_fresh_stderr,
        shrunk_profile,
        paths.repo_root,
    )
    write_exec_json(
        shrink_validation_dir / "post_shrink_repeat.json",
        post_repeat_rc,
        post_repeat_stdout,
        post_repeat_stderr,
        shrunk_profile,
        paths.repo_root,
    )
    if post_fresh_rc != 0 or post_repeat_rc != 0:
        write_shrink_status(
            shrink_status_path,
            status="post_shrink_failed",
            reason="post_shrink_failed",
            pre_rc1=pre_rc1,
            pre_rc2=pre_rc2,
            post_fresh_rc=post_fresh_rc,
            post_repeat_rc=post_repeat_rc,
        )
        return 0

    shrink_metrics = Path(env["SHRINK_DIR"]) / "metrics.jsonl"
    removed, kept = count_shrink_decisions(shrink_metrics)
    write_shrink_status(
        shrink_status_path,
        status="success",
        reason="success",
        pre_rc1=pre_rc1,
        pre_rc2=pre_rc2,
        post_fresh_rc=post_fresh_rc,
        post_repeat_rc=post_repeat_rc,
        removed=removed,
        kept=kept,
    )
    return 0


# CLI wiring; defaults honor env vars to ease integration with scripts/matrix runs.
def parse_args(repo_root: Path) -> argparse.Namespace:
    default_out = repo_root / "book" / "experiments" / "shrink-trace" / "out"
    default_world_baseline = repo_root / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--out-dir", default=os.environ.get("OUT_DIR", str(default_out)))
    common.add_argument("--fixture", default=os.environ.get("FIXTURE_BIN", "sandbox_target"))
    common.add_argument("--world-baseline", default=os.environ.get("WORLD_BASELINE", str(default_world_baseline)))
    common.add_argument("--seed-dyld", type=int, default=env_int("SEED_DYLD", 1))
    common.add_argument("--deny-sigstop", type=int, default=env_int("DENY_SIGSTOP", 0))
    common.add_argument("--import-dyld-support", type=int, default=env_int("IMPORT_DYLD_SUPPORT", 1))
    common.add_argument("--dyld-log", type=int, default=env_int("DYLD_LOG", 0))
    common.add_argument("--allow-fixture-exec", type=int, default=env_int("ALLOW_FIXTURE_EXEC", 1))
    common.add_argument("--network-rules", default=os.environ.get("NETWORK_RULES", "parsed"))
    common.add_argument("--success-streak", type=int, default=env_int("SUCCESS_STREAK", 2))
    common.add_argument("--deny-scope", default=os.environ.get("DENY_SCOPE", "all"))
    common.add_argument("--clean", action="store_true")
    common.add_argument("--no-clean", action="store_true")

    parser = argparse.ArgumentParser(description="Trace and shrink SBPL profiles on the fixed host baseline.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("workflow", parents=[common], help="trace + shrink in one pass")
    subparsers.add_parser("trace", parents=[common], help="trace only (build profile from denials)")
    subparsers.add_parser("shrink", parents=[common], help="shrink only (minimize existing profile)")
    return parser.parse_args()


# Orchestrate a full tool run and always emit run.json with timing.
def main() -> int:
    repo_root = path_utils.find_repo_root()
    paths = resolve_paths(repo_root)
    args = parse_args(repo_root)

    # Timing is recorded in run.json for observed durations.
    start_epoch = time.time()
    exit_code = 0

    # All file-system I/O is rooted at the run directory.
    run_dir = path_utils.ensure_absolute(args.out_dir, repo_root)
    world_baseline = path_utils.ensure_absolute(args.world_baseline, repo_root)
    knobs = {
        "fixture": args.fixture,
        "seed_dyld": args.seed_dyld,
        "import_dyld_support": args.import_dyld_support,
        "dyld_log": args.dyld_log,
        "allow_fixture_exec": args.allow_fixture_exec,
        "network_rules": args.network_rules,
        "success_streak": args.success_streak,
        "deny_scope": args.deny_scope,
        "deny_sigstop": args.deny_sigstop,
    }

    # By default we clean for trace/workflow to avoid stale artifacts.
    clean_default = args.command in ("workflow", "trace")
    if args.clean and args.no_clean:
        print("[!] Cannot set both --clean and --no-clean.", file=sys.stderr)
        return 2
    clean = clean_default
    if args.clean:
        clean = True
    if args.no_clean:
        clean = False

    if clean and run_dir.exists():
        shutil.rmtree(run_dir)

    paths_map = ensure_dirs(run_dir)
    profile_dir = paths_map["profiles"]
    bin_dir = paths_map["bin"]
    trace_dir = paths_map["trace"]
    shrink_dir = paths_map["shrink"]
    trace_validation_dir = paths_map["trace_validation"]
    shrink_validation_dir = paths_map["shrink_validation"]
    trace_profile = profile_dir / "trace.sb"
    shrunk_profile = profile_dir / "shrunk.sb"

    trace_stdout = trace_dir / "stdout.txt"
    trace_stderr = trace_dir / "stderr.txt"
    shrink_stdout = shrink_dir / "stdout.txt"
    shrink_stderr = shrink_dir / "stderr.txt"
    shrink_status_path = shrink_dir / "status.json"
    dyld_log_path = Path(os.environ.get("DYLD_LOG_PATH", str(trace_dir / "dyld.log")))

    # Build the env contract expected by the experiment scripts.
    env = build_env(
        repo_root=repo_root,
        run_dir=run_dir,
        trace_dir=trace_dir,
        shrink_dir=shrink_dir,
        bin_dir=bin_dir,
        dyld_log_path=dyld_log_path,
        knobs=knobs,
    )

    try:
        # Compile the fixture binaries into artifacts/bin.
        build_rc = run_command([str(paths.build_fixture)], env=env, cwd=run_dir)
        if build_rc != 0:
            print("[!] Fixture build failed.", file=sys.stderr)
            exit_code = build_rc
            return exit_code

        fixture_path = bin_dir / args.fixture
        if not fixture_path.exists():
            print(f"[!] Fixture not found: {fixture_path}", file=sys.stderr)
            exit_code = 1
            return exit_code

        # Trace phase runs first for workflow/trace.
        if args.command in ("workflow", "trace"):
            trace_rc = run_trace_phase(
                paths=paths,
                run_dir=run_dir,
                env=env,
                fixture=args.fixture,
                trace_profile=trace_profile,
                trace_stdout=trace_stdout,
                trace_stderr=trace_stderr,
            )
            if trace_rc != 0:
                exit_code = trace_rc
            # If deny-sigstop is off, run sandbox_min to detect early loader issues.
            if args.deny_sigstop != 1:
                sandbox_min_stdout = trace_validation_dir / "sandbox_min.stdout.txt"
                sandbox_min_stderr = trace_validation_dir / "sandbox_min.stderr.txt"
                sandbox_min_rc = sandbox_min_check(
                    run_dir=run_dir,
                    trace_profile=trace_profile,
                    env=env,
                    dyld_log=args.dyld_log,
                    dyld_log_path=dyld_log_path,
                    stdout_path=sandbox_min_stdout,
                    stderr_path=sandbox_min_stderr,
                )
                write_exec_json(
                    trace_validation_dir / "sandbox_min.json",
                    sandbox_min_rc,
                    sandbox_min_stdout,
                    sandbox_min_stderr,
                    trace_profile,
                    repo_root,
                )
            else:
                write_shrink_status(shrink_status_path, status="skipped", reason="deny_sigstop")

            # Trace-only exits after writing a skipped shrink status.
            if args.command == "trace":
                write_shrink_status(shrink_status_path, status="skipped", reason="trace_only")
                return exit_code

        # Shrink phase runs for workflow or explicit shrink.
        if args.command in ("workflow", "shrink"):
            if not trace_profile.exists():
                print(f"[!] Trace profile missing: {trace_profile}", file=sys.stderr)
                write_shrink_status(shrink_status_path, status="skipped", reason="missing_trace_profile")
                exit_code = 1
                return exit_code

            trace_status = read_json(trace_dir / "status.json").get("status", "unknown")
            # For workflow, shrink only proceeds after trace success.
            if args.command == "workflow" and trace_status != "success":
                write_shrink_status(shrink_status_path, status="skipped", reason=f"trace_{trace_status}")
                return exit_code

            if args.deny_sigstop == 1:
                write_shrink_status(shrink_status_path, status="skipped", reason="deny_sigstop")
                return exit_code

            shrink_rc = run_shrink_phase(
                paths=paths,
                run_dir=run_dir,
                env=env,
                fixture=args.fixture,
                trace_profile=trace_profile,
                shrunk_profile=shrunk_profile,
                trace_validation_dir=trace_validation_dir,
                shrink_validation_dir=shrink_validation_dir,
                shrink_stdout=shrink_stdout,
                shrink_stderr=shrink_stderr,
                shrink_status_path=shrink_status_path,
            )
            exit_code = shrink_rc
    finally:
        # run.json is always emitted so partial runs remain inspectable.
        end_epoch = time.time()
        timing = {
            "start_epoch": start_epoch,
            "start_utc": iso_utc(start_epoch),
            "end_epoch": end_epoch,
            "end_utc": iso_utc(end_epoch),
            "duration_s": round(end_epoch - start_epoch, 3),
        }
        build_run_json(run_dir, repo_root, world_baseline, knobs, timing)

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
