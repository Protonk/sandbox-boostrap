"""
Agent-facing connector for Seatbelt-focused Ghidra headless runs.

Why this exists:
- Centralize task registration and env policy so agents do not have to remember the headless incantations.
- Keep all Ghidra side effects in `dumps/ghidra/{out,projects,user,tmp}` and never move host artifacts out of
  `dumps/Sandbox-private/<build>/...`.
- Offer a dry-run path (render shell) and an execution path with consistent HOME/TMPDIR/JAVA settings.

Safety/assumptions:
- Baseline: see `book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json`; inputs must already exist under Sandbox-private.
- `JAVA_TOOL_OPTIONS` is forced to a repo-local home/temp to dodge seatbelt prompts and permission errors.
- `analysis_properties` is accepted for parity but ignored by Ghidra 11.4.2 (use pre-scripts instead).
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from . import scaffold as gh_scaffold


ROOT = Path(__file__).resolve().parents[3]
DUMPS_ROOT = ROOT / "dumps"
ARM64_ANALYSIS_PROPERTIES = Path(__file__).resolve().parent / "analysis_arm64.properties"


def _ensure_under(child: Path, parent: Path) -> None:
    gh_scaffold.ensure_under(child, parent)


@dataclass(frozen=True)
class TaskSpec:
    """Definition of a headless Ghidra task."""

    name: str
    description: str
    import_target: str
    script_path: Path

    @classmethod
    def from_scaffold(cls, config: gh_scaffold.TaskConfig) -> "TaskSpec":
        return cls(
            name=config.name,
            description=config.description,
            import_target=config.import_target,
            script_path=gh_scaffold.SCRIPTS_DIR / config.script,
        )


class TaskRegistry:
    """Registry for Ghidra tasks accessible to agents."""

    def __init__(self, tasks: Mapping[str, TaskSpec]):
        self._tasks = dict(tasks)

    @classmethod
    def default(cls) -> "TaskRegistry":
        return cls({name: TaskSpec.from_scaffold(cfg) for name, cfg in gh_scaffold.TASKS.items()})

    def get(self, name: str) -> TaskSpec:
        if name not in self._tasks:
            raise KeyError(f"Unknown Ghidra task: {name}")
        return self._tasks[name]

    def list(self) -> List[str]:
        return sorted(self._tasks.keys())

    def register(self, spec: TaskSpec) -> None:
        self._tasks[spec.name] = spec


@dataclass(frozen=True)
class HeadlessInvocation:
    """Fully rendered headless command plus metadata (safe to print/log for repro)."""

    task: TaskSpec
    build_id: str
    command: List[str]
    env: Dict[str, str]
    out_dir: Path
    project_name: str
    project_file: Path
    mode: str  # "import" or "process"

    def render_shell(self) -> str:
        return gh_scaffold.render_shell_command(self.command)


@dataclass
class HeadlessResult:
    invocation: HeadlessInvocation
    returncode: Optional[int] = None
    completed: Optional[subprocess.CompletedProcess[str]] = None


def _cleanup_temp_markers(temp_dir: Path) -> None:
    """Remove known temp marker files Ghidra drops (e.g., .lastmaint) under our sandboxed temp root."""
    for marker in temp_dir.rglob(".lastmaint"):
        try:
            marker.unlink()
        except Exception:
            continue


def _build_env(
    java_home: Optional[str],
    user_dir: Path,
    temp_dir: Path,
    extra_env: Optional[Mapping[str, str]],
) -> Dict[str, str]:
    # Build a sandboxed environment so headless never touches the real HOME/TMP.
    env: MutableMapping[str, str] = dict(os.environ)
    if java_home:
        env["JAVA_HOME"] = java_home
    env["GHIDRA_USER_HOME"] = str(user_dir)
    env["HOME"] = str(user_dir)
    env["TMPDIR"] = str(temp_dir)
    env["TEMP"] = str(temp_dir)
    env["TMP"] = str(temp_dir)
    user_home_prop = f"-Duser.home={user_dir}"
    tmp_prop = f"-Djava.io.tmpdir={temp_dir}"
    if env.get("JAVA_TOOL_OPTIONS"):
        env["JAVA_TOOL_OPTIONS"] = env["JAVA_TOOL_OPTIONS"] + " " + user_home_prop + " " + tmp_prop
    else:
        env["JAVA_TOOL_OPTIONS"] = user_home_prop + " " + tmp_prop
    if extra_env:
        env.update(extra_env)
    return dict(env)


class HeadlessConnector:
    """Build and optionally run Ghidra headless tasks with consistent sandboxing."""

    def __init__(
        self,
        registry: Optional[TaskRegistry] = None,
        ghidra_headless: Optional[str] = None,
        java_home: Optional[str] = None,
        user_dir: Optional[Path] = None,
        temp_dir: Optional[Path] = None,
        extra_env: Optional[Mapping[str, str]] = None,
        analysis_properties: Optional[str] = None,
    ):
        self.registry = registry or TaskRegistry.default()
        self.ghidra_headless = ghidra_headless
        self.java_home = java_home
        self.user_dir = user_dir if user_dir else gh_scaffold.GHIDRA_ROOT / "user"
        _ensure_under(self.user_dir, gh_scaffold.GHIDRA_ROOT)
        self.temp_dir = temp_dir if temp_dir else gh_scaffold.GHIDRA_ROOT / "tmp"
        _ensure_under(self.temp_dir, gh_scaffold.GHIDRA_ROOT)
        self.extra_env = dict(extra_env) if extra_env else {}
        self.analysis_properties = analysis_properties

    def build(
        self,
        task_name: str,
        build_id: Optional[str] = None,
        project_name: Optional[str] = None,
        processor: Optional[str] = None,
        no_analysis: bool = False,
        process_existing: bool = False,
        script_args: Optional[Sequence[str]] = None,
        ghidra_headless: Optional[str] = None,
        java_home: Optional[str] = None,
        vm_path: Optional[str] = None,
        analysis_properties: Optional[str] = None,
        pre_scripts: Optional[Sequence[str]] = None,
    ) -> HeadlessInvocation:
        task_spec = self.registry.get(task_name)
        task_cfg = gh_scaffold.TASKS[task_name]
        build = gh_scaffold.BuildPaths.from_build(build_id or gh_scaffold.DEFAULT_BUILD_ID)
        missing = build.missing()
        if missing:
            missing_str = ", ".join(str(p) for p in missing)
            raise FileNotFoundError(f"Missing inputs for build {build.build_id}: {missing_str}")

        vm_path_path: Optional[Path] = Path(vm_path).resolve() if vm_path else None
        use_java_home = java_home or self.java_home
        if not vm_path_path and use_java_home:
            vm_path_path = Path(use_java_home).resolve() / "bin" / "java"

        project = project_name or f"sandbox_{build.build_id}"
        project_file = gh_scaffold.PROJECTS_ROOT / f"{project}.gpr"
        if process_existing and not project_file.exists():
            raise FileNotFoundError(f"Missing project for --process-existing: {project_file}")

        args = list(script_args) if script_args else []
        analysis_props_value = analysis_properties or self.analysis_properties
        pre_scripts_list = list(pre_scripts) if pre_scripts else []
        if process_existing:
            cmd, out_dir = gh_scaffold.build_process_command(
                task_cfg,
                build,
                ghidra_headless or self.ghidra_headless,
                vm_path_path,
                no_analysis,
                args,
                analysis_props_value,
                pre_scripts_list,
                project,
            )
            mode = "process"
        else:
            cmd, out_dir = gh_scaffold.build_headless_command(
                task_cfg,
                build,
                ghidra_headless or self.ghidra_headless,
                vm_path_path,
                no_analysis,
                args,
                processor,
                analysis_props_value,
                pre_scripts_list,
                project,
            )
            mode = "import"
        env = _build_env(use_java_home, self.user_dir, self.temp_dir, self.extra_env)
        return HeadlessInvocation(
            task=task_spec,
            build_id=build.build_id,
            command=cmd,
            env=env,
            out_dir=out_dir,
            project_name=project,
            project_file=project_file,
            mode=mode,
        )

    def run(self, invocation: HeadlessInvocation, execute: bool = False, timeout: Optional[int] = None) -> HeadlessResult:
        result = HeadlessResult(invocation=invocation)
        if not execute:
            return result

        headless_candidate = self.ghidra_headless or invocation.command[0]
        headless_path = gh_scaffold.resolve_headless_path(headless_candidate, require_exists=True)
        if str(headless_path) != invocation.command[0]:
            invocation.command[0] = str(headless_path)

        invocation.out_dir.mkdir(parents=True, exist_ok=True)
        gh_scaffold.PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
        self.user_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)

        completed = subprocess.run(invocation.command, check=False, env=invocation.env, timeout=timeout)
        result.completed = completed
        result.returncode = completed.returncode
        try:
            _cleanup_temp_markers(self.temp_dir)
        except Exception:
            # temp cleanup is best-effort
            pass
        return result
