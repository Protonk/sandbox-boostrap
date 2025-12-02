"""
Command builder for headless Ghidra runs against Sandbox-private artifacts.
Tasks focus on the kernel KC (com.apple.security.sandbox) and emit outputs under dumps/ghidra/out/.
"""
from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent  # dumps/
REPO_ROOT = ROOT.parent
SANDBOX_PRIVATE = ROOT / "Sandbox-private"
BOOK_API_SCRIPTS = REPO_ROOT / "book" / "api" / "ghidra" / "scripts"
SCRIPTS_DIR = BOOK_API_SCRIPTS
OUT_ROOT = HERE / "out"
PROJECTS_ROOT = HERE / "projects"
TEMP_ROOT = HERE / "tmp"
DEFAULT_BUILD_ID = "14.4.1-23E224"


@dataclass(frozen=True)
class BuildPaths:
    build_id: str
    base: Path
    kernel: Path
    userland: Path
    profiles_dir: Path
    compiled_textedit: Path
    system_version: Path

    @classmethod
    def from_build(cls, build_id: str = DEFAULT_BUILD_ID) -> "BuildPaths":
        base = SANDBOX_PRIVATE / build_id
        return cls(
            build_id=build_id,
            base=base,
            kernel=base / "kernel" / "BootKernelExtensions.kc",
            userland=base / "userland" / "libsystem_sandbox.dylib",
            profiles_dir=base / "profiles" / "Profiles",
            compiled_textedit=base / "profiles" / "compiled" / "com.apple.TextEdit.sandbox.sb.bin",
            system_version=base / "SYSTEM_VERSION.txt",
        )

    def missing(self) -> List[Path]:
        paths = [
            self.kernel,
            self.userland,
            self.profiles_dir,
            self.compiled_textedit,
            self.system_version,
        ]
        return [p for p in paths if not p.exists()]


@dataclass(frozen=True)
class TaskConfig:
    name: str
    script: str
    import_target: str
    description: str

    def script_path(self) -> Path:
        return SCRIPTS_DIR / self.script


TASKS: Dict[str, TaskConfig] = {
    "kernel-symbols": TaskConfig(
        name="kernel-symbols",
        script="kernel_symbols.py",
        import_target="kernel",
        description="Import KC and dump symbols/strings for com.apple.security.sandbox.",
    ),
    "kernel-tag-switch": TaskConfig(
        name="kernel-tag-switch",
        script="kernel_tag_switch.py",
        import_target="kernel",
        description="Locate PolicyGraph dispatcher/tag switch inside the KC.",
    ),
    "kernel-op-table": TaskConfig(
        name="kernel-op-table",
        script="kernel_op_table.py",
        import_target="kernel",
        description="Recover operation pointer table entries from the KC.",
    ),
    "kernel-string-refs": TaskConfig(
        name="kernel-string-refs",
        script="kernel_string_refs.py",
        import_target="kernel",
        description="Resolve references to sandbox strings and AppleMatch imports in the KC.",
    ),
    "kernel-function-dump": TaskConfig(
        name="kernel-function-dump",
        script="kernel_function_dump.py",
        import_target="kernel",
        description="Dump disassembly for specified functions/addresses.",
    ),
    "kernel-addr-lookup": TaskConfig(
        name="kernel-addr-lookup",
        script="kernel_addr_lookup.py",
        import_target="kernel",
        description="Lookup file offsets/constants to map to addresses/functions/callers.",
    ),
    "kernel-function-info": TaskConfig(
        name="kernel-function-info",
        script="kernel_function_info.py",
        import_target="kernel",
        description="Emit metadata for specified functions (callers, callees, size).",
    ),
    "kernel-imm-search": TaskConfig(
        name="kernel-imm-search",
        script="kernel_imm_search.py",
        import_target="kernel",
        description="Search instructions for a given immediate (scalar) value.",
    ),
    "kernel-data-define": TaskConfig(
        name="kernel-data-define",
        script="kernel_data_define_and_refs.py",
        import_target="kernel",
        description="Define data at given addresses and dump references (for pointer/table pivots).",
    ),
}


def ensure_under(child: Path, parent: Path) -> None:
    try:
        child.relative_to(parent)
    except ValueError as exc:
        raise ValueError(f"{child} is not under {parent}") from exc


def resolve_headless_path(candidate: str | None, require_exists: bool) -> Path:
    value = candidate if candidate else os.environ.get("GHIDRA_HEADLESS")
    if not value:
        placeholder = Path("<ghidra-headless>")
        if require_exists:
            raise ValueError("Set --ghidra-headless or GHIDRA_HEADLESS to run Ghidra headless")
        return placeholder
    path = Path(value)
    if require_exists and not path.exists():
        raise FileNotFoundError(f"Ghidra headless binary not found: {path}")
    return path


def build_headless_command(
    task: TaskConfig,
    build: BuildPaths,
    ghidra_headless: str | None,
    vm_path: Path | None,
    no_analysis: bool,
    script_args: List[str],
    processor: str | None,
    analysis_properties: str | None,
    project_name: str,
) -> Tuple[List[str], Path]:
    import_path = getattr(build, task.import_target)
    out_dir = OUT_ROOT / build.build_id / task.name
    ensure_under(out_dir, OUT_ROOT)
    headless = resolve_headless_path(ghidra_headless, require_exists=False)
    project_dir = PROJECTS_ROOT
    cmd = [
        str(headless),
        str(project_dir),
        project_name,
        "-overwrite",
    ]
    if processor:
        cmd.extend(["-processor", processor])
    if no_analysis:
        cmd.append("-noanalysis")
    if analysis_properties:
        cmd.extend(["-analysisProperties", str(analysis_properties)])
    cmd.extend(
        [
            "-import",
            str(import_path),
            "-scriptPath",
            str(SCRIPTS_DIR),
            "-scriptlog",
            str(out_dir / "script.log"),
            "-postScript",
            task.script,
            str(out_dir),
            build.build_id,
        ]
    )
    cmd.extend(script_args)
    if vm_path:
        cmd.extend(["-vmPath", str(vm_path)])
    return cmd, out_dir


def build_process_command(
    task: TaskConfig,
    build: BuildPaths,
    ghidra_headless: str | None,
    vm_path: Path | None,
    no_analysis: bool,
    script_args: List[str],
    analysis_properties: str | None,
    project_name: str,
) -> Tuple[List[str], Path]:
    import_path = getattr(build, task.import_target)
    out_dir = OUT_ROOT / build.build_id / task.name
    ensure_under(out_dir, OUT_ROOT)
    headless = resolve_headless_path(ghidra_headless, require_exists=False)
    project_dir = PROJECTS_ROOT
    cmd = [
        str(headless),
        str(project_dir),
        project_name,
    ]
    if no_analysis:
        cmd.append("-noanalysis")
    if analysis_properties:
        cmd.extend(["-analysisProperties", str(analysis_properties)])
    cmd.extend(
        [
            "-process",
            import_path.name,
            "-scriptPath",
            str(SCRIPTS_DIR),
            "-scriptlog",
            str(out_dir / "script.log"),
            "-postScript",
            task.script,
            str(out_dir),
            build.build_id,
        ]
    )
    cmd.extend(script_args)
    if vm_path:
        cmd.extend(["-vmPath", str(vm_path)])
    return cmd, out_dir


def render_shell_command(cmd: Iterable[str]) -> str:
    return " ".join(shlex.quote(part) for part in cmd)


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build (and optionally run) Ghidra headless commands for sandbox RE.")
    parser.add_argument("task", choices=sorted(TASKS.keys()), help="Task to run.")
    parser.add_argument("--build-id", default=DEFAULT_BUILD_ID, help="Sandbox-private build ID.")
    parser.add_argument("--ghidra-headless", help="Path to Ghidra analyzeHeadless (env GHIDRA_HEADLESS fallback).")
    parser.add_argument("--project-name", help="Override Ghidra project name (defaults to sandbox_<build_id>).")
    parser.add_argument(
        "--user-dir",
        default=str(HERE / "user"),
        help="Ghidra user settings dir (keeps java_home.save inside repo).",
    )
    parser.add_argument(
        "--java-home",
        help="JAVA_HOME to export for the headless subprocess; sets VM lookup and avoids interactive JDK prompt.",
    )
    parser.add_argument(
        "--vm-path",
        help="Override path to Java executable passed via -vmPath; defaults to JAVA_HOME/bin/java when JAVA_HOME is set.",
    )
    parser.add_argument("--processor", help="Override processor/language ID for import (passed via -processor).")
    parser.add_argument("--no-analysis", action="store_true", help="Add -noanalysis to the headless run.")
    parser.add_argument(
        "--process-existing",
        action="store_true",
        help="Use an existing analyzed project (no import/overwrite) and run the script via -process.",
    )
    parser.add_argument(
        "--analysis-properties",
        help="analysisProperties string or file (e.g., Analysis.X86 Constant Reference Analyzer.enabled=false).",
    )
    parser.add_argument(
        "--script-args",
        nargs="*",
        default=[],
        help="Extra args passed to the Ghidra script after <out_dir> and <build_id>.",
    )
    parser.add_argument("--exec", action="store_true", dest="do_exec", help="Execute instead of printing.")
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    task = TASKS[args.task]
    build = BuildPaths.from_build(args.build_id)
    missing = build.missing()
    if missing:
        for path in missing:
            sys.stderr.write(f"Missing input: {path}\n")
        return 1

    user_dir = Path(args.user_dir).resolve()
    vm_path = None
    if args.vm_path:
        vm_path = Path(args.vm_path).resolve()
    elif args.java_home:
        vm_path = Path(args.java_home).resolve() / "bin" / "java"

    project_name = args.project_name if args.project_name else f"sandbox_{build.build_id}"
    project_file = PROJECTS_ROOT / f"{project_name}.gpr"
    if args.process_existing:
        if not project_file.exists():
            sys.stderr.write(f"Missing project for --process-existing: {project_file}\n")
            return 1
        cmd, out_dir = build_process_command(
            task,
            build,
            args.ghidra_headless,
            vm_path,
            args.no_analysis,
            args.script_args,
            args.analysis_properties,
            project_name,
        )
    else:
        cmd, out_dir = build_headless_command(
            task,
            build,
            args.ghidra_headless,
            vm_path,
            args.no_analysis,
            args.script_args,
            args.processor,
            args.analysis_properties,
            project_name,
        )
    shell_cmd = render_shell_command(cmd)
    print(f"[task {task.name}] output dir: {out_dir}")
    print(f"[task {task.name}] command: {shell_cmd}")

    if not args.do_exec:
        return 0

    headless_path = resolve_headless_path(args.ghidra_headless, require_exists=True)
    if str(headless_path) != cmd[0]:
        cmd[0] = str(headless_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    PROJECTS_ROOT.mkdir(parents=True, exist_ok=True)
    user_dir.mkdir(parents=True, exist_ok=True)
    TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    if args.java_home:
        env["JAVA_HOME"] = args.java_home
    env["GHIDRA_USER_HOME"] = str(user_dir)
    env["HOME"] = str(user_dir)
    env["TMPDIR"] = str(TEMP_ROOT)
    env["TEMP"] = str(TEMP_ROOT)
    env["TMP"] = str(TEMP_ROOT)
    user_home_prop = f"-Duser.home={user_dir}"
    tmp_prop = f"-Djava.io.tmpdir={TEMP_ROOT}"
    if env.get("JAVA_TOOL_OPTIONS"):
        env["JAVA_TOOL_OPTIONS"] = env["JAVA_TOOL_OPTIONS"] + " " + user_home_prop + " " + tmp_prop
    else:
        env["JAVA_TOOL_OPTIONS"] = user_home_prop + " " + tmp_prop
    completed = subprocess.run(cmd, check=False, env=env)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
