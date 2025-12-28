"""
Canonical headless-command builder for Ghidra tasks on the Sonoma baseline (`book/world/sonoma-14.4.1-23E224-arm64/world.json`).

Intent:
- Build (and optionally run) `analyzeHeadless` invocations against the extracted host artifacts in
  `dumps/Sandbox-private/<build>/...` without ever copying those artifacts into tracked trees.
- Keep all Ghidra side effects inside `dumps/ghidra/{out,projects,user,tmp}`; callers should not need
  to reason about Ghidra’s defaults or macOS prompts.
- Provide a single source of truth for task registration (scripts + import targets + output layout).

Safety reminders (why the plumbing is opinionated):
- `HOME`/`GHIDRA_USER_HOME`/`JAVA_TOOL_OPTIONS` are forced under `dumps/ghidra/` so headless does not
  touch the real user tree (seatbelt-protected) or prompt for a JDK path.
- Inputs are always read from `Sandbox-private` in place; outputs stay under `dumps/ghidra/out/` with
  optional redirects (e.g., kernel-symbols into the experiment tree).
- Apply-gate and analysis churn are expected; scripts should log to `script.log` in their out dir.
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


REPO_ROOT = Path(__file__).resolve().parents[3]
DUMPS_ROOT = REPO_ROOT / "dumps"
GHIDRA_ROOT = DUMPS_ROOT / "ghidra"
SANDBOX_PRIVATE = DUMPS_ROOT / "Sandbox-private"
BOOK_API_SCRIPTS = Path(__file__).resolve().parent / "scripts"
SCRIPTS_DIR = BOOK_API_SCRIPTS
OUT_ROOT = GHIDRA_ROOT / "out"
KERNEL_SYMBOLS_OUT_ROOT = REPO_ROOT / "book" / "experiments" / "kernel-symbols" / "out"
PROJECTS_ROOT = GHIDRA_ROOT / "projects"
TEMP_ROOT = GHIDRA_ROOT / "tmp"
DEFAULT_BUILD_ID = "14.4.1-23E224"


@dataclass(frozen=True)
class BuildPaths:
    """Paths to host artifacts for a given build ID (never copied into tracked trees)."""
    build_id: str
    base: Path
    kernel: Path
    kernel_collection: Path
    sandbox_kext: Path
    amfi_kext: Path
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
            kernel_collection=base / "kernel" / "BootKernelCollection.kc",
            sandbox_kext=base / "kernel" / "sandbox_kext.bin",
            amfi_kext=base
            / "kernel"
            / "sandbox_kext_com_apple_driver_AppleMobileFileIntegrity.bin",
            userland=base / "userland" / "libsystem_sandbox.dylib",
            profiles_dir=base / "profiles" / "Profiles",
            compiled_textedit=base / "profiles" / "compiled" / "com.apple.TextEdit.sandbox.sb.bin",
            system_version=base / "SYSTEM_VERSION.txt",
        )

    def missing(self, import_target: str | None = None) -> List[Path]:
        paths = [
            self.kernel,
            self.kernel_collection,
            self.sandbox_kext,
            self.userland,
            self.profiles_dir,
            self.compiled_textedit,
            self.system_version,
        ]
        if import_target == "amfi_kext":
            paths.append(self.amfi_kext)
        return [p for p in paths if not p.exists()]


@dataclass(frozen=True)
class TaskConfig:
    """Definition of a headless task: which script to run, where to import from, and where to write."""
    name: str
    script: str
    import_target: str
    description: str
    out_root: Path | None = None

    def script_path(self) -> Path:
        return SCRIPTS_DIR / self.script


TASKS: Dict[str, TaskConfig] = {
    "kernel-symbols": TaskConfig(
        name="kernel-symbols",
        script="kernel_symbols.py",
        import_target="kernel",
        description="Import KC and dump symbols/strings for com.apple.security.sandbox.",
        out_root=KERNEL_SYMBOLS_OUT_ROOT,
    ),
    "kernel-collection-symbols": TaskConfig(
        name="kernel-collection-symbols",
        script="kernel_symbols.py",
        import_target="kernel_collection",
        description="Dump symbols/strings for com.apple.security.sandbox in the KC.",
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
    "kernel-collection-function-dump": TaskConfig(
        name="kernel-collection-function-dump",
        script="kernel_function_dump.py",
        import_target="kernel_collection",
        description="Dump disassembly for specified functions/addresses in the KC.",
    ),
    "kernel-collection-addr-window-dump": TaskConfig(
        name="kernel-collection-addr-window-dump",
        script="kernel_addr_window_dump.py",
        import_target="kernel_collection",
        description="Dump an instruction window around a KC address.",
    ),
    "kernel-imports": TaskConfig(
        name="kernel-imports",
        script="kernel_imports_scan.py",
        import_target="kernel",
        description="Enumerate external symbols/imports and their references.",
    ),
    "kernel-collection-imports": TaskConfig(
        name="kernel-collection-imports",
        script="kernel_imports_scan.py",
        import_target="kernel_collection",
        description="Enumerate external symbols/imports and their references in the KC.",
    ),
    "kernel-collection-stub-got-map": TaskConfig(
        name="kernel-collection-stub-got-map",
        script="kernel_stub_got_map.py",
        import_target="kernel_collection",
        description="Map KC stubs/trampolines to GOT entries (auth_got/auth_ptr/got).",
    ),
    "kernel-collection-stub-call-sites": TaskConfig(
        name="kernel-collection-stub-call-sites",
        script="kernel_stub_call_sites.py",
        import_target="kernel_collection",
        description="Scan KC for BL/B call sites targeting stub/trampoline addresses.",
    ),
    "kernel-mac-policy-register": TaskConfig(
        name="kernel-mac-policy-register",
        script="mac_policy_register_scan.py",
        import_target="kernel_collection",
        description="Locate mac_policy_register call sites and recover arg pointers in the KC.",
    ),
    "kernel-collection-string-call-sites": TaskConfig(
        name="kernel-collection-string-call-sites",
        script="kernel_string_call_sites.py",
        import_target="kernel_collection",
        description="Find functions referencing strings and list call sites in the KC.",
    ),
    "kernel-collection-jump-table-read": TaskConfig(
        name="kernel-collection-jump-table-read",
        script="kernel_jump_table_read.py",
        import_target="kernel_collection",
        description="Read a signed-32 jump table and resolve targets in the KC.",
    ),
    "kernel-collection-syscall-code-scan": TaskConfig(
        name="kernel-collection-syscall-code-scan",
        script="sandbox_syscall_code_scan.py",
        import_target="kernel_collection",
        description="Scan the KC for compare-like uses of a syscall call code.",
    ),
    "kernel-mac-policy-register-anchor": TaskConfig(
        name="kernel-mac-policy-register-anchor",
        script="kernel_anchor_mac_policy_register.py",
        import_target="kernel_collection",
        description="Rename and apply signature to mac_policy_register anchor in the KC.",
    ),
    "kernel-mac-policy-register-instances": TaskConfig(
        name="kernel-mac-policy-register-instances",
        script="kernel_mac_policy_register_instances.py",
        import_target="kernel_collection",
        description="Recover mac_policy_register instances and decode mac_policy_conf fields.",
    ),
    "kernel-block-disasm": TaskConfig(
        name="kernel-block-disasm",
        script="kernel_block_disasm.py",
        import_target="kernel",
        description="Disassemble across matching KC memory blocks (prepares follow-on scans).",
    ),
    "kernel-addr-lookup": TaskConfig(
        name="kernel-addr-lookup",
        script="kernel_addr_lookup.py",
        import_target="kernel",
        description="Lookup file offsets/constants to map to addresses/functions/callers.",
    ),
    "sandbox-kext-addr-lookup": TaskConfig(
        name="sandbox-kext-addr-lookup",
        script="kernel_addr_lookup.py",
        import_target="sandbox_kext",
        description="Lookup addresses/constants inside sandbox_kext.",
    ),
    "sandbox-kext-addr-window-dump": TaskConfig(
        name="sandbox-kext-addr-window-dump",
        script="kernel_addr_window_dump.py",
        import_target="sandbox_kext",
        description="Dump an instruction window around a sandbox_kext address.",
    ),
    "kernel-adrp-add-scan": TaskConfig(
        name="kernel-adrp-add-scan",
        script="kernel_adrp_add_scan.py",
        import_target="kernel",
        description="Locate ADRP+ADD/SUB sequences that materialize a target address.",
    ),
    "kernel-adrp-ldr-scan": TaskConfig(
        name="kernel-adrp-ldr-scan",
        script="kernel_adrp_ldr_scan.py",
        import_target="kernel",
        description="Locate ADRP+LDR sequences that load a target address.",
    ),
    "sandbox-kext-adrp-add-scan": TaskConfig(
        name="sandbox-kext-adrp-add-scan",
        script="kernel_adrp_add_scan.py",
        import_target="sandbox_kext",
        description="Locate ADRP+ADD/SUB sequences in sandbox_kext for a target address.",
    ),
    "sandbox-kext-adrp-ldr-scan": TaskConfig(
        name="sandbox-kext-adrp-ldr-scan",
        script="kernel_adrp_ldr_scan.py",
        import_target="sandbox_kext",
        description="Locate ADRP+LDR sequences in sandbox_kext for a target address.",
    ),
    "sandbox-kext-adrp-ldr-got-scan": TaskConfig(
        name="sandbox-kext-adrp-ldr-got-scan",
        script="kernel_adrp_ldr_scan.py",
        import_target="sandbox_kext",
        description="Locate ADRP+LDR sequences in sandbox_kext that land in __auth_got.",
    ),
    "kernel-function-info": TaskConfig(
        name="kernel-function-info",
        script="kernel_function_info.py",
        import_target="kernel",
        description="Emit metadata for specified functions (callers, callees, size).",
    ),
    "kernel-collection-function-info": TaskConfig(
        name="kernel-collection-function-info",
        script="kernel_function_info.py",
        import_target="kernel_collection",
        description="Emit metadata for specified functions in the KC (callers, callees, size).",
    ),
    "sandbox-kext-conf-scan": TaskConfig(
        name="sandbox-kext-conf-scan",
        script="sandbox_kext_conf_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox kext data segments for mac_policy_conf candidates.",
    ),
    "sandbox-kext-symbols": TaskConfig(
        name="sandbox-kext-symbols",
        script="kernel_symbols.py",
        import_target="sandbox_kext",
        description="Emit symbol/string tables for sandbox_kext.",
    ),
    "sandbox-kext-mac-policy-register": TaskConfig(
        name="sandbox-kext-mac-policy-register",
        script="mac_policy_register_scan.py",
        import_target="sandbox_kext",
        description="Locate mac_policy_register call sites inside sandbox_kext.bin.",
    ),
    "sandbox-kext-block-disasm": TaskConfig(
        name="sandbox-kext-block-disasm",
        script="kernel_block_disasm.py",
        import_target="sandbox_kext",
        description="Disassemble across matching sandbox kext blocks (e.g., __stubs).",
    ),
    "sandbox-kext-function-dump": TaskConfig(
        name="sandbox-kext-function-dump",
        script="kernel_function_dump.py",
        import_target="sandbox_kext",
        description="Dump disassembly for specified functions/addresses in sandbox_kext.",
    ),
    "sandbox-kext-stub-got-map": TaskConfig(
        name="sandbox-kext-stub-got-map",
        script="kernel_stub_got_map.py",
        import_target="sandbox_kext",
        description="Map sandbox kext stubs to GOT entries (auth_got/auth_ptr/got).",
    ),
    "sandbox-kext-got-ref-sweep": TaskConfig(
        name="sandbox-kext-got-ref-sweep",
        script="kernel_got_ref_sweep.py",
        import_target="sandbox_kext",
        description="Define GOT entries and collect references in sandbox_kext.",
    ),
    "sandbox-kext-got-load-sweep": TaskConfig(
        name="sandbox-kext-got-load-sweep",
        script="kernel_got_load_sweep.py",
        import_target="sandbox_kext",
        description="Scan code for GOT loads or direct refs in sandbox_kext.",
    ),
    "sandbox-kext-imm-search": TaskConfig(
        name="sandbox-kext-imm-search",
        script="kernel_imm_search.py",
        import_target="sandbox_kext",
        description="Search sandbox_kext instructions for a given immediate value.",
    ),
    "sandbox-kext-op-table": TaskConfig(
        name="sandbox-kext-op-table",
        script="kernel_op_table.py",
        import_target="sandbox_kext",
        description="Surface pointer-table candidates inside sandbox_kext segments.",
    ),
    "sandbox-kext-pointer-value-scan": TaskConfig(
        name="sandbox-kext-pointer-value-scan",
        script="kernel_pointer_value_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox_kext memory for a specific pointer value.",
    ),
    "sandbox-kext-jump-table-dump": TaskConfig(
        name="sandbox-kext-jump-table-dump",
        script="kernel_jump_table_dump.py",
        import_target="sandbox_kext",
        description="Dump jump-table entries for sandbox_kext dispatcher candidates.",
    ),
    "sandbox-kext-jump-table-read": TaskConfig(
        name="sandbox-kext-jump-table-read",
        script="kernel_jump_table_read.py",
        import_target="sandbox_kext",
        description="Read a signed-32 jump table and resolve targets in sandbox_kext.",
    ),
    "sandbox-kext-syscall-code-scan": TaskConfig(
        name="sandbox-kext-syscall-code-scan",
        script="sandbox_syscall_code_scan.py",
        import_target="sandbox_kext",
        description="Scan sandbox_kext for compare-like uses of a syscall call code.",
    ),
    "kernel-imm-search": TaskConfig(
        name="kernel-imm-search",
        script="kernel_imm_search.py",
        import_target="kernel",
        description="Search instructions for a given immediate (scalar) value.",
    ),
    "kernel-arm-const-base-scan": TaskConfig(
        name="kernel-arm-const-base-scan",
        script="kernel_arm_const_base_scan.py",
        import_target="kernel",
        description="Scan ADRP base materializations into a target address range.",
    ),
    "sandbox-kext-arm-const-base-scan": TaskConfig(
        name="sandbox-kext-arm-const-base-scan",
        script="kernel_arm_const_base_scan.py",
        import_target="sandbox_kext",
        description="Scan ADRP base materializations into a target address range in sandbox_kext.",
    ),
    "kernel-field2-mask-scan": TaskConfig(
        name="kernel-field2-mask-scan",
        script="kernel_field2_mask_scan.py",
        import_target="kernel",
        description="Search sandbox code for mask immediates (field2/filter_arg flags).",
    ),
    "kernel-data-define": TaskConfig(
        name="kernel-data-define",
        script="kernel_data_define_and_refs.py",
        import_target="kernel",
        description="Define data at given addresses and dump references (for pointer/table pivots).",
    ),
    "sandbox-kext-data-define": TaskConfig(
        name="sandbox-kext-data-define",
        script="kernel_data_define_and_refs.py",
        import_target="sandbox_kext",
        description="Define data at given addresses in sandbox_kext and dump references.",
    ),
    "sandbox-kext-string-refs": TaskConfig(
        name="sandbox-kext-string-refs",
        script="kernel_string_refs.py",
        import_target="sandbox_kext",
        description="Resolve references to key sandbox strings inside sandbox_kext.bin.",
    ),
    "amfi-kext-block-disasm": TaskConfig(
        name="amfi-kext-block-disasm",
        script="kernel_block_disasm.py",
        import_target="amfi_kext",
        description="Disassemble across matching AMFI kext blocks (prepares follow-on scans).",
    ),
    "amfi-kext-mac-policy-register": TaskConfig(
        name="amfi-kext-mac-policy-register",
        script="mac_policy_register_scan.py",
        import_target="amfi_kext",
        description="Locate mac_policy_register call sites inside AMFI kext slice.",
    ),
    "amfi-kext-got-ref-sweep": TaskConfig(
        name="amfi-kext-got-ref-sweep",
        script="kernel_got_ref_sweep.py",
        import_target="amfi_kext",
        description="Define GOT entries and collect references in AMFI kext slice.",
    ),
    "amfi-kext-got-load-sweep": TaskConfig(
        name="amfi-kext-got-load-sweep",
        script="kernel_got_load_sweep.py",
        import_target="amfi_kext",
        description="Scan code for GOT loads or direct refs in AMFI kext slice.",
    ),
    "amfi-kext-function-dump": TaskConfig(
        name="amfi-kext-function-dump",
        script="kernel_function_dump.py",
        import_target="amfi_kext",
        description="Dump disassembly for specified AMFI kext functions/addresses.",
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
    pre_scripts: List[str] | None,
    project_name: str,
) -> Tuple[List[str], Path]:
    import_path = getattr(build, task.import_target)
    out_root = task.out_root if task.out_root else OUT_ROOT
    out_dir = out_root / build.build_id / task.name
    ensure_under(out_dir, out_root)
    headless = resolve_headless_path(ghidra_headless, require_exists=False)
    project_dir = PROJECTS_ROOT
    # Full import + analysis run that overwrites the program and runs our postScript.
    cmd = [str(headless), str(project_dir), project_name, "-overwrite"]
    if processor:
        cmd.extend(["-processor", processor])
    if no_analysis:
        cmd.append("-noanalysis")
    if analysis_properties:
        cmd.extend(["-analysisProperties", str(analysis_properties)])
    if pre_scripts:
        for script in pre_scripts:
            cmd.extend(["-preScript", script])
    if vm_path:
        cmd.extend(["-vmPath", str(vm_path)])
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
    return cmd, out_dir


def build_process_command(
    task: TaskConfig,
    build: BuildPaths,
    ghidra_headless: str | None,
    vm_path: Path | None,
    no_analysis: bool,
    script_args: List[str],
    analysis_properties: str | None,
    pre_scripts: List[str] | None,
    project_name: str,
) -> Tuple[List[str], Path]:
    import_path = getattr(build, task.import_target)
    out_root = task.out_root if task.out_root else OUT_ROOT
    out_dir = out_root / build.build_id / task.name
    ensure_under(out_dir, out_root)
    headless = resolve_headless_path(ghidra_headless, require_exists=False)
    project_dir = PROJECTS_ROOT
    # Script-only pass against an already-imported project (no overwrite).
    cmd = [str(headless), str(project_dir), project_name]
    if no_analysis:
        cmd.append("-noanalysis")
    if analysis_properties:
        cmd.extend(["-analysisProperties", str(analysis_properties)])
    if pre_scripts:
        for script in pre_scripts:
            cmd.extend(["-preScript", script])
    if vm_path:
        cmd.extend(["-vmPath", str(vm_path)])
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
        default=str(GHIDRA_ROOT / "user"),
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
        "--pre-script",
        nargs="*",
        default=[],
        help="One or more Ghidra preScripts to run before analysis (e.g., disable_x86_analyzers.py).",
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
    missing = build.missing(task.import_target)
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
            args.pre_script,
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
            args.pre_script,
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
    # Pin HOME/temp to repo-local dirs so Ghidra does not write under the real user home (often blocked).
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
