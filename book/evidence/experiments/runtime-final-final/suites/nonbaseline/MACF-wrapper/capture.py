"""
Run the MACF wrapper probes (hooks + syscall context) and normalize output.

Events are filtered to the traced process (`pid == $target`). The generated
DTrace script logs both MACF hooks and related syscalls for correlation.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import subprocess
from typing import List, Tuple

from book.api import path_utils


def _load_normalize():
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("macf_wrapper.normalize", here / "normalize.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load normalize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


normalize = _load_normalize()

DTRACE_BIN = "/usr/sbin/dtrace"
DEFAULT_HOOKS_FILE = "book/evidence/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/meta/selected_hooks.json"
DEFAULT_WORLD_ID = "sonoma-14.6.1-debug-vm"


def load_selected_hooks(path: pathlib.Path) -> Tuple[str, str, str | None, List[str]]:
    if not path.exists():
        raise FileNotFoundError(f"Selected hooks file not found: {path}")
    data = json.loads(path.read_text())
    hooks = data.get("hooks") or []
    if not hooks:
        raise ValueError("No hooks defined in selected hooks file")
    provider = data.get("provider", "fbt")
    module = data.get("module", "mach_kernel")
    world_id = data.get("world_id")
    return provider, module, world_id, hooks


def render_dtrace_script(
    *,
    provider: str,
    module: str,
    hooks: List[str],
    runtime_world_id: str,
    run_id: str,
    exit_after_one: bool,
) -> str:
    lines: List[str] = [
        "#pragma D option quiet",
        f'inline string WORLD_ID = "{runtime_world_id}";',
        f'inline string RUN_ID = "{run_id}";',
    ]

    if "mac_vnode_check_open" in hooks:
        lines.extend(
            [
                f"{provider}:{module}:mac_vnode_check_open:entry",
                "/pid == $target/",
                "{",
                "    this->ts = timestamp;",
                '    printf("EVENT kind=hook hook=mac_vnode_check_open world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu ctx=0x%p vp=0x%p acc_mode=%d\\n",',
                "        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, (void *)arg0, (void *)arg1, (int)arg2);",
                "    " + ("exit(0);" if exit_after_one else ""),
                "}",
            ]
        )

    if "mac_vnop_setxattr" in hooks:
        lines.extend(
            [
                f"{provider}:{module}:mac_vnop_setxattr:entry",
                "/pid == $target/",
                "{",
                "    this->ts = timestamp;",
                '    printf("EVENT kind=hook hook=mac_vnop_setxattr world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu vp=0x%p name_ptr=0x%p buf_ptr=0x%p len=%llu\\n",',
                "        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, (void *)arg0, (void *)arg1, (void *)arg2, (unsigned long long)arg3);",
                "    " + ("exit(0);" if exit_after_one else ""),
                "}",
            ]
        )

    lines.extend(
        [
            "syscall::open*:entry",
            "/pid == $target/",
            "{",
            "    this->ts = timestamp;",
            '    printf("EVENT kind=syscall sys=open world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu path=%s flags=0x%x\\n",',
            "        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, copyinstr(arg0), (int)arg1);",
            "}",
            "",
            "syscall::setxattr:entry",
            "/pid == $target/",
            "{",
            "    this->ts = timestamp;",
            '    printf("EVENT kind=syscall sys=setxattr world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu path=%s name=%s size=%llu\\n",',
            "        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, copyinstr(arg0), copyinstr(arg1), (unsigned long long)arg4);",
            "}",
            "",
            "syscall::fsetxattr:entry",
            "/pid == $target/",
            "{",
            "    this->ts = timestamp;",
            '    printf("EVENT kind=syscall sys=fsetxattr world=%s run_id=%s pid=%d tid=%d exec=%s ts=%llu fd=%d name=%s size=%llu\\n",',
            "        WORLD_ID, RUN_ID, pid, tid, execname, this->ts, (int)arg0, copyinstr(arg1), (unsigned long long)arg4);",
            "}",
        ]
    )

    return "\n".join(lines) + "\n"


def run_dtrace(*, raw_out: pathlib.Path, script_text: str, run_command: str | None, target_pid: int | None) -> None:
    if not run_command and target_pid is None:
        raise ValueError("Provide either --run-command or --target-pid to set $target")
    script_path = raw_out.parent / "dtrace_tmp.d"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(script_text)

    cmd = [DTRACE_BIN, "-q", "-s", str(script_path)]
    if run_command:
        cmd.extend(["-c", run_command])
    elif target_pid is not None:
        cmd.extend(["-p", str(target_pid)])

    raw_out.parent.mkdir(parents=True, exist_ok=True)
    with raw_out.open("w") as log:
        subprocess.run(cmd, stdout=log, check=True)


def normalize_log(
    *,
    repo_root: pathlib.Path,
    raw_path: pathlib.Path,
    out_path: pathlib.Path,
    runtime_world_id: str,
    run_id: str,
    os_build: str | None,
    kernel_version: str | None,
    provider: str,
    module: str,
    hooks: List[str],
    run_command: str | None,
    target_pid: int | None,
    scenario: str | None,
    scenario_description: str | None,
    summary_path: pathlib.Path | None,
) -> None:
    with raw_path.open() as f:
        events = normalize.parse_raw_log(f.readlines())

    static_refs = normalize.resolve_default_static_refs(repo_root)
    output = normalize.build_output(
        events=events,
        runtime_world_id=runtime_world_id,
        run_id=run_id,
        os_build=os_build,
        kernel_version=kernel_version,
        provider=provider,
        module=module,
        hooks=hooks,
        run_command=run_command,
        target_pid=target_pid,
        static_refs=static_refs,
        scenario=scenario,
        scenario_description=scenario_description,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(output, f, indent=2, sort_keys=True)
    if summary_path:
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("w") as f:
            json.dump(output.get("summary", {}), f, indent=2, sort_keys=True)


def write_manifest(
    *,
    meta_path: pathlib.Path,
    runtime_world_id: str,
    run_id: str,
    provider: str,
    module: str,
    hooks: List[str],
    raw_out: pathlib.Path,
    json_out: pathlib.Path,
    run_command: str | None,
    target_pid: int | None,
    scenario: str | None,
    scenario_description: str | None,
    summary_path: pathlib.Path | None,
) -> None:
    meta = {
        "runtime_world_id": runtime_world_id,
        "run_id": run_id,
        "provider": provider,
        "module": module,
        "hooks": hooks,
        "raw_log": path_utils.to_repo_relative(raw_out),
        "json_output": path_utils.to_repo_relative(json_out),
        "run_command": run_command,
        "target_pid": target_pid,
        "scenario": scenario,
        "scenario_description": scenario_description,
        "summary": path_utils.to_repo_relative(summary_path) if summary_path else None,
    }
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run MACF wrapper DTrace capture and normalize output.")
    parser.add_argument("--run-id", required=True, help="Run identifier for output filenames.")
    parser.add_argument("--runtime-world-id", default=None, help="Runtime world identifier (overrides hooks file).")
    parser.add_argument("--hooks-file", default=DEFAULT_HOOKS_FILE, help="Path to selected_hooks.json.")
    parser.add_argument("--hooks", nargs="*", default=None, help="Override hook list (space-separated names).")
    parser.add_argument("--provider", default=None, help="Override provider (default from hooks file).")
    parser.add_argument("--module", default=None, help="Override module (default from hooks file).")
    parser.add_argument("--run-command", default=None, help="Command to run under tracing (-c).")
    parser.add_argument("--target-pid", type=int, default=None, help="Attach to an existing pid (-p).")
    parser.add_argument("--exit-after-one", action="store_true", help="Exit after the first matching hook event.")
    parser.add_argument("--raw-out", default=None, help="Raw log output path (defaults to out/raw/<run_id>.log).")
    parser.add_argument("--json-out", default=None, help="Normalized JSON output path (defaults to out/json/<run_id>.json).")
    parser.add_argument("--meta-out", default=None, help="Run manifest path (defaults to out/meta/<run_id>.json).")
    parser.add_argument("--os-build", default=None, help="OS build string.")
    parser.add_argument("--kernel-version", default=None, help="Kernel version string.")
    parser.add_argument("--skip-dtrace", action="store_true", help="Skip running DTrace and only normalize.")
    parser.add_argument("--scenario", default=None, help="Scenario identifier for this run.")
    parser.add_argument("--scenario-description", default=None, help="Scenario description.")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    hooks_file = path_utils.ensure_absolute(repo_root / args.hooks_file)
    provider_default, module_default, world_default, hooks_default = load_selected_hooks(hooks_file)

    hooks = hooks_default if args.hooks is None or len(args.hooks) == 0 else list(args.hooks)
    provider = args.provider or provider_default
    module = args.module or module_default
    runtime_world_id = args.runtime_world_id or world_default or DEFAULT_WORLD_ID

    raw_out_rel = args.raw_out or f"book/evidence/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/raw/{args.run_id}.log"
    json_out_rel = args.json_out or f"book/evidence/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/json/{args.run_id}.json"
    meta_out_rel = args.meta_out or f"book/evidence/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/meta/{args.run_id}.json"
    summary_rel = f"book/evidence/experiments/runtime-final-final/suites/nonbaseline/MACF-wrapper/out/meta/{args.run_id}_summary.json"

    raw_out = path_utils.ensure_absolute(repo_root / raw_out_rel)
    json_out = path_utils.ensure_absolute(repo_root / json_out_rel)
    meta_out = path_utils.ensure_absolute(repo_root / meta_out_rel)
    summary_out = path_utils.ensure_absolute(repo_root / summary_rel)

    run_command = args.run_command
    target_pid = args.target_pid

    if not args.skip_dtrace:
        script_text = render_dtrace_script(
            provider=provider,
            module=module,
            hooks=hooks,
            runtime_world_id=runtime_world_id,
            run_id=args.run_id,
            exit_after_one=args.exit_after_one,
        )
        run_dtrace(raw_out=raw_out, script_text=script_text, run_command=run_command, target_pid=target_pid)

    normalize_log(
        repo_root=repo_root,
        raw_path=raw_out,
        out_path=json_out,
        runtime_world_id=runtime_world_id,
        run_id=args.run_id,
        os_build=args.os_build,
        kernel_version=args.kernel_version,
        provider=provider,
        module=module,
        hooks=hooks,
        run_command=run_command,
        target_pid=target_pid,
        scenario=args.scenario,
        scenario_description=args.scenario_description,
        summary_path=summary_out,
    )

    write_manifest(
        meta_path=meta_out,
        runtime_world_id=runtime_world_id,
        run_id=args.run_id,
        provider=provider,
        module=module,
        hooks=hooks,
        raw_out=raw_out,
        json_out=json_out,
        run_command=run_command,
        target_pid=target_pid,
        scenario=args.scenario,
        scenario_description=args.scenario_description,
        summary_path=summary_out,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
