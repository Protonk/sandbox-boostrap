"""
Run the DTrace probe for mac_policy_register and normalize the output.

This is a convenience wrapper around:
- a generated DTrace script (provider/function) that emits EVENT lines
- normalize.py (turns raw logs into schema-shaped JSON)
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import subprocess
import sys
from typing import Optional

from book.api import path_utils


def _load_normalize() -> object:
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("runtime_mac_policy.normalize", here / "normalize.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load normalize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


normalize = _load_normalize()

DTRACE_BIN = "/usr/sbin/dtrace"


def run_dtrace(
    raw_out: pathlib.Path,
    target_func: str,
    provider: str,
    target_mod: str,
    run_command: str | None,
    exit_after_one: bool,
) -> None:
    probe = f"{provider}:{target_mod}:{target_func}:entry"
    if target_mod == "":
        probe = f"{provider}::{target_func}:entry"
    script_lines = [
        "#pragma D option quiet",
        f"{probe}",
        "{",
        '    printf("EVENT target_symbol=%s mpc=%p handlep=%p xd=%p\\n", probefunc, arg0, arg1, arg2);',
    ]
    if exit_after_one:
        script_lines.append("    exit(0);")
    script_lines.append("}")
    script_text = "\n".join(script_lines) + "\n"

    script_path = raw_out.parent / "dtrace_tmp.d"
    script_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(script_text)

    cmd = [DTRACE_BIN, "-q", "-s", str(script_path)]
    if run_command:
        cmd.extend(["-c", run_command])
    raw_out.parent.mkdir(parents=True, exist_ok=True)
    with raw_out.open("w") as log:
        subprocess.run(cmd, stdout=log, check=True)


def normalize_log(
    repo_root: pathlib.Path,
    raw_path: pathlib.Path,
    out_path: pathlib.Path,
    runtime_world_id: str,
    os_build: Optional[str],
    kernel_version: Optional[str],
    bootkc_uuid: Optional[str],
    bootkc_hash: Optional[str],
    sandbox_kext_uuid: Optional[str],
    sandbox_kext_hash: Optional[str],
    kaslr_slide: Optional[str],
    sip_config: Optional[str],
    tracing_config: Optional[str],
) -> None:
    with raw_path.open() as f:
        events = normalize.parse_raw_log(f.readlines())

    static_refs = normalize.resolve_default_static_refs(repo_root)
    output = normalize.build_output(
        events=events,
        runtime_world_id=runtime_world_id,
        os_build=os_build,
        kernel_version=kernel_version,
        bootkc_uuid=bootkc_uuid,
        bootkc_hash=bootkc_hash,
        sandbox_kext_uuid=sandbox_kext_uuid,
        sandbox_kext_hash=sandbox_kext_hash,
        kaslr_slide=kaslr_slide,
        sip_config=sip_config,
        tracing_config=tracing_config,
        static_refs=static_refs,
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(output, f, indent=2, sort_keys=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run mac_policy_register DTrace capture and normalize output.")
    parser.add_argument("--target-func", default="mac_policy_register", help="Target function name for fbt probe.")
    parser.add_argument(
        "--provider",
        default="fbt",
        help="DTrace provider (default fbt; use syscall for fallback testing).",
    )
    parser.add_argument(
        "--target-mod",
        default="kernel",
        help="DTrace module for the probe (blank for syscall provider).",
    )
    parser.add_argument(
        "--run-command",
        default=None,
        help="Optional command to run under dtrace (-c). If omitted, dtrace runs until interrupted.",
    )
    parser.add_argument(
        "--exit-after-one",
        action="store_true",
        help="Request the DTrace script to exit after the first matched event.",
    )
    parser.add_argument(
        "--raw-out",
        default="book/evidence/experiments/runtime-final-final/suites/nonbaseline/runtime-mac_policy/out/raw/mac_policy.log",
        help="Path to write raw DTrace output.",
    )
    parser.add_argument(
        "--json-out",
        default="book/evidence/experiments/runtime-final-final/suites/nonbaseline/runtime-mac_policy/out/runtime_mac_policy_registration.json",
        help="Path to write normalized JSON.",
    )
    parser.add_argument("--runtime-world-id", required=True, help="Runtime world identifier for this capture.")
    parser.add_argument("--os-build", default=None, help="OS build string.")
    parser.add_argument("--kernel-version", default=None, help="Kernel version string.")
    parser.add_argument("--bootkc-uuid", default=None, help="BootKC UUID.")
    parser.add_argument("--bootkc-hash", default=None, help="BootKC hash.")
    parser.add_argument("--sandbox-kext-uuid", default=None, help="Sandbox kext UUID.")
    parser.add_argument("--sandbox-kext-hash", default=None, help="Sandbox kext hash.")
    parser.add_argument("--kaslr-slide", default=None, help="KASLR slide (hex string).")
    parser.add_argument("--sip-config", default=None, help="SIP/AMFI configuration.")
    parser.add_argument("--tracing-config", default=None, help="Tracing configuration used for DTrace.")
    parser.add_argument(
        "--skip-dtrace",
        action="store_true",
        help="Skip running DTrace and only normalize an existing raw log.",
    )
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root()
    raw_out = path_utils.ensure_absolute(repo_root / args.raw_out)
    json_out = path_utils.ensure_absolute(repo_root / args.json_out)

    if not args.skip_dtrace:
        run_dtrace(
            raw_out=raw_out,
            target_func=args.target_func,
            provider=args.provider,
            target_mod=args.target_mod,
            run_command=args.run_command,
            exit_after_one=args.exit_after_one,
        )

    normalize_log(
        repo_root=repo_root,
        raw_path=raw_out,
        out_path=json_out,
        runtime_world_id=args.runtime_world_id,
        os_build=args.os_build,
        kernel_version=args.kernel_version,
        bootkc_uuid=args.bootkc_uuid,
        bootkc_hash=args.bootkc_hash,
        sandbox_kext_uuid=args.sandbox_kext_uuid,
        sandbox_kext_hash=args.sandbox_kext_hash,
        kaslr_slide=args.kaslr_slide,
        sip_config=args.sip_config,
        tracing_config=args.tracing_config,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
