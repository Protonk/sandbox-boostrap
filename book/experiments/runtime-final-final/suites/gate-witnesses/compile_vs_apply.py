#!/usr/bin/env python3
"""
Compile-vs-apply split for apply-gate witnesses.

Goal: answer the concrete fork:
  - Is the gate enforced at compile time (libsandbox sandbox_compile_*)?
  - Or at apply time (sandbox_apply / attach/validation step)?

This script is contract-driven:
- compile is observed via wrapper-emitted tool:"sbpl-compile" markers
- apply/exec phases are observed via tool:"sbpl-apply" markers and the runtime contract upgrader
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.contracts import schema as rt_contract
from book.api.runtime.contracts import models as rt_models


EPERM = 1


@dataclass(frozen=True)
class RunResult:
    cmd: List[str]
    rc: int
    stdout: str
    stderr_raw: str

    @property
    def stderr_canonical(self) -> str:
        return rt_contract.strip_tool_markers(self.stderr_raw) or ""


def _run(cmd: List[str], timeout_sec: int = 10) -> RunResult:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    return RunResult(cmd=cmd, rc=proc.returncode, stdout=proc.stdout or "", stderr_raw=proc.stderr or "")


def _sanitize_text(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    prefix = str(REPO_ROOT) + "/"
    return value.replace(prefix, "")


def _sanitize_compile_marker(marker: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(marker, dict):
        return None
    out: Dict[str, Any] = {
        "marker_schema_version": marker.get("marker_schema_version"),
        "stage": marker.get("stage"),
        "api": marker.get("api"),
        "rc": marker.get("rc"),
        "errno": marker.get("errno"),
        "errbuf": _sanitize_text(marker.get("errbuf")),
        "profile": None,
        "profile_type": marker.get("profile_type"),
        "bytecode_length": marker.get("bytecode_length"),
    }
    profile = marker.get("profile")
    if isinstance(profile, str):
        out["profile"] = path_utils.to_repo_relative(Path(profile), REPO_ROOT)
    return out


def _compile_report(stderr_raw: str) -> Dict[str, Any]:
    markers = rt_contract.extract_sbpl_compile_markers(stderr_raw)
    marker = markers[0] if markers else None
    marker_sanitized = _sanitize_compile_marker(marker)
    return {
        "marker": marker_sanitized,
        "marker_count": len(markers),
        "rc": marker_sanitized.get("rc") if isinstance(marker_sanitized, dict) else None,
        "errno": marker_sanitized.get("errno") if isinstance(marker_sanitized, dict) else None,
        "errbuf": marker_sanitized.get("errbuf") if isinstance(marker_sanitized, dict) else None,
        "profile_type": marker_sanitized.get("profile_type") if isinstance(marker_sanitized, dict) else None,
        "bytecode_length": marker_sanitized.get("bytecode_length") if isinstance(marker_sanitized, dict) else None,
    }


def _apply_report(stderr_raw: str) -> Dict[str, Any]:
    upgraded = rt_contract.upgrade_runtime_result({}, stderr_raw)
    return {
        "failure_stage": upgraded.get("failure_stage"),
        "failure_kind": upgraded.get("failure_kind"),
        "apply_report": upgraded.get("apply_report"),
    }


def _is_compile_gate_eperm(report: Dict[str, Any]) -> bool:
    return report.get("rc") not in (0, None) and report.get("errno") == EPERM


def _is_apply_gate_eperm(report: Dict[str, Any]) -> bool:
    if report.get("failure_stage") != "apply":
        return False
    apply = report.get("apply_report")
    return isinstance(apply, dict) and apply.get("errno") == EPERM


def _rel(path: Path, root: Path) -> str:
    return path_utils.to_repo_relative(path, root)


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _write_variant_files(out_dir: Path) -> List[Dict[str, Any]]:
    """
    Micro-variants off the minimal failing construct.

    Keep each variant as a single targeted edit so outcomes are easy to interpret.
    """

    variants: List[Dict[str, Any]] = []

    base_v2 = "(version 2)\n(allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))\n"
    base_v1 = "(version 1)\n(allow iokit-open-user-client (apply-message-filter (deny iokit-external-method)))\n"
    base_v2_mach_bootstrap = (
        "(version 2)\n"
        "(allow mach-bootstrap\n"
        "    (apply-message-filter (with report)\n"
        "        (deny mach-message-send)\n"
        "        (allow mach-message-send (message-number 207))\n"
        "    )\n"
        ")\n"
    )

    candidates = [
        ("base_v2", base_v2, "baseline (matches airlock/cgpdfservice witness form)"),
        ("base_v2_outer_iokit_open", base_v2.replace("iokit-open-user-client", "iokit-open", 1), "swap outer op"),
        ("base_v2_inner_allow_external_method", base_v2.replace("(deny iokit-external-method)", "(allow iokit-external-method)", 1), "swap inner deny->allow"),
        ("base_v2_inner_deny_async_external_method", base_v2.replace("iokit-external-method", "iokit-async-external-method", 1), "swap inner op"),
        ("base_v2_inner_deny_external_trap", base_v2.replace("iokit-external-method", "iokit-external-trap", 1), "swap inner op"),
        (
            "base_v2_mach_bootstrap_deny_message_send",
            base_v2_mach_bootstrap,
            "scope: mach-bootstrap message filter with deny",
        ),
        (
            "base_v2_mach_bootstrap_allow_only",
            base_v2_mach_bootstrap.replace("(deny mach-message-send)\n", ""),
            "scope: mach-bootstrap message filter allow-only",
        ),
        (
            "base_v2_mach_bootstrap_allow_only_with_file_write",
            base_v2_mach_bootstrap.replace("(deny mach-message-send)\n", "") + "(allow file-write*)\n",
            "scope: mach-bootstrap allow-only + allow file-write* (so markers survive post-apply)",
        ),
        ("base_v1", base_v1, "baseline (matches blastdoor witness version)"),
        ("base_v1_outer_iokit_open", base_v1.replace("iokit-open-user-client", "iokit-open", 1), "swap outer op"),
        ("base_v1_inner_allow_external_method", base_v1.replace("(deny iokit-external-method)", "(allow iokit-external-method)", 1), "swap inner deny->allow"),
        ("base_v1_inner_deny_async_external_method", base_v1.replace("iokit-external-method", "iokit-async-external-method", 1), "swap inner op"),
        ("base_v1_inner_deny_external_trap", base_v1.replace("iokit-external-method", "iokit-external-trap", 1), "swap inner op"),
    ]

    _ensure_dir(out_dir)
    for variant_id, sbpl, note in candidates:
        path = out_dir / f"{variant_id}.sb"
        path.write_text(sbpl, encoding="utf-8")
        variants.append({"id": variant_id, "path": path, "note": note})
    return variants


def main() -> int:
    root = path_utils.find_repo_root(Path(__file__))
    wrapper = root / "book/tools/sbpl/wrapper/wrapper"
    witness_root = root / "book/experiments/runtime-final-final/suites/gate-witnesses/out/witnesses"
    out_dir = root / "book/experiments/runtime-final-final/suites/gate-witnesses/out"
    variants_dir = out_dir / "micro_variants"

    if not wrapper.exists():
        raise SystemExit(f"missing wrapper binary: {wrapper}")
    if not witness_root.exists():
        raise SystemExit(f"missing witness root: {witness_root}")

    results: Dict[str, Any] = {
        "world_id": rt_models.WORLD_ID,
        "wrapper": _rel(wrapper, root),
        "witnesses": [],
        "micro_variants": [],
    }

    # 1) Witness corpus: compile + apply (via sandbox_apply on compiled blob).
    for target_dir in sorted(p for p in witness_root.iterdir() if p.is_dir()):
        failing_sb = target_dir / "minimal_failing.sb"
        neighbor_sb = target_dir / "passing_neighbor.sb"
        if not failing_sb.exists() or not neighbor_sb.exists():
            continue

        target_out = target_dir / "compile_vs_apply"
        _ensure_dir(target_out)

        failing_blob = target_out / "minimal_failing.sb.bin"
        neighbor_blob = target_out / "passing_neighbor.sb.bin"

        failing_compile = _run([str(wrapper), "--compile", str(failing_sb), "--out", str(failing_blob)])
        neighbor_compile = _run([str(wrapper), "--compile", str(neighbor_sb), "--out", str(neighbor_blob)])

        failing_apply_blob = _run([str(wrapper), "--preflight", "force", "--blob", str(failing_blob), "--", "/usr/bin/true"])
        neighbor_apply_blob = _run([str(wrapper), "--preflight", "force", "--blob", str(neighbor_blob), "--", "/usr/bin/true"])

        failing_apply_sbpl = _run([str(wrapper), "--preflight", "force", "--sbpl", str(failing_sb), "--", "/usr/bin/true"])
        neighbor_apply_sbpl = _run([str(wrapper), "--preflight", "force", "--sbpl", str(neighbor_sb), "--", "/usr/bin/true"])

        failing_compile_report = _compile_report(failing_compile.stderr_raw)
        neighbor_compile_report = _compile_report(neighbor_compile.stderr_raw)
        failing_apply_blob_report = _apply_report(failing_apply_blob.stderr_raw)
        neighbor_apply_blob_report = _apply_report(neighbor_apply_blob.stderr_raw)

        fork = {
            "compile_gate_eperm": _is_compile_gate_eperm(failing_compile_report),
            "apply_gate_eperm": _is_apply_gate_eperm(failing_apply_blob_report),
        }

        results["witnesses"].append(
            {
                "target": target_dir.name,
                "minimal_failing": {
                    "sbpl": _rel(failing_sb, root),
                    "compile": {
                        "wrapper_rc": failing_compile.rc,
                        "stderr": failing_compile.stderr_canonical,
                        "report": failing_compile_report,
                        "blob": _rel(failing_blob, root) if failing_blob.exists() else None,
                    },
                    "apply_blob": {
                        "wrapper_rc": failing_apply_blob.rc,
                        "stderr": failing_apply_blob.stderr_canonical,
                        "report": failing_apply_blob_report,
                    },
                    "apply_sbpl": {
                        "wrapper_rc": failing_apply_sbpl.rc,
                        "stderr": failing_apply_sbpl.stderr_canonical,
                        "report": _apply_report(failing_apply_sbpl.stderr_raw),
                    },
                },
                "passing_neighbor": {
                    "sbpl": _rel(neighbor_sb, root),
                    "compile": {
                        "wrapper_rc": neighbor_compile.rc,
                        "stderr": neighbor_compile.stderr_canonical,
                        "report": neighbor_compile_report,
                        "blob": _rel(neighbor_blob, root) if neighbor_blob.exists() else None,
                    },
                    "apply_blob": {
                        "wrapper_rc": neighbor_apply_blob.rc,
                        "stderr": neighbor_apply_blob.stderr_canonical,
                        "report": neighbor_apply_blob_report,
                    },
                    "apply_sbpl": {
                        "wrapper_rc": neighbor_apply_sbpl.rc,
                        "stderr": neighbor_apply_sbpl.stderr_canonical,
                        "report": _apply_report(neighbor_apply_sbpl.stderr_raw),
                    },
                },
                "fork": fork,
            }
        )

    # 2) Micro-variant matrix: compile + apply. These are stable SBPL files written into out/.
    variants = _write_variant_files(variants_dir)
    for v in variants:
        sb_path = v["path"]
        blob_path = sb_path.with_suffix(".sb.bin")
        compile_run = _run([str(wrapper), "--compile", str(sb_path), "--out", str(blob_path)])
        apply_run = _run([str(wrapper), "--preflight", "force", "--blob", str(blob_path), "--", "/usr/bin/true"]) if blob_path.exists() else None
        compile_report = _compile_report(compile_run.stderr_raw)
        apply_report = None if apply_run is None else _apply_report(apply_run.stderr_raw)

        results["micro_variants"].append(
            {
                "id": v["id"],
                "note": v["note"],
                "sbpl": _rel(sb_path, root),
                "compile": {
                    "wrapper_rc": compile_run.rc,
                    "stderr": compile_run.stderr_canonical,
                    "report": compile_report,
                    "blob": _rel(blob_path, root) if blob_path.exists() else None,
                },
                "apply_blob": None
                if apply_run is None
                else {
                    "wrapper_rc": apply_run.rc,
                    "stderr": apply_run.stderr_canonical,
                    "report": apply_report,
                },
            }
        )

    out_path = out_dir / "compile_vs_apply.json"
    out_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"[+] wrote {_rel(out_path, root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
