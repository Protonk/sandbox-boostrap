#!/usr/bin/env python3
"""
Lifecycle-lockdown: multi-source evidence checks for `book.api.lifecycle`.

This runner is intentionally small and host-bound. It captures both:
- raw tool outputs (stdout/stderr + argv)
- small normalized summaries for easier comparison
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.lifecycle import runner as lifecycle
from book.api.runtime.contracts import schema as rt_contract


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_OUT = BASE_DIR / "out"

GATE_SBPL_DEFAULT = Path("book/experiments/gate-witnesses/out/witnesses/airlock/minimal_failing.sb")
ADHOC_ENTITLEMENTS = Path("book/experiments/entitlement-diff/entitlements/none.plist")


@dataclass(frozen=True)
class CmdResult:
    argv: List[str]
    cwd: str
    returncode: int
    stdout: str
    stderr: str


def _run_cmd(argv: List[str], *, cwd: Path = REPO_ROOT, timeout_s: int = 60) -> CmdResult:
    res = subprocess.run(argv, capture_output=True, text=True, cwd=str(cwd), timeout=timeout_s)
    return CmdResult(argv=list(argv), cwd=str(cwd), returncode=res.returncode, stdout=res.stdout or "", stderr=res.stderr or "")


def _redact_repo_paths(text: str) -> str:
    if not text:
        return text
    repo = str(REPO_ROOT.resolve())
    return text.replace(repo + "/", "").replace(repo, ".")


def _write_cmd_bundle(out_dir: Path, name: str, result: CmdResult) -> Dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{name}.stdout.txt").write_text(_redact_repo_paths(result.stdout))
    (out_dir / f"{name}.stderr.txt").write_text(_redact_repo_paths(result.stderr))
    record = {
        "argv": path_utils.relativize_command(result.argv, repo_root=REPO_ROOT),
        "cwd": path_utils.to_repo_relative(result.cwd, repo_root=REPO_ROOT),
        "returncode": result.returncode,
        "stdout": f"{name}.stdout.txt",
        "stderr": f"{name}.stderr.txt",
    }
    (out_dir / f"{name}.command.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    return record


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def run_entitlements(out_dir: Path) -> Dict[str, Any]:
    out_dir = path_utils.ensure_absolute(out_dir, repo_root=REPO_ROOT) / "entitlements"
    out_dir.mkdir(parents=True, exist_ok=True)

    unsigned_path = out_dir / "entitlements_unsigned.json"
    signed_path = out_dir / "entitlements_signed.json"

    unsigned = lifecycle.capture_entitlements_evolution(unsigned_path, repo_root=REPO_ROOT, build=True)
    exe_rel = unsigned.get("executable")
    exe_abs = path_utils.ensure_absolute(Path(exe_rel), repo_root=REPO_ROOT) if isinstance(exe_rel, str) else None

    cmd_records: Dict[str, Any] = {}
    if exe_abs:
        cmd_records["codesign_dv_unsigned"] = _write_cmd_bundle(
            out_dir,
            "codesign_dv_unsigned",
            _run_cmd(["codesign", "-dv", "--verbose=4", str(exe_abs)], timeout_s=30),
        )
        cmd_records["codesign_entitlements_unsigned"] = _write_cmd_bundle(
            out_dir,
            "codesign_entitlements_unsigned",
            _run_cmd(["codesign", "-d", "--entitlements", ":-", str(exe_abs)], timeout_s=30),
        )

        ent_plist = path_utils.ensure_absolute(ADHOC_ENTITLEMENTS, repo_root=REPO_ROOT)
        cmd_records["codesign_adhoc_sign"] = _write_cmd_bundle(
            out_dir,
            "codesign_adhoc_sign",
            _run_cmd(
                ["codesign", "--force", "--sign", "-", "--entitlements", str(ent_plist), str(exe_abs)],
                timeout_s=30,
            ),
        )

        signed = lifecycle.capture_entitlements_evolution(signed_path, repo_root=REPO_ROOT, build=False)
        cmd_records["codesign_dv_signed"] = _write_cmd_bundle(
            out_dir,
            "codesign_dv_signed",
            _run_cmd(["codesign", "-dv", "--verbose=4", str(exe_abs)], timeout_s=30),
        )
        cmd_records["codesign_entitlements_signed"] = _write_cmd_bundle(
            out_dir,
            "codesign_entitlements_signed",
            _run_cmd(["codesign", "-d", "--entitlements", ":-", str(exe_abs)], timeout_s=30),
        )
    else:
        signed = {}

    summary = {
        "world_id": unsigned.get("world_id"),
        "executable": exe_rel,
        "unsigned": {
            "entitlements_present": unsigned.get("entitlements_present"),
            "signing_identifier": unsigned.get("signing_identifier"),
        },
        "signed": {
            "entitlements_present": signed.get("entitlements_present") if signed else None,
            "signing_identifier": signed.get("signing_identifier") if signed else None,
        },
        "commands": cmd_records,
        "limits": [
            "This compares two independent metadata views (Security.framework vs codesign) and does not claim entitlement effectiveness.",
            "Ad-hoc signing may constrain which entitlements can be embedded; treat failures as bounded outcomes.",
        ],
    }
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def _derive_wrapper_apply_report(stderr: str) -> Dict[str, Any] | None:
    markers = rt_contract.extract_sbpl_apply_markers(stderr)
    if not markers:
        return None
    return rt_contract.derive_apply_report_from_markers(markers) or None


def run_apply(out_dir: Path, *, gate_sbpl: Path, force_gates: bool = False) -> Dict[str, Any]:
    out_dir = path_utils.ensure_absolute(out_dir, repo_root=REPO_ROOT) / "apply"
    out_dir.mkdir(parents=True, exist_ok=True)

    wrapper = path_utils.ensure_absolute(Path("book/tools/sbpl/wrapper/wrapper"), repo_root=REPO_ROOT)
    true_bin = Path("/usr/bin/true")

    results: Dict[str, Any] = {"world_id": _load_json(REPO_ROOT / "book/world/sonoma-14.4.1-23E224-arm64/world.json").get("world_id")}

    def _derive_blob_for_sbpl(sbpl_abs: Path) -> Path | None:
        candidate = sbpl_abs.parent / "compile_vs_apply" / f"{sbpl_abs.name}.bin"
        return candidate if candidate.exists() else None

    wrapper_rel = path_utils.to_repo_relative(wrapper, repo_root=REPO_ROOT)

    # Scenario 1: a known "passing neighbor" profile from the gate-witness corpus.
    passing_sbpl_abs = gate_sbpl_abs = path_utils.ensure_absolute(gate_sbpl, repo_root=REPO_ROOT)
    passing_neighbor = gate_sbpl_abs.parent / "passing_neighbor.sb"
    if passing_neighbor.exists():
        passing_sbpl_abs = passing_neighbor
    results["passing_sbpl"] = path_utils.to_repo_relative(passing_sbpl_abs, repo_root=REPO_ROOT)
    passing_blob_abs = _derive_blob_for_sbpl(passing_sbpl_abs)
    results["passing_blob"] = path_utils.to_repo_relative(passing_blob_abs, repo_root=REPO_ROOT) if passing_blob_abs else None

    api_passing_out = out_dir / "api_apply_attempt_passing.json"
    lifecycle.capture_apply_attempt(api_passing_out, repo_root=REPO_ROOT, sbpl_file=passing_sbpl_abs)

    cmd_sbpl_passing = _run_cmd([wrapper_rel, "--sbpl", results["passing_sbpl"], "--", str(true_bin)], timeout_s=30)
    results["wrapper_sbpl_passing"] = _write_cmd_bundle(out_dir, "wrapper_sbpl_passing", cmd_sbpl_passing)
    results["wrapper_sbpl_passing"]["apply_report"] = _derive_wrapper_apply_report(cmd_sbpl_passing.stderr)

    if passing_blob_abs:
        cmd_blob_passing = _run_cmd([wrapper_rel, "--blob", results["passing_blob"], "--", str(true_bin)], timeout_s=30)
        results["wrapper_blob_passing"] = _write_cmd_bundle(out_dir, "wrapper_blob_passing", cmd_blob_passing)
        results["wrapper_blob_passing"]["apply_report"] = _derive_wrapper_apply_report(cmd_blob_passing.stderr)
    else:
        results["wrapper_blob_passing"] = {"status": "blocked", "reason": "missing_compiled_blob"}

    # Scenario 2: a known apply-gated profile from the gate-witness corpus (wrapper identity).
    results["gate_sbpl"] = path_utils.to_repo_relative(gate_sbpl_abs, repo_root=REPO_ROOT)
    gate_blob_abs = _derive_blob_for_sbpl(gate_sbpl_abs)
    results["gate_blob"] = path_utils.to_repo_relative(gate_blob_abs, repo_root=REPO_ROOT) if gate_blob_abs else None

    api_gate_out = out_dir / "api_apply_attempt_gate.json"
    api_preflight_mode = "force" if force_gates else "enforce"
    try:
        lifecycle.capture_apply_attempt(
            api_gate_out,
            repo_root=REPO_ROOT,
            sbpl_file=gate_sbpl_abs,
            preflight_mode=api_preflight_mode,
        )
        results["api_gate_status"] = "ok"
        results["api_gate_preflight_mode"] = api_preflight_mode
    except Exception as exc:
        results["api_gate_status"] = "error"
        results["api_gate_error"] = str(exc)

    cmd_sbpl_gate = _run_cmd([wrapper_rel, "--sbpl", results["gate_sbpl"], "--", str(true_bin)], timeout_s=30)
    results["wrapper_sbpl_gate"] = _write_cmd_bundle(out_dir, "wrapper_sbpl_gate", cmd_sbpl_gate)
    results["wrapper_sbpl_gate"]["apply_report"] = _derive_wrapper_apply_report(cmd_sbpl_gate.stderr)

    if gate_blob_abs:
        cmd_blob_gate = _run_cmd([wrapper_rel, "--blob", results["gate_blob"], "--", str(true_bin)], timeout_s=30)
        results["wrapper_blob_gate"] = _write_cmd_bundle(out_dir, "wrapper_blob_gate", cmd_blob_gate)
        results["wrapper_blob_gate"]["apply_report"] = _derive_wrapper_apply_report(cmd_blob_gate.stderr)
    else:
        results["wrapper_blob_gate"] = {"status": "blocked", "reason": "missing_compiled_blob"}

    if force_gates:
        cmd_sbpl_gate_force = _run_cmd(
            [wrapper_rel, "--preflight", "force", "--sbpl", results["gate_sbpl"], "--", str(true_bin)],
            timeout_s=30,
        )
        results["wrapper_sbpl_gate_force"] = _write_cmd_bundle(out_dir, "wrapper_sbpl_gate_force", cmd_sbpl_gate_force)
        results["wrapper_sbpl_gate_force"]["apply_report"] = _derive_wrapper_apply_report(cmd_sbpl_gate_force.stderr)

        if gate_blob_abs:
            cmd_blob_gate_force = _run_cmd(
                [wrapper_rel, "--preflight", "force", "--blob", results["gate_blob"], "--", str(true_bin)],
                timeout_s=30,
            )
            results["wrapper_blob_gate_force"] = _write_cmd_bundle(out_dir, "wrapper_blob_gate_force", cmd_blob_gate_force)
            results["wrapper_blob_gate_force"]["apply_report"] = _derive_wrapper_apply_report(cmd_blob_gate_force.stderr)
        else:
            results["wrapper_blob_gate_force"] = {"status": "blocked", "reason": "missing_compiled_blob"}

    # Preflight scan witness for the gate SBPL (static signature classification).
    scan = _run_cmd(["python3", "book/tools/preflight/preflight.py", "scan", str(gate_sbpl_abs)], timeout_s=30)
    results["preflight_scan_gate"] = _write_cmd_bundle(out_dir, "preflight_scan_gate", scan)
    try:
        results["preflight_scan_gate"]["parsed"] = json.loads(scan.stdout)
    except Exception:
        results["preflight_scan_gate"]["parsed"] = None

    (out_dir / "summary.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    return results


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Lifecycle-lockdown evidence runner (Sonoma baseline).")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Output directory (default: book/experiments/lifecycle-lockdown/out)")
    ap.add_argument(
        "--gate-sbpl",
        type=Path,
        default=GATE_SBPL_DEFAULT,
        help="Repo-relative SBPL path expected to be apply-gated for wrapper identity (default: airlock minimal_failing.sb)",
    )
    ap.add_argument("--only", choices=["entitlements", "apply", "all"], default="all", help="Run a subset (default: all)")
    ap.add_argument(
        "--force-gates",
        action="store_true",
        help="Attempt apply even when wrapper preflight flags a known gate signature (records apply-stage outcomes; treat as non-semantic).",
    )
    args = ap.parse_args(argv)

    out_dir = path_utils.ensure_absolute(args.out, repo_root=REPO_ROOT)
    out_dir.mkdir(parents=True, exist_ok=True)
    if args.only in {"entitlements", "all"}:
        run_entitlements(out_dir)
    if args.only in {"apply", "all"}:
        run_apply(out_dir, gate_sbpl=args.gate_sbpl, force_gates=args.force_gates)

    print(f"[+] wrote {path_utils.to_repo_relative(out_dir, repo_root=REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
