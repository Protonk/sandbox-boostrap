#!/usr/bin/env python3
"""
Run inside + runtime plan + promotion packet + field2 refresh + decision witnesses.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve()
for parent in REPO_ROOT.parents:
    if (parent / "book").is_dir():
        REPO_ROOT = parent
        break
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils
from book.api.runtime.execution import service as runtime_api
from book.api.runtime.execution.channels import ChannelSpec

RATCHET_ROOT = Path(__file__).resolve().parent
FIELD2_ROOT = REPO_ROOT / "book" / "evidence" / "experiments" / "field2-final-final"
RUNTIME_ADVERSARIAL_PLAN = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "runtime-adversarial"
    / "plan.json"
)
DEFAULT_PACKET_OUT = (
    REPO_ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "runtime-final-final"
    / "evidence"
    / "packets"
    / "runtime-adversarial.promotion_packet.json"
)
INSIDE_TOOL = REPO_ROOT / "book" / "tools" / "inside" / "inside.py"
FIELD2_REFRESH = FIELD2_ROOT / "field2-atlas" / "field2_refresh.py"
DECISION_WITNESSES = RATCHET_ROOT / "decision_witnesses.py"


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")


def _run_inside(*, repo_root: Path, include_apply: bool, with_logs: bool) -> dict[str, Any]:
    cmd = [sys.executable, str(INSIDE_TOOL), "--json"]
    if include_apply:
        cmd.append("--include-apply")
    if with_logs:
        cmd.append("--with-logs")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    proc = subprocess.run(
        cmd,
        cwd=repo_root,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    stdout = proc.stdout.strip()
    if not stdout:
        raise RuntimeError("inside tool returned empty output")
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("inside tool returned non-JSON output") from exc


def _run_script(script_path: Path, args: list[str], *, repo_root: Path) -> None:
    cmd = [sys.executable, str(script_path), *args]
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)
    subprocess.check_call(cmd, cwd=repo_root, env=env)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", type=Path, default=RUNTIME_ADVERSARIAL_PLAN)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--channel", default="launchd_clean")
    parser.add_argument("--packet-out", type=Path, default=DEFAULT_PACKET_OUT)
    parser.add_argument("--allow-non-promotable", action="store_true")
    parser.add_argument("--allow-constrained", action="store_true")
    parser.add_argument("--inside-out", type=Path)
    parser.add_argument("--inside-include-apply", action="store_true")
    parser.add_argument("--inside-with-logs", action="store_true")
    parser.add_argument("--only-profile", action="append")
    parser.add_argument("--only-scenario", action="append")
    parser.add_argument("--skip-refresh", action="store_true")
    parser.add_argument("--skip-witnesses", action="store_true")
    parser.add_argument("--decisions", type=Path, default=FIELD2_ROOT / "decisions.jsonl")
    parser.add_argument("--milestone", type=Path, default=FIELD2_ROOT / "active_milestone.json")
    parser.add_argument("--witnesses-out", type=Path, default=FIELD2_ROOT / "decision_witnesses.jsonl")
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(Path(__file__).resolve())
    plan_path = path_utils.ensure_absolute(args.plan, repo_root=repo_root)
    out_dir = path_utils.ensure_absolute(args.out or (plan_path.parent / "out"), repo_root=repo_root)

    inside_doc = _run_inside(
        repo_root=repo_root,
        include_apply=args.inside_include_apply,
        with_logs=args.inside_with_logs,
    )
    inside_summary = inside_doc.get("summary") if isinstance(inside_doc, dict) else {}
    harness_constrained = inside_summary.get("harness_constrained")
    if harness_constrained is True and not args.allow_constrained:
        print("[!] inside reports harness_constrained=true; aborting runtime run")
        raise SystemExit(2)

    channel = ChannelSpec(
        channel=args.channel,
        require_clean=(args.channel == "launchd_clean"),
    )
    bundle = runtime_api.run_plan(
        plan_path,
        out_dir,
        channel=channel,
        only_profiles=args.only_profile,
        only_scenarios=args.only_scenario,
        dry_run=False,
    )

    run_dir = bundle.out_dir
    inside_out = args.inside_out or (run_dir / "inside.json")
    inside_out = path_utils.ensure_absolute(inside_out, repo_root=repo_root)
    _write_json(inside_out, inside_doc)

    packet_out = path_utils.ensure_absolute(args.packet_out, repo_root=repo_root)
    packet = runtime_api.emit_promotion_packet(
        run_dir,
        packet_out,
        require_promotable=not args.allow_non_promotable,
    )
    packet_relpath = path_utils.to_repo_relative(packet_out, repo_root=repo_root)
    print(f"[+] wrote {packet_relpath}")

    if not args.skip_refresh:
        _run_script(
            FIELD2_REFRESH,
            ["--packet", str(packet_out), "--decisions", str(args.decisions), "--milestone", str(args.milestone)],
            repo_root=repo_root,
        )

    if not args.skip_witnesses:
        _run_script(
            DECISION_WITNESSES,
            [
                "--packet",
                str(packet_out),
                "--decisions",
                str(args.decisions),
                "--milestone",
                str(args.milestone),
                "--out",
                str(args.witnesses_out),
                "--inside",
                str(inside_out),
            ],
            repo_root=repo_root,
        )


if __name__ == "__main__":
    main()
