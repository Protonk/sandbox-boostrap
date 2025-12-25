"""EntitlementJail 1.x witness runner for entitlement-diff."""

from __future__ import annotations

import argparse
from typing import Dict

from ej_cli import REPO_ROOT, write_json
from ej_scenarios import (
    scenario_attach_holdopen_default,
    scenario_bookmark_roundtrip,
    scenario_bookmarks,
    scenario_bundle_evidence_out,
    scenario_downloads_rw,
    scenario_evidence,
    scenario_health_check_profile,
    scenario_inventory,
    scenario_matrix_groups,
    scenario_net_op_groups,
    scenario_net_client,
    scenario_probe_families,
    scenario_quarantine_lab,
    scenario_run_matrix_out,
    scenario_wait_attach,
    scenario_wait_create,
    scenario_wait_hold_open,
    scenario_wait_multi_trigger,
    scenario_wait_path_class,
    scenario_wait_probe_wait,
    scenario_wait_timeout_matrix,
    scenario_wait_interval,
)

OUT_ROOT = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "ej"


def _write_outputs(outputs: Dict[str, Dict[str, object]]) -> None:
    for name, payload in outputs.items():
        write_json(OUT_ROOT / f"{name}.json", payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run EntitlementJail 1.x probes for entitlement-diff.")
    parser.add_argument(
        "--scenario",
        default="all",
        choices=[
            "inventory",
            "evidence",
            "matrix_groups",
            "bookmarks",
            "downloads_rw",
            "net_client",
            "net_op_groups",
            "probe_families",
            "bookmark_roundtrip",
            "wait_attach",
            "wait_timeout_matrix",
            "wait_path_class",
            "wait_multi_trigger",
            "wait_probe_wait",
            "wait_hold_open",
            "wait_create",
            "wait_interval",
            "attach_holdopen_default",
            "health_check_profile",
            "run_matrix_out",
            "bundle_evidence_out",
            "quarantine_lab",
            "all",
        ],
        help="Scenario to run (default: all).",
    )
    parser.add_argument(
        "--matrix-groups",
        default="",
        help="Comma-separated matrix groups (default: baseline,debug,inject,jit).",
    )
    parser.add_argument("--ack-risk", default=None, help="ack-risk value for tier-2 profiles (optional).")
    args = parser.parse_args()

    outputs: Dict[str, Dict[str, object]] = {}

    if args.scenario in {"inventory", "all"}:
        outputs.update(scenario_inventory())

    if args.scenario in {"evidence", "all"}:
        outputs.update(scenario_evidence(ack_risk=args.ack_risk))

    if args.scenario in {"matrix_groups", "all"}:
        groups = [g.strip() for g in args.matrix_groups.split(",") if g.strip()]
        outputs.update(scenario_matrix_groups(groups=groups or None, ack_risk=args.ack_risk))

    if args.scenario in {"bookmarks", "all"}:
        outputs.update(scenario_bookmarks(ack_risk=args.ack_risk))

    if args.scenario in {"downloads_rw", "all"}:
        outputs.update(scenario_downloads_rw(ack_risk=args.ack_risk))

    if args.scenario in {"net_client", "all"}:
        outputs.update(scenario_net_client(ack_risk=args.ack_risk))

    if args.scenario in {"net_op_groups", "all"}:
        outputs.update(scenario_net_op_groups(ack_risk=args.ack_risk))

    if args.scenario in {"probe_families", "all"}:
        outputs.update(scenario_probe_families(ack_risk=args.ack_risk))

    if args.scenario in {"bookmark_roundtrip", "all"}:
        outputs.update(scenario_bookmark_roundtrip(ack_risk=args.ack_risk))

    if args.scenario in {"wait_attach", "all"}:
        outputs.update(scenario_wait_attach(ack_risk=args.ack_risk))

    if args.scenario in {"wait_timeout_matrix", "all"}:
        outputs.update(scenario_wait_timeout_matrix(ack_risk=args.ack_risk))

    if args.scenario in {"wait_path_class", "all"}:
        outputs.update(scenario_wait_path_class(ack_risk=args.ack_risk))

    if args.scenario in {"wait_multi_trigger", "all"}:
        outputs.update(scenario_wait_multi_trigger(ack_risk=args.ack_risk))

    if args.scenario in {"wait_probe_wait", "all"}:
        outputs.update(scenario_wait_probe_wait(ack_risk=args.ack_risk))

    if args.scenario in {"wait_hold_open", "all"}:
        outputs.update(scenario_wait_hold_open(ack_risk=args.ack_risk))

    if args.scenario in {"wait_create", "all"}:
        outputs.update(scenario_wait_create(ack_risk=args.ack_risk))

    if args.scenario in {"wait_interval", "all"}:
        outputs.update(scenario_wait_interval(ack_risk=args.ack_risk))

    if args.scenario in {"attach_holdopen_default", "all"}:
        outputs.update(scenario_attach_holdopen_default(ack_risk=args.ack_risk))

    if args.scenario in {"health_check_profile", "all"}:
        outputs.update(scenario_health_check_profile(ack_risk=args.ack_risk))

    if args.scenario in {"run_matrix_out", "all"}:
        outputs.update(scenario_run_matrix_out(ack_risk=args.ack_risk))

    if args.scenario in {"bundle_evidence_out", "all"}:
        outputs.update(scenario_bundle_evidence_out(ack_risk=args.ack_risk))

    if args.scenario in {"quarantine_lab", "all"}:
        outputs.update(scenario_quarantine_lab(ack_risk=args.ack_risk))

    _write_outputs(outputs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
