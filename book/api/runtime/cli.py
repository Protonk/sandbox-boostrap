#!/usr/bin/env python3
"""
Runtime CLI entrypoint (service contract).

This CLI is the stable "human and agent" interface to runtime. It exposes:
- Plan-based runs via `run --plan ...` (recommended for experiments).
- Bundle lifecycle helpers (`validate-bundle`, `reindex-bundle`, `emit-promotion`).
- Registry and plan introspection (`list-*`, `describe-*`, `*-lint`).
- Legacy matrix-based helpers (normalize/cut/story/golden) for existing runtime
  mapping workflows.

The CLI delegates all plan execution and artifact IO to `book.api.runtime.execution.service`.
It does not implement channel logic, locking, or bundle writing itself; those
contracts are enforced by the library layer so non-CLI callers get identical
behavior.

Assumptions:
- Commands are run from within the repo (or with paths resolvable against it).
- Plan runs write into a bundle root that contains run-scoped directories
  (`out/<run_id>/...`) and a `LATEST` pointer updated only after commit.

Refusals:
- The CLI does not guess promotability; strict promotion packet emission is an
  explicit opt-in (`emit-promotion --require-promotable`).

The CLI is a thin wrapper over library functions. That means the
behavior is the same whether you run a command or import the API in code.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from book.api import path_utils
from book.api.runtime.contracts import normalize
from book.api.runtime.execution.harness import runner as harness_runner
from book.api.runtime.analysis.mapping import story as runtime_story
from book.api.runtime.execution import workflow
from book.api.runtime.execution import service as runtime_api
from book.api.runtime.execution.channels import ChannelSpec
from book.api.runtime.bundles import reader as bundle_reader
from book.api.runtime.plans import registry as runtime_registry
from book.api.runtime.plans import loader as runtime_plan
from book.api.runtime.plans import builder as runtime_plan_builder
from book.api.runtime.analysis import op_summary as runtime_op_summary


# Resolve repo roots once so defaults remain stable across subcommands.
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BOOK_ROOT = REPO_ROOT / "book"


def _default_matrix() -> Path:
    bundle_root = BOOK_ROOT / "experiments" / "runtime-checks" / "out"
    try:
        bundle_dir, _ = bundle_reader.resolve_bundle_dir(bundle_root, repo_root=REPO_ROOT)
    except FileNotFoundError:
        bundle_dir = bundle_root
    return bundle_dir / "expected_matrix.json"


def _default_runtime_results() -> Path:
    bundle_root = BOOK_ROOT / "experiments" / "runtime-checks" / "out"
    try:
        bundle_dir, _ = bundle_reader.resolve_bundle_dir(bundle_root, repo_root=REPO_ROOT)
    except FileNotFoundError:
        bundle_dir = bundle_root
    return bundle_dir / "runtime_results.json"


def run_command(args: argparse.Namespace) -> int:
    """Handle the `run` CLI subcommand."""
    if args.plan:
        out_dir = args.out or args.plan.parent / "out"
        channel = ChannelSpec(
            channel=args.channel,
            require_clean=(args.channel == "launchd_clean"),
            lock_mode=args.lock_mode,
            lock_timeout_seconds=args.lock_timeout_seconds,
        )
        bundle = runtime_api.run_plan(
            args.plan,
            out_dir,
            channel=channel,
            only_profiles=args.only_profile,
            only_scenarios=args.only_scenario,
            dry_run=args.dry,
        )
        print(f"[+] wrote {bundle.out_dir}")
        print(f"[+] updated {out_dir / 'LATEST'}")
        return 0 if bundle.status not in {"failed"} else 1
    if args.dry:
        raise SystemExit("--dry requires --plan")
    out_dir = args.out or (BOOK_ROOT / "profiles" / "golden-triple")
    out_path = harness_runner.run_matrix(args.matrix, out_dir=out_dir)
    print(f"[+] wrote {out_path}")
    return 0


def normalize_command(args: argparse.Namespace) -> int:
    """Handle the `normalize` CLI subcommand."""
    out_path = normalize.write_matrix_observations(
        args.matrix,
        args.runtime_results,
        args.out,
        world_id=args.world_id,
    )
    print(f"[+] wrote {out_path}")
    return 0


def cut_command(args: argparse.Namespace) -> int:
    """Handle the `cut` CLI subcommand."""
    cut = workflow.build_cut(
        args.matrix,
        args.runtime_results,
        args.out,
        world_id=args.world_id,
    )
    print(f"[+] wrote {cut.manifest}")
    return 0


def story_command(args: argparse.Namespace) -> int:
    """Handle the `story` CLI subcommand."""
    story_doc = runtime_story.build_story(args.ops, args.scenarios, vocab_path=args.vocab, world_id=args.world_id)
    out_path = runtime_story.write_story(story_doc, args.out)
    print(f"[+] wrote {out_path}")
    return 0


def golden_command(args: argparse.Namespace) -> int:
    """Handle the `golden` CLI subcommand."""
    artifacts = workflow.generate_golden_artifacts(
        matrix_path=args.matrix,
        runtime_results_path=args.runtime_results,
        baseline_ref=args.baseline,
        out_root=args.out,
    )
    print(f"[+] wrote {artifacts.decode_summary}")
    print(f"[+] wrote {artifacts.expectations}")
    print(f"[+] wrote {artifacts.traces}")
    return 0


def promote_command(args: argparse.Namespace) -> int:
    """Handle the `promote` CLI subcommand."""
    cut = workflow.promote_cut(args.staging, args.out)
    print(f"[+] wrote {cut.manifest}")
    return 0


def mismatch_command(args: argparse.Namespace) -> int:
    """Handle the `mismatch` CLI subcommand."""
    matrix_doc = json.loads(Path(args.matrix).read_text())
    runtime_doc = json.loads(Path(args.runtime_results).read_text())
    world_id = args.world_id or matrix_doc.get("world_id") or runtime_doc.get("world_id")
    if not world_id:
        raise SystemExit("world_id missing; pass --world-id")
    summary = workflow.classify_mismatches(matrix_doc, runtime_doc, world_id)
    out_path = Path(args.out)
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"[+] wrote {out_path}")
    return 0


def list_registries_command(args: argparse.Namespace) -> int:
    """Handle the `list-registries` CLI subcommand."""
    registries = runtime_registry.list_registries()
    payload = [
        {
            "id": reg.registry_id,
            "probes": str(path_utils.to_repo_relative(reg.probes, repo_root=REPO_ROOT)),
            "profiles": str(path_utils.to_repo_relative(reg.profiles, repo_root=REPO_ROOT)),
            "description": reg.description,
        }
        for reg in registries
    ]
    print(json.dumps(payload, indent=2))
    return 0


def list_probes_command(args: argparse.Namespace) -> int:
    """Handle the `list-probes` CLI subcommand."""
    probes = runtime_registry.list_probes(args.registry)
    print(json.dumps(probes, indent=2))
    return 0


def list_profiles_command(args: argparse.Namespace) -> int:
    """Handle the `list-profiles` CLI subcommand."""
    profiles = runtime_registry.list_profiles(args.registry)
    print(json.dumps(profiles, indent=2))
    return 0


def describe_probe_command(args: argparse.Namespace) -> int:
    """Handle the `describe-probe` CLI subcommand."""
    probe = runtime_registry.resolve_probe(args.registry, args.probe)
    print(json.dumps(probe, indent=2))
    return 0


def describe_profile_command(args: argparse.Namespace) -> int:
    """Handle the `describe-profile` CLI subcommand."""
    profile = runtime_registry.resolve_profile(args.registry, args.profile)
    print(json.dumps(profile, indent=2))
    return 0


def emit_promotion_command(args: argparse.Namespace) -> int:
    """Handle the `emit-promotion` CLI subcommand."""
    packet = runtime_api.emit_promotion_packet(args.bundle, args.out, require_promotable=args.require_promotable)
    promotability = packet.get("promotability") or {}
    if not promotability.get("promotable_decision_stage"):
        reasons = promotability.get("reasons") or []
        print(f"[!] not promotable: {reasons}")
    print(f"[+] wrote {args.out}")
    return 0


def validate_bundle_command(args: argparse.Namespace) -> int:
    """Handle the `validate-bundle` CLI subcommand."""
    result = runtime_api.validate_bundle(args.bundle)
    if not result.ok:
        for err in result.errors:
            print(f"[!] {err}")
        return 1
    print("[+] bundle ok")
    return 0


def status_command(args: argparse.Namespace) -> int:
    """Handle the `status` CLI subcommand."""
    status = runtime_api.runtime_status()
    print(json.dumps(status, indent=2))
    return 0


def list_plans_command(args: argparse.Namespace) -> int:
    """Handle the `list-plans` CLI subcommand."""
    plans = runtime_plan.list_plans()
    print(json.dumps(plans, indent=2))
    return 0


def describe_plan_command(args: argparse.Namespace) -> int:
    """Handle the `describe-plan` CLI subcommand."""
    doc = runtime_plan.load_plan(args.plan)
    payload = {
        "plan": doc,
        "path": str(path_utils.to_repo_relative(args.plan, repo_root=REPO_ROOT)),
        "plan_digest": runtime_plan.plan_digest(doc),
    }
    print(json.dumps(payload, indent=2))
    return 0


def plan_lint_command(args: argparse.Namespace) -> int:
    """Handle the `plan-lint` CLI subcommand."""
    _doc, errors = runtime_plan.lint_plan(args.plan)
    if errors:
        for err in errors:
            print(f"[!] {err}")
        return 1
    print("[+] plan ok")
    return 0


def list_templates_command(args: argparse.Namespace) -> int:
    """Handle the `list-templates` CLI subcommand."""
    templates = runtime_plan_builder.list_plan_templates()
    print(json.dumps(templates, indent=2))
    return 0


def plan_build_command(args: argparse.Namespace) -> int:
    """Handle the `plan-build` CLI subcommand."""
    result = runtime_plan_builder.build_plan_from_template(
        args.template,
        args.out,
        overwrite=args.overwrite,
        write_expected_matrix=not args.skip_expected_matrix,
    )
    print(f"[+] wrote {result.plan_path}")
    print(f"[+] wrote {result.probes_path}")
    print(f"[+] wrote {result.profiles_path}")
    if result.expected_matrix_path:
        print(f"[+] wrote {result.expected_matrix_path}")
    return 0


def summarize_ops_command(args: argparse.Namespace) -> int:
    """Handle the `summarize-ops` CLI subcommand."""
    if bool(args.bundle) == bool(args.packet):
        raise SystemExit("must pass exactly one of --bundle or --packet")
    if args.bundle:
        runtime_op_summary.summarize_ops_from_bundle(
            args.bundle,
            out_path=args.out,
            strict=not args.allow_unverified,
        )
    else:
        runtime_op_summary.summarize_ops_from_packet(
            args.packet,
            out_path=args.out,
            require_promotable=not args.allow_nonpromotable,
        )
    print(f"[+] wrote {args.out}")
    return 0


def registry_lint_command(args: argparse.Namespace) -> int:
    """Handle the `registry-lint` CLI subcommand."""
    _doc, errors = runtime_registry.lint_registry(args.registry)
    if errors:
        for err in errors:
            print(f"[!] {err}")
        return 1
    print("[+] registry ok")
    return 0


def registry_upgrade_command(args: argparse.Namespace) -> int:
    """Handle the `registry-upgrade` CLI subcommand."""
    result = runtime_registry.upgrade_registry(
        args.registry,
        out_dir=args.out_dir,
        overwrite=args.overwrite,
    )
    print(f"[+] wrote {result.probes_path}")
    print(f"[+] wrote {result.profiles_path}")
    return 0


def reindex_bundle_command(args: argparse.Namespace) -> int:
    """Handle the `reindex-bundle` CLI subcommand."""
    if args.repair and args.strict:
        raise SystemExit("--repair and --strict are mutually exclusive")
    if not args.repair and not args.strict:
        raise SystemExit("must pass either --strict or --repair")
    runtime_api.reindex_bundle(args.bundle, repair=args.repair)
    print("[+] bundle ok" if args.strict else "[+] bundle reindexed")
    return 0


def run_all_command(args: argparse.Namespace) -> int:
    """Handle the `run-all` CLI subcommand (legacy matrix runner)."""
    run = workflow.run_from_matrix(
        args.matrix,
        args.out,
        world_id=args.world_id,
    )
    print(f"[+] wrote {run.runtime_results}")
    print(f"[+] wrote {run.cut.manifest}")
    if run.mismatch_summary:
        print(f"[+] wrote {run.mismatch_summary}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for `python -m book.api.runtime`."""
    ap = argparse.ArgumentParser(description="Runtime tools (run, normalize, cut, story, promote).")
    sub = ap.add_subparsers(dest="command", required=True)

    ap_run = sub.add_parser("run", help="Run a plan or expected matrix (writes runtime results).")
    ap_run.add_argument("--plan", type=Path, help="Path to runtime plan JSON")
    ap_run.add_argument("--matrix", type=Path, default=_default_matrix(), help="Path to expected_matrix.json")
    ap_run.add_argument("--out", type=Path, help="Output directory")
    ap_run.add_argument("--channel", type=str, default="direct", help="Channel (launchd_clean|direct)")
    ap_run.add_argument("--lock-mode", type=str, default="fail", choices=["fail", "wait"], help="Bundle lock mode")
    ap_run.add_argument("--lock-timeout-seconds", type=float, default=30.0, help="Bundle lock timeout (wait mode)")
    ap_run.add_argument("--only-profile", action="append", default=[], help="Limit to a profile_id (plan mode)")
    ap_run.add_argument("--only-scenario", action="append", default=[], help="Limit to an expectation_id (plan mode)")
    ap_run.add_argument("--dry", action="store_true", help="Validate/emit plan artifacts without running probes")
    ap_run.set_defaults(func=run_command)

    ap_norm = sub.add_parser("normalize", help="Normalize expected_matrix + runtime_results into observations.")
    ap_norm.add_argument("--matrix", type=Path, default=_default_matrix(), help="Path to expected_matrix.json")
    ap_norm.add_argument("--runtime-results", type=Path, default=_default_runtime_results(), help="Path to runtime_results.json")
    ap_norm.add_argument("--out", type=Path, required=True, help="Output path for observations JSON")
    ap_norm.add_argument("--world-id", type=str, help="Override world_id")
    ap_norm.set_defaults(func=normalize_command)

    ap_cut = sub.add_parser("cut", help="Generate a runtime cut from expected_matrix + runtime_results.")
    ap_cut.add_argument("--matrix", type=Path, default=_default_matrix(), help="Path to expected_matrix.json")
    ap_cut.add_argument("--runtime-results", type=Path, default=_default_runtime_results(), help="Path to runtime_results.json")
    ap_cut.add_argument("--out", type=Path, required=True, help="Output staging directory for runtime cut")
    ap_cut.add_argument("--world-id", type=str, help="Override world_id")
    ap_cut.set_defaults(func=cut_command)

    ap_story = sub.add_parser("story", help="Build a runtime story from ops + scenarios.")
    ap_story.add_argument("--ops", type=Path, required=True, help="Path to ops.json")
    ap_story.add_argument("--scenarios", type=Path, required=True, help="Path to scenarios.json")
    ap_story.add_argument("--vocab", type=Path, default=BOOK_ROOT / "graph" / "mappings" / "vocab" / "ops.json", help="Path to ops vocab")
    ap_story.add_argument("--out", type=Path, required=True, help="Output path for runtime_story.json")
    ap_story.add_argument("--world-id", type=str, help="Override world_id")
    ap_story.set_defaults(func=story_command)

    ap_golden = sub.add_parser("golden", help="Generate golden decodes/expectations/traces from runtime-checks outputs.")
    ap_golden.add_argument("--matrix", type=Path, default=_default_matrix(), help="Path to expected_matrix.json")
    ap_golden.add_argument("--runtime-results", type=Path, default=_default_runtime_results(), help="Path to runtime_results.json")
    ap_golden.add_argument("--baseline", type=Path, default=BOOK_ROOT / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json", help="Path to world baseline JSON")
    ap_golden.add_argument("--out", type=Path, default=BOOK_ROOT / "graph" / "mappings" / "runtime", help="Root output directory")
    ap_golden.set_defaults(func=golden_command)

    ap_promote = sub.add_parser("promote", help="Promote a staged runtime cut into runtime_cuts.")
    ap_promote.add_argument("--staging", type=Path, required=True, help="Staging root for runtime cut")
    ap_promote.add_argument("--out", type=Path, default=BOOK_ROOT / "graph" / "mappings" / "runtime_cuts", help="Target root")
    ap_promote.set_defaults(func=promote_command)

    ap_mismatch = sub.add_parser("mismatch", help="Classify mismatches for expected_matrix + runtime_results.")
    ap_mismatch.add_argument("--matrix", type=Path, default=_default_matrix(), help="Path to expected_matrix.json")
    ap_mismatch.add_argument("--runtime-results", type=Path, default=_default_runtime_results(), help="Path to runtime_results.json")
    ap_mismatch.add_argument("--out", type=Path, required=True, help="Output path for mismatch_summary.json")
    ap_mismatch.add_argument("--world-id", type=str, help="Override world_id")
    ap_mismatch.set_defaults(func=mismatch_command)

    ap_all = sub.add_parser("run-all", help="Run matrix, build cut, and emit mismatch summary.")
    ap_all.add_argument("--matrix", type=Path, default=_default_matrix(), help="Path to expected_matrix.json")
    ap_all.add_argument("--out", type=Path, required=True, help="Output directory")
    ap_all.add_argument("--world-id", type=str, help="Override world_id")
    ap_all.set_defaults(func=run_all_command)

    ap_list_reg = sub.add_parser("list-registries", help="List available runtime registries.")
    ap_list_reg.set_defaults(func=list_registries_command)

    ap_list_probes = sub.add_parser("list-probes", help="List probes in a registry.")
    ap_list_probes.add_argument("--registry", type=str, required=True, help="Registry id")
    ap_list_probes.set_defaults(func=list_probes_command)

    ap_list_profiles = sub.add_parser("list-profiles", help="List profiles in a registry.")
    ap_list_profiles.add_argument("--registry", type=str, required=True, help="Registry id")
    ap_list_profiles.set_defaults(func=list_profiles_command)

    ap_desc_probe = sub.add_parser("describe-probe", help="Describe a probe by id.")
    ap_desc_probe.add_argument("--registry", type=str, required=True, help="Registry id")
    ap_desc_probe.add_argument("--probe", type=str, required=True, help="Probe id")
    ap_desc_probe.set_defaults(func=describe_probe_command)

    ap_desc_profile = sub.add_parser("describe-profile", help="Describe a profile by id.")
    ap_desc_profile.add_argument("--registry", type=str, required=True, help="Registry id")
    ap_desc_profile.add_argument("--profile", type=str, required=True, help="Profile id")
    ap_desc_profile.set_defaults(func=describe_profile_command)

    ap_emit = sub.add_parser("emit-promotion", help="Emit a promotion packet from a run bundle.")
    ap_emit.add_argument("--bundle", type=Path, required=True, help="Run bundle output directory")
    ap_emit.add_argument("--out", type=Path, required=True, help="Output path for promotion packet")
    ap_emit.add_argument("--require-promotable", action="store_true", help="Fail unless decision-stage promotable")
    ap_emit.set_defaults(func=emit_promotion_command)

    ap_validate = sub.add_parser("validate-bundle", help="Validate a run bundle artifact index.")
    ap_validate.add_argument("--bundle", type=Path, required=True, help="Run bundle output directory")
    ap_validate.set_defaults(func=validate_bundle_command)

    ap_reindex = sub.add_parser("reindex-bundle", help="Verify or repair an artifact_index.json.")
    ap_reindex.add_argument("--bundle", type=Path, required=True, help="Run bundle output directory")
    ap_reindex.add_argument("--strict", action="store_true", help="Fail on missing/digest mismatch")
    ap_reindex.add_argument("--repair", action="store_true", help="Recompute artifact_index digests/sizes")
    ap_reindex.set_defaults(func=reindex_bundle_command)

    ap_status = sub.add_parser("status", help="Report runtime environment readiness.")
    ap_status.set_defaults(func=status_command)

    ap_list_plans = sub.add_parser("list-plans", help="List plan.json files under book/experiments.")
    ap_list_plans.set_defaults(func=list_plans_command)

    ap_desc_plan = sub.add_parser("describe-plan", help="Describe a plan.json (includes digest).")
    ap_desc_plan.add_argument("--plan", type=Path, required=True, help="Path to plan.json")
    ap_desc_plan.set_defaults(func=describe_plan_command)

    ap_plan_lint = sub.add_parser("plan-lint", help="Validate a plan.json against its registry.")
    ap_plan_lint.add_argument("--plan", type=Path, required=True, help="Path to plan.json")
    ap_plan_lint.set_defaults(func=plan_lint_command)

    ap_list_templates = sub.add_parser("list-templates", help="List available plan templates.")
    ap_list_templates.set_defaults(func=list_templates_command)

    ap_plan_build = sub.add_parser("plan-build", help="Generate plan/registry data from a template.")
    ap_plan_build.add_argument("--template", type=str, required=True, help="Template id")
    ap_plan_build.add_argument("--out", type=Path, required=True, help="Experiment directory root")
    ap_plan_build.add_argument("--overwrite", action="store_true", help="Overwrite existing plan/registry files")
    ap_plan_build.add_argument(
        "--skip-expected-matrix",
        action="store_true",
        help="Skip writing out/expected_matrix.json",
    )
    ap_plan_build.set_defaults(func=plan_build_command)

    ap_op_summary = sub.add_parser("summarize-ops", help="Summarize op-level runtime results.")
    ap_op_summary.add_argument("--bundle", type=Path, help="Runtime bundle root")
    ap_op_summary.add_argument("--packet", type=Path, help="Promotion packet path")
    ap_op_summary.add_argument("--out", type=Path, required=True, help="Output path for op_runtime_summary.json")
    ap_op_summary.add_argument(
        "--allow-unverified",
        action="store_true",
        help="Allow unverified bundles (skips strict bundle validation)",
    )
    ap_op_summary.add_argument(
        "--allow-nonpromotable",
        action="store_true",
        help="Allow non-promotable promotion packets",
    )
    ap_op_summary.set_defaults(func=summarize_ops_command)

    ap_reg_lint = sub.add_parser("registry-lint", help="Validate probe/profile registries.")
    ap_reg_lint.add_argument("--registry", type=str, help="Registry id (omit to lint all)")
    ap_reg_lint.set_defaults(func=registry_lint_command)

    ap_reg_upgrade = sub.add_parser("registry-upgrade", help="Normalize probe/profile registries to the current schema.")
    ap_reg_upgrade.add_argument("--registry", type=str, required=True, help="Registry id")
    ap_reg_upgrade.add_argument("--out-dir", type=Path, help="Output directory (defaults to registry dir)")
    ap_reg_upgrade.add_argument("--overwrite", action="store_true", help="Overwrite existing registry files")
    ap_reg_upgrade.set_defaults(func=registry_upgrade_command)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
