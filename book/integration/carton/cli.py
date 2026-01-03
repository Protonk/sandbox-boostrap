"""Unified CLI for CARTON pipeline operations."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable, List, Optional

from book.integration.carton import paths
from book.integration.carton.core import pipeline as pipeline_mod
from book.integration.carton.core import registry as registry_mod
from book.integration.carton.core.models import Registry
from book.integration.carton.tools import check as check_mod
from book.integration.carton.tools import diff as diff_mod


def _repo_root() -> Path:
    return paths.repo_root()


def _parse_csv(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _run_check(repo_root: Path) -> None:
    spec_path = paths.ensure_absolute(paths.CARTON_SPEC, repo_root_path=repo_root)
    manifest_path = paths.ensure_absolute(paths.MANIFEST_PATH, repo_root_path=repo_root)
    errors = check_mod.run_check(
        spec_path=spec_path,
        manifest_path=manifest_path,
        repo_root=repo_root,
    )
    if errors:
        print("CARTON check failed:")
        for err in errors:
            print(f"- {err}")
        raise SystemExit(1)
    print("CARTON check OK")


def _resolve_jobs(
    registry: Registry,
    *,
    include_mappings: bool,
    promote: bool,
    explicit_ids: Optional[Iterable[str]] = None,
) -> List[str]:
    job_ids: List[str] = registry.job_ids(kinds=["meta"])
    if explicit_ids:
        job_ids.extend(explicit_ids)
        return job_ids
    if include_mappings:
        job_ids.extend(registry.job_ids(kinds=["mapping", "promotion"]))
    elif promote:
        job_ids.extend(registry.job_ids(kinds=["promotion"]))
    job_ids.extend(registry.job_ids(kinds=["fixer", "contracts"]))
    return job_ids


def cmd_build(args: argparse.Namespace) -> None:
    repo_root = _repo_root()
    registry = registry_mod.build_registry()
    pipeline = pipeline_mod.Pipeline(registry, repo_root)
    job_ids = _resolve_jobs(
        registry,
        include_mappings=args.include_mappings,
        promote=args.promote,
        explicit_ids=_parse_csv(args.jobs) or None,
    )
    pipeline.run_jobs(job_ids, changed_only=not args.no_changed_only)
    if not args.skip_check:
        _run_check(repo_root)

def cmd_fix(args: argparse.Namespace) -> None:
    repo_root = _repo_root()
    registry = registry_mod.build_registry()
    pipeline = pipeline_mod.Pipeline(registry, repo_root)
    job_ids = registry.job_ids(kinds=["meta"])
    if args.jobs:
        job_ids.extend(_parse_csv(args.jobs))
    else:
        job_ids.extend(registry.job_ids(kinds=["fixer"]))
    pipeline.run_jobs(job_ids, changed_only=not args.no_changed_only)


def cmd_promote(args: argparse.Namespace) -> None:
    args.promote = True
    cmd_build(args)


def cmd_check(_args: argparse.Namespace) -> None:
    _run_check(_repo_root())


def cmd_diff(args: argparse.Namespace) -> None:
    diff_mod.main(
        [
            "--spec",
            args.spec,
            "--manifest",
            args.manifest,
        ]
        + (["--other", args.other] if args.other else [])
    )


def cmd_graph(args: argparse.Namespace) -> None:
    repo_root = _repo_root()
    registry = registry_mod.build_registry()
    pipeline = pipeline_mod.Pipeline(registry, repo_root)
    job_ids = _resolve_jobs(
        registry,
        include_mappings=args.include_mappings,
        promote=args.promote,
        explicit_ids=_parse_csv(args.jobs) or None,
    )
    for line in pipeline.graph_lines(job_ids):
        print(line)


def cmd_explain(args: argparse.Namespace) -> None:
    repo_root = _repo_root()
    registry = registry_mod.build_registry()
    pipeline = pipeline_mod.Pipeline(registry, repo_root)
    for line in pipeline.explain(args.job_id):
        print(line)


def cmd_validate(args: argparse.Namespace) -> None:
    from book.integration.carton.validation import __main__ as validation_main

    argv: List[str] = []
    if args.all:
        argv.append("--all")
    for job_id in args.id:
        argv.extend(["--id", job_id])
    for tag in args.tag:
        argv.extend(["--tag", tag])
    for experiment in args.experiment:
        argv.extend(["--experiment", experiment])
    if args.skip_missing_inputs:
        argv.append("--skip-missing-inputs")
    if args.list:
        argv.append("--list")
    if args.describe:
        argv.extend(["--describe", args.describe])
    validation_main.main(argv)


def cmd_swift(args: argparse.Namespace) -> None:
    from book.integration.carton.jobs import graph as graph_jobs

    repo_root = _repo_root()
    if args.build and args.run:
        raise SystemExit("swift: choose one of --build or --run")
    if args.build:
        graph_jobs.run_swift_build(repo_root)
        return
    graph_jobs.run_swift_run(repo_root)


def cmd_track(args: argparse.Namespace) -> None:
    repo_root = _repo_root()
    registry = registry_mod.build_registry()
    pipeline = pipeline_mod.Pipeline(registry, repo_root)
    job_ids = registry.job_ids(kinds=["meta"]) + ["contracts.manifest"]
    pipeline.run_jobs(job_ids, changed_only=not args.no_changed_only)
    if not args.skip_check:
        _run_check(repo_root)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CARTON pipeline CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    build = subparsers.add_parser("build", help="Build CARTON bundle")
    build.add_argument("--include-mappings", action="store_true", help="run mapping + promotion jobs")
    build.add_argument("--promote", action="store_true", help="run promotion jobs before fixers")
    build.add_argument("--jobs", help="comma-separated job ids to run (overrides defaults)")
    build.add_argument("--no-changed-only", action="store_true", help="run all jobs even if outputs look fresh")
    build.add_argument("--skip-check", action="store_true", help="skip CARTON check at end")
    build.set_defaults(func=cmd_build)

    fix = subparsers.add_parser("fix", help="Run CARTON fixers only")
    fix.add_argument("--jobs", help="comma-separated fixer job ids to run (default: all fixers)")
    fix.add_argument("--no-changed-only", action="store_true", help="run all fixers even if outputs look fresh")
    fix.set_defaults(func=cmd_fix)

    promote = subparsers.add_parser("promote", help="Promote runtime mappings and rebuild CARTON bundle")
    promote.add_argument("--include-mappings", action="store_true", help="run mapping + promotion jobs")
    promote.add_argument("--jobs", help="comma-separated job ids to run (overrides defaults)")
    promote.add_argument("--no-changed-only", action="store_true", help="run all jobs even if outputs look fresh")
    promote.add_argument("--skip-check", action="store_true", help="skip CARTON check at end")
    promote.set_defaults(func=cmd_promote)

    check = subparsers.add_parser("check", help="Verify CARTON bundle")
    check.set_defaults(func=cmd_check)

    diff = subparsers.add_parser("diff", help="Show CARTON drift report")
    diff.add_argument("--spec", default=str(paths.CARTON_SPEC), help="repo-relative spec path")
    diff.add_argument("--manifest", default=str(paths.MANIFEST_PATH), help="repo-relative manifest path")
    diff.add_argument("--other", help="optional other manifest (repo-relative)")
    diff.set_defaults(func=cmd_diff)

    graph = subparsers.add_parser("graph", help="Show CARTON job graph")
    graph.add_argument("--include-mappings", action="store_true", help="include mapping + promotion jobs")
    graph.add_argument("--promote", action="store_true", help="include promotion jobs")
    graph.add_argument("--jobs", help="comma-separated job ids to render (overrides defaults)")
    graph.set_defaults(func=cmd_graph)

    explain = subparsers.add_parser("explain", help="Explain a CARTON job")
    explain.add_argument("job_id", help="job id to explain")
    explain.set_defaults(func=cmd_explain)

    validate = subparsers.add_parser("validate", help="Run validation jobs")
    validate.add_argument("--all", action="store_true", help="run all registered jobs")
    validate.add_argument("--id", action="append", default=[], help="run a specific job id (repeatable)")
    validate.add_argument("--tag", action="append", default=[], help="run jobs matching tag (repeatable)")
    validate.add_argument(
        "--experiment", action="append", default=[], help="run jobs matching experiment (repeatable)"
    )
    validate.add_argument("--skip-missing-inputs", action="store_true", help="skip jobs whose inputs are absent")
    validate.add_argument("--list", action="store_true", help="list available jobs and exit")
    validate.add_argument("--describe", help="show details for a specific job id and exit")
    validate.set_defaults(func=cmd_validate)

    swift = subparsers.add_parser("swift", help="Run the Swift graph tool")
    swift.add_argument("--run", action="store_true", help="run the Swift graph tool")
    swift.add_argument("--build", action="store_true", help="build the Swift graph tool")
    swift.set_defaults(func=cmd_swift)

    track = subparsers.add_parser("track", help="Update inventory graph and CARTON manifest")
    track.add_argument("--no-changed-only", action="store_true", help="run all jobs even if outputs look fresh")
    track.add_argument("--skip-check", action="store_true", help="skip CARTON check at end")
    track.set_defaults(func=cmd_track)

    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)
