"""CLI entrypoints for Frida helpers."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Optional, Sequence

from book.api import path_utils


def _add_runner_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument(
        "--spawn",
        nargs="+",
        help="Spawn argv (preferred for bootstrap), e.g. --spawn ./targets/open_loop /etc/hosts",
    )
    ap.add_argument("--attach-pid", type=int, help="Attach to an existing pid")
    ap.add_argument("--script", required=True, help="Path to frida agent JS")
    ap.add_argument("--frida-config", default=None, help="JSON object for script configure()")
    ap.add_argument("--frida-config-path", default=None, help="Path to JSON file for script configure()")
    ap.add_argument(
        "--out-dir",
        default="book/api/frida/out",
        help="Output directory",
    )
    ap.add_argument(
        "--duration-s",
        type=float,
        default=None,
        help="How long to run before detach (spawn mode; also used for attach when set)",
    )


def _run_runner(args: argparse.Namespace) -> int:
    from book.api.frida import runner

    return runner.run(
        spawn=args.spawn,
        attach_pid=args.attach_pid,
        script=args.script,
        config_json=args.frida_config,
        config_path=args.frida_config_path,
        out_dir=args.out_dir,
        duration_s=args.duration_s,
    )


def _run_normalize(args: argparse.Namespace) -> int:
    from book.api.frida.normalize import normalize_run_dir

    repo_root = path_utils.find_repo_root()
    run_dir = path_utils.ensure_absolute(args.run_dir, repo_root)
    report = normalize_run_dir(run_dir)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def _run_index(args: argparse.Namespace) -> int:
    from book.api.frida.query import build_index

    repo_root = path_utils.find_repo_root()
    run_dir = path_utils.ensure_absolute(args.run_dir, repo_root)
    index_path = args.index_path
    report = build_index(run_dir=run_dir, index_path=index_path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def _run_query(args: argparse.Namespace) -> int:
    from book.api.frida.query import query_run_dir

    if (args.sql is None) == (args.sql_file is None):
        raise SystemExit("Provide exactly one of --sql or --sql-file")

    sql_text = args.sql
    if args.sql_file is not None:
        repo_root = path_utils.find_repo_root()
        sql_path = path_utils.ensure_absolute(args.sql_file, repo_root)
        sql_text = sql_path.read_text()

    report = query_run_dir(
        run_dir=args.run_dir,
        sql=sql_text,
        use_index=args.use_index,
        index_path=args.index_path,
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def _run_export(args: argparse.Namespace) -> int:
    from book.api.frida.export_chrometrace import export_run_dir

    repo_root = path_utils.find_repo_root()
    run_dir = path_utils.ensure_absolute(args.run_dir, repo_root)
    out_path = args.out_path
    report = export_run_dir(run_dir, out_path=out_path)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def _run_validate(args: argparse.Namespace) -> int:
    from book.api.frida.validate import validate_run_dirs

    report = validate_run_dirs([Path(p) for p in args.run_dirs])
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def _run_generate_hook(args: argparse.Namespace) -> int:
    from book.api.frida.generate_hook import HookGeneratorError, generate_hook_files, write_generated_hook

    repo_root = path_utils.find_repo_root()
    input_path = path_utils.ensure_absolute(args.input, repo_root)
    try:
        input_obj = json.loads(input_path.read_text())
    except json.JSONDecodeError as exc:
        msg = " ".join(str(exc.msg).split())
        report = {
            "ok": False,
            "error": f"JSONDecodeError: {msg} (line {exc.lineno} col {exc.colno})",
            "input_path": path_utils.to_repo_relative(input_path, repo_root),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    except Exception as exc:
        report = {
            "ok": False,
            "error": f"{type(exc).__name__}: {exc}",
            "input_path": path_utils.to_repo_relative(input_path, repo_root),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    try:
        out = generate_hook_files(input_obj)
        hook_js = out["hook_js"]
        manifest_json = out["manifest_json"]
        hook_name = str(manifest_json.get("hook", {}).get("id"))
        write_report = write_generated_hook(
            Path(args.out_dir),
            hook_name=hook_name,
            hook_js=hook_js,
            manifest_json=manifest_json,
            force=bool(args.force),
        )
    except HookGeneratorError as exc:
        report = {
            "ok": False,
            "error": str(exc),
            "input_path": path_utils.to_repo_relative(input_path, repo_root),
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1

    report = {
        "ok": True,
        "input_path": path_utils.to_repo_relative(input_path, repo_root),
        "write": write_report,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


def _run_build_ts_hooks(args: argparse.Namespace) -> int:
    from book.api.frida.build_ts_hooks import TSHookBuildError, build_ts_hooks

    try:
        report = build_ts_hooks(force=bool(args.force), check=bool(args.check))
    except TSHookBuildError as exc:
        out = {"ok": False, "error": str(exc)}
        print(json.dumps(out, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report.get("ok") else 1


def build_arg_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="Spawn/attach a process and run a Frida script")
    _add_runner_args(run_parser)
    run_parser.set_defaults(func=_run_runner)

    norm_parser = sub.add_parser("normalize", help="Normalize a run directory to trace v1 (in-place)")
    norm_parser.add_argument("run_dir", help="Run directory containing meta.json + events.jsonl")
    norm_parser.set_defaults(func=_run_normalize)

    idx_parser = sub.add_parser("index", help="Build/refresh a cached DuckDB index for a run directory")
    idx_parser.add_argument("run_dir", help="Run directory containing meta.json + events.jsonl")
    idx_parser.add_argument("--index-path", default=None, help="Override output DuckDB path (default: <run_dir>/index.duckdb)")
    idx_parser.set_defaults(func=_run_index)

    q_parser = sub.add_parser("query", help="Run a DuckDB SQL query over a run directory event stream")
    q_parser.add_argument("run_dir", help="Run directory containing meta.json + events.jsonl")
    q_parser.add_argument("--sql", default=None, help="SQL query text (must reference 'events')")
    q_parser.add_argument("--sql-file", default=None, help="Path to a .sql file (must reference 'events')")
    q_parser.add_argument("--use-index", action="store_true", help="Query the cached index.duckdb table instead of JSONL")
    q_parser.add_argument("--index-path", default=None, help="Override index DuckDB path (default: <run_dir>/index.duckdb)")
    q_parser.set_defaults(func=_run_query)

    ex_parser = sub.add_parser("export", help="Export a normalized trace v1 run to Chrome Trace JSON (artifact)")
    ex_parser.add_argument("run_dir", help="Run directory containing meta.json + events.jsonl (trace v1)")
    ex_parser.add_argument("--out-path", default=None, help="Override output trace path (default: <run_dir>/trace.chrometrace.json)")
    ex_parser.set_defaults(func=_run_export)

    val_parser = sub.add_parser("validate", help="Validate schema/query/export invariants for run directories")
    val_parser.add_argument("run_dirs", nargs="+", help="Run directories containing meta.json + events.jsonl")
    val_parser.set_defaults(func=_run_validate)

    gen_parser = sub.add_parser("generate-hook", help="Generate a new hook + manifest from a v1 input JSON")
    gen_parser.add_argument("--input", required=True, help="Path to HOOK_GENERATOR_INPUT v1 JSON")
    gen_parser.add_argument(
        "--out-dir",
        default="book/api/frida/hooks",
        help="Output directory (default: book/api/frida/hooks)",
    )
    gen_parser.add_argument("--force", action="store_true", help="Overwrite existing files")
    gen_parser.set_defaults(func=_run_generate_hook)

    ts_parser = sub.add_parser("build-ts-hooks", help="Compile hooks_ts/*.ts into runtime hooks/*.js artifacts")
    ts_parser.add_argument("--force", action="store_true", help="Overwrite existing runtime hook artifacts")
    ts_parser.add_argument("--check", action="store_true", help="Check whether runtime artifacts are up to date (no writes)")
    ts_parser.set_defaults(func=_run_build_ts_hooks)

    return ap


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = build_arg_parser()
    args = ap.parse_args(argv)
    func = getattr(args, "func", None)
    if func is None:
        raise SystemExit("missing subcommand")
    return func(args)


if __name__ == "__main__":
    raise SystemExit(main())
