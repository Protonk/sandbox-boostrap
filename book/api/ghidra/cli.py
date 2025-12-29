"""CLI for listing and describing Ghidra task groups.

The CLI is intentionally small and read-only; it exposes registry state for
humans and tests without requiring Ghidra to be installed.
"""

from __future__ import annotations

import argparse

from . import registry


def _print_groups() -> int:
    for name in registry.list_groups():
        print(name)
    return 0


def _print_tasks(group: str | None) -> int:
    if group:
        tasks = registry.tasks_for_group(group)
    else:
        tasks = registry.all_tasks().values()
    for task in sorted(tasks, key=lambda t: t.name):
        # Keep output deterministic to simplify test assertions and shell usage.
        label = "%s (%s)" % (task.name, task.import_target)
        print("%s: %s" % (label, task.description))
    return 0


def _print_task(name: str) -> int:
    tasks = registry.all_tasks()
    if name not in tasks:
        raise SystemExit("unknown task: %s" % name)
    task = tasks[name]
    print("name: %s" % task.name)
    print("group: %s" % (task.group or ""))
    print("import_target: %s" % task.import_target)
    print("script: %s" % task.script)
    print("description: %s" % task.description)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ghidra task registry helpers")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("groups", help="List task groups")

    list_parser = sub.add_parser("list", help="List tasks")
    list_parser.add_argument("--group", help="Filter to a specific group")

    desc_parser = sub.add_parser("describe", help="Describe a task")
    desc_parser.add_argument("name", help="Task name")

    args = parser.parse_args(argv)
    if args.command == "groups":
        return _print_groups()
    if args.command == "list":
        return _print_tasks(args.group)
    if args.command == "describe":
        return _print_task(args.name)

    # Default to help so shell users see available commands instead of a stack trace.
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
