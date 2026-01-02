"""
Normalize raw DTrace JSONL into phase-keyed deny signatures.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
from collections import Counter
from typing import Any, Dict, List, Tuple

from book.api import path_utils
from book.api.profile.identity import baseline_world_id

USER_RE = re.compile(r"^/Users/[^/]+")


def shape_path(path: str) -> str:
    if not path:
        return ""
    return USER_RE.sub("/Users/$USER", path)


def load_events(path: pathlib.Path, *, phase: str) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    events: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    if not path.exists():
        return events, errors
    for idx, line in enumerate(path.read_text().splitlines()):
        raw = line.strip()
        if not raw:
            continue
        try:
            event = json.loads(raw)
        except Exception as exc:
            errors.append({"line": idx + 1, "error": f"{type(exc).__name__}: {exc}"})
            continue
        event["phase"] = phase
        events.append(event)
    return events, errors


def signature_key(event: Dict[str, Any]) -> Tuple[Any, ...]:
    phase = event.get("phase")
    kind = event.get("kind")
    name = event.get("name")
    errno = event.get("errno")
    if kind == "syscall":
        path_shape = shape_path(str(event.get("path") or ""))
        path2_shape = shape_path(str(event.get("path2") or ""))
        return (phase, kind, name, errno, path_shape, path2_shape)
    if kind == "sandbox_api":
        op = str(event.get("op") or "")
        return (phase, kind, name, errno, op)
    return (phase, kind, name, errno)


def key_to_record(key: Tuple[Any, ...]) -> Dict[str, Any]:
    phase, kind, name, errno, *rest = key
    record: Dict[str, Any] = {
        "phase": phase,
        "kind": kind,
        "name": name,
        "errno": errno,
    }
    if kind == "syscall":
        record["path_shape"] = rest[0] if len(rest) > 0 else ""
        record["path2_shape"] = rest[1] if len(rest) > 1 else ""
    elif kind == "sandbox_api":
        record["op"] = rest[0] if rest else ""
    return record


def normalize(
    *,
    repo_root: pathlib.Path,
    raw_inputs: Dict[str, pathlib.Path],
    out_path: pathlib.Path,
) -> None:
    all_events: List[Dict[str, Any]] = []
    input_meta: List[Dict[str, Any]] = []
    parse_errors: Dict[str, List[Dict[str, Any]]] = {}

    for phase, raw_path in raw_inputs.items():
        events, errors = load_events(raw_path, phase=phase)
        all_events.extend(events)
        input_meta.append(
            {
                "phase": phase,
                "raw_path": path_utils.to_repo_relative(raw_path, repo_root),
                "event_count": len(events),
                "parse_error_count": len(errors),
            }
        )
        if errors:
            parse_errors[phase] = errors

    counter: Counter[Tuple[Any, ...]] = Counter()
    for event in all_events:
        counter[signature_key(event)] += 1

    signatures = []
    for key, count in sorted(counter.items(), key=lambda item: (item[0][0], -item[1], item[0][2] or "")):
        record = key_to_record(key)
        record["count"] = count
        signatures.append(record)

    output = {
        "world_id": baseline_world_id(repo_root),
        "inputs": input_meta,
        "deny_signatures": signatures,
        "path_shape": {
            "rule": "replace /Users/<name> with /Users/$USER",
        },
        "parse_errors": parse_errors,
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize DTrace JSONL captures.")
    parser.add_argument(
        "--out",
        default="book/evidence/experiments/runtime-final-final/suites/dtrace-testing/out/normalized/deny_signatures.json",
        help="Output JSON path.",
    )
    parser.add_argument(
        "--raw-smoke",
        default="book/evidence/experiments/runtime-final-final/suites/dtrace-testing/out/raw/smoke.jsonl",
        help="Raw smoke JSONL path.",
    )
    parser.add_argument(
        "--raw-idle",
        default="book/evidence/experiments/runtime-final-final/suites/dtrace-testing/out/raw/idle.jsonl",
        help="Raw idle JSONL path.",
    )
    parser.add_argument(
        "--raw-interaction",
        default="book/evidence/experiments/runtime-final-final/suites/dtrace-testing/out/raw/interaction.jsonl",
        help="Raw interaction JSONL path.",
    )
    args = parser.parse_args()

    repo_root = path_utils.find_repo_root(pathlib.Path(__file__))
    raw_inputs = {
        "smoke": path_utils.ensure_absolute(args.raw_smoke, repo_root),
        "idle": path_utils.ensure_absolute(args.raw_idle, repo_root),
        "interaction": path_utils.ensure_absolute(args.raw_interaction, repo_root),
    }
    out_path = path_utils.ensure_absolute(args.out, repo_root)

    normalize(repo_root=repo_root, raw_inputs=raw_inputs, out_path=out_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
