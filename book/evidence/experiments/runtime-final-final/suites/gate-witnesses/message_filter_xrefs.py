#!/usr/bin/env python3
"""
Generate a small, durable xref report for message-filter-related kernel strings.

Goal (host-grounded):
- Turn the kernel string clue ("missing message filter entitlement") into an xref
  boundary object: which sandbox-kext functions reference the relevant strings?
- Cross-check userland dyld slices for presence/absence of the entitlement key.

This script relies on existing host artifacts:
- Ghidra project: book/dumps/ghidra/projects/sandbox_kext_14.4.1-23E224.{gpr,rep}
- KC/kext inputs under book/dumps/ghidra/private/aapl-restricted/14.4.1-23E224/...

It writes a compact summary JSON under this experiment's out/ directory.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.ghidra import connector as gh_connector
from book.api.path_utils import to_repo_relative
from book.api.runtime.contracts.models import WORLD_ID


BUILD_ID = "14.4.1-23E224"
GHIDRA_TASK = "sandbox-kext-string-refs"
GHIDRA_PROJECT = f"sandbox_kext_{BUILD_ID}"

ENTITLEMENT_MESSAGE_FILTER = "com.apple.private.security.message-filter"
ENTITLEMENT_MESSAGE_FILTER_MANAGER = "com.apple.private.security.message-filter-manager"

KERNEL_QUERY_STRINGS = [
    ENTITLEMENT_MESSAGE_FILTER,
    ENTITLEMENT_MESSAGE_FILTER_MANAGER,
    "missing message filter entitlement",
    "failed to associate message filter",
    "cannot apply mach message filtering",
]

USERLAND_STRING_QUERIES = [
    ENTITLEMENT_MESSAGE_FILTER,
    ENTITLEMENT_MESSAGE_FILTER_MANAGER,
]

DYLD_SLICES = [
    REPO_ROOT / "book/evidence/graph/mappings/dyld-libs/usr/lib/libsandbox.1.dylib",
    REPO_ROOT / "book/evidence/graph/mappings/dyld-libs/usr/lib/system/libsystem_sandbox.dylib",
]


def _strings_contains_counts(path: Path, needles: Sequence[str], max_samples_per_needle: int = 5) -> Dict[str, Any]:
    cmd_exec = ["/usr/bin/strings", "-a", str(path)]
    proc = subprocess.Popen(cmd_exec, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    counts: Dict[str, int] = {n: 0 for n in needles}
    samples: Dict[str, List[str]] = {n: [] for n in needles}
    assert proc.stdout is not None
    for line in proc.stdout:
        s = line.strip()
        for needle in needles:
            if needle in s:
                counts[needle] += 1
                if len(samples[needle]) < max_samples_per_needle:
                    samples[needle].append(s)
    stderr = (proc.stderr.read() if proc.stderr else "") if proc.stderr else ""
    rc = proc.wait(timeout=30)
    return {"tool": "/usr/bin/strings", "args": ["-a"], "rc": rc, "stderr": stderr.strip() or None, "counts": counts, "samples": samples}


def _ensure_kernel_xrefs(
    refresh: bool,
    ghidra_headless: Optional[str],
    java_home: Optional[str],
    no_analysis: bool,
) -> Path:
    out_path = REPO_ROOT / f"book/evidence/dumps/ghidra/out/{BUILD_ID}/{GHIDRA_TASK}/string_references.json"
    if not refresh:
        return out_path

    runner = gh_connector.HeadlessConnector(ghidra_headless=ghidra_headless, java_home=java_home)
    invocation = runner.build(
        task_name=GHIDRA_TASK,
        build_id=BUILD_ID,
        project_name=GHIDRA_PROJECT,
        process_existing=True,
        no_analysis=no_analysis,
        script_args=list(KERNEL_QUERY_STRINGS),
    )
    result = runner.run(invocation, execute=True, timeout=900)
    if result.returncode != 0:
        raise RuntimeError(f"ghidra task failed: {GHIDRA_TASK} rc={result.returncode} out_dir={invocation.out_dir}")
    return out_path


def _summarize_ghidra_string_refs(payload: Dict[str, Any], query_set: Iterable[str]) -> Dict[str, Any]:
    queries = set(query_set)
    strings = payload.get("strings") if isinstance(payload.get("strings"), list) else []

    hits: List[Dict[str, Any]] = []
    for entry in strings:
        if not isinstance(entry, dict):
            continue
        matched = [q for q in entry.get("queries", []) if q in queries] if isinstance(entry.get("queries"), list) else []
        if not matched:
            continue
        refs = entry.get("references") if isinstance(entry.get("references"), list) else []
        func_names = sorted({r.get("function") for r in refs if isinstance(r, dict) and isinstance(r.get("function"), str)})
        hits.append(
            {
                "value": entry.get("value"),
                "address": entry.get("address"),
                "block": entry.get("block"),
                "queries": matched,
                "reference_count": len(refs),
                "functions": func_names,
            }
        )

    hits.sort(key=lambda h: (h.get("value") or "", h.get("address") or ""))
    return {"hits": hits, "hit_count": len(hits)}


def _read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    default_out = REPO_ROOT / "book/evidence/experiments/runtime-final-final/suites/gate-witnesses/out/message_filter_xrefs.json"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(default_out), help="Output JSON path.")
    parser.add_argument(
        "--refresh-ghidra",
        action="store_true",
        help="Run the Ghidra task to refresh book/evidence/dumps/ghidra/out before summarizing.",
    )
    parser.add_argument(
        "--no-analysis",
        action="store_true",
        help="When refreshing, pass -noanalysis (xref quality may be lower).",
    )
    parser.add_argument("--ghidra-headless", default=os.environ.get("GHIDRA_HEADLESS"), help="Path to analyzeHeadless.")
    parser.add_argument("--java-home", default=os.environ.get("JAVA_HOME"), help="JAVA_HOME to use for headless.")
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    out_path = Path(args.out)

    ghidra_out_path = _ensure_kernel_xrefs(
        refresh=args.refresh_ghidra,
        ghidra_headless=args.ghidra_headless,
        java_home=args.java_home,
        no_analysis=args.no_analysis,
    )
    ghidra_payload = _read_json(ghidra_out_path) if ghidra_out_path.exists() else {}

    kernel_summary = _summarize_ghidra_string_refs(ghidra_payload, KERNEL_QUERY_STRINGS)

    userland_results: List[Dict[str, Any]] = []
    for lib in DYLD_SLICES:
        entry: Dict[str, Any] = {"path": to_repo_relative(lib, REPO_ROOT), "exists": lib.exists()}
        if lib.exists():
            entry["strings"] = _strings_contains_counts(lib, USERLAND_STRING_QUERIES)
        userland_results.append(entry)

    payload: Dict[str, Any] = {
        "schema_version": "1.0",
        "world_id": WORLD_ID,
        "kernel": {
            "build_id": BUILD_ID,
            "ghidra_task": GHIDRA_TASK,
            "ghidra_project": GHIDRA_PROJECT,
            "queries": list(KERNEL_QUERY_STRINGS),
            "source": to_repo_relative(ghidra_out_path, REPO_ROOT),
            **kernel_summary,
        },
        "userland": {
            "queries": list(USERLAND_STRING_QUERIES),
            "dyld_slices": userland_results,
        },
    }
    _write_json(out_path, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
