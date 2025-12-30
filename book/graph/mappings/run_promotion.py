"""
Thin promotion helper: run validation for selected tags/ids then call mapping generators.

Usage example (runtime + system profiles):
    python -m book.graph.mappings.run_promotion \\
      --generators runtime,system-profiles
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

GENERATOR_CMDS = {
    "runtime": [
        [sys.executable, str(ROOT / "graph" / "mappings" / "runtime" / "generate_runtime_signatures.py")],
    ],
    "system-profiles": [
        [sys.executable, str(ROOT / "graph" / "mappings" / "system_profiles" / "generate_digests_from_ir.py")],
    ],
}


def run_validation(tags):
    """
    Run the validation harness with the requested tags before promotion.
    This keeps promotion tied to the same evidence tiers used to vet the
    mappings (smoke/system-profiles/etc.).
    """
    cmd = [sys.executable, "-m", "book.graph.concepts.validation"]
    for tag in tags:
        cmd.extend(["--tag", tag])
    subprocess.check_call(cmd, cwd=ROOT.parent)


def main():
    """
    Dispatch generator scripts after a minimal validation pass. The default set
    refreshes runtime signatures, system profile digests, and CARTON coverage +
    indices in a single run.
    """
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--generators",
        default="runtime,system-profiles",
        help=(
            "comma-separated generators to run "
            "(runtime,system-profiles)"
        ),
    )
    args = ap.parse_args()
    gens = [g.strip() for g in args.generators.split(",") if g.strip()]
    tags = {"smoke"}
    if "system-profiles" in gens:
        tags.add("system-profiles")
    run_validation(sorted(tags))

    for gen in gens:
        cmds = GENERATOR_CMDS.get(gen)
        if not cmds:
            raise SystemExit(f"unknown generator: {gen}")
        for cmd in cmds:
            subprocess.check_call(cmd, cwd=ROOT.parent)


if __name__ == "__main__":
    main()
