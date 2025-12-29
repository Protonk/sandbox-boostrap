"""Simple IO helpers for Ghidra scripts.

These helpers intentionally avoid fancy dependencies so they run in Ghidra's
Jython environment. Keep output deterministic (sorted keys, trailing newline)
to make shape snapshots and diffs readable.
"""

import json
import os


def ensure_out_dir(path):
    # os.makedirs is available in Jython; using it avoids pathlib compatibility issues.
    if not os.path.isdir(path):
        os.makedirs(path)


def write_json(path, payload):
    parent = os.path.dirname(path)
    if parent:
        ensure_out_dir(parent)
    with open(path, "w") as f:
        # Sorted keys + newline keep diffs stable across runs and tooling.
        json.dump(payload, f, indent=2, sort_keys=True)
        f.write("\n")
