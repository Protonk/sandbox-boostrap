#!/usr/bin/env python3
"""
Deprecated wrapper: run runtime-adversarial via runtime plan execution.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from book.api import path_utils
from book.api.runtime import api as runtime_api
from book.api.runtime.channels import ChannelSpec


REPO_ROOT = path_utils.find_repo_root(Path(__file__))
PLAN = Path(__file__).with_name("plan.json")
OUT_DIR = Path(__file__).with_name("out")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run runtime-adversarial via runtime plan.")
    parser.add_argument("--out", type=Path, default=OUT_DIR, help="Output directory")
    parser.add_argument("--channel", type=str, default="launchd_clean", help="Channel (launchd_clean|direct)")
    parser.add_argument("--only-profile", action="append", default=[], help="Limit to a profile_id")
    parser.add_argument("--only-scenario", action="append", default=[], help="Limit to an expectation_id")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    channel = ChannelSpec(channel=args.channel, require_clean=(args.channel == "launchd_clean"))
    runtime_api.run_plan(
        PLAN,
        args.out,
        channel=channel,
        only_profiles=args.only_profile,
        only_scenarios=args.only_scenario,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
