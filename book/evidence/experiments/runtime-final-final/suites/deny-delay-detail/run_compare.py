#!/usr/bin/env python3
"""
Tri-run comparison hook for a stable downloads deny configuration.
"""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from book.api import path_utils
from book.api.profile.identity import baseline_world_id
from book.api.witness import outputs
from book.api.witness.analysis import compare
from book.api.witness.models import ActionSpec, CommandSpec, EntitlementAction, SbplAction


def main() -> None:
    repo_root = path_utils.find_repo_root(Path(__file__))
    world_id = baseline_world_id(repo_root)
    out_root = path_utils.ensure_absolute(Path("book/evidence/experiments/runtime-final-final/suites/deny-delay-detail/out"), repo_root)
    out_root.mkdir(parents=True, exist_ok=True)

    run_id = str(uuid.uuid4())
    suffix = run_id.replace("-", "")[:12]
    action_id = f"downloads_direct_{suffix}"
    plan_id = f"deny-delay-detail:compare:{run_id}"
    file_name = f"atlas_compare_{suffix}.txt"

    # Use $HOME in command strings to avoid embedding absolute paths in outputs.
    host_downloads = Path.home() / "Downloads" / file_name
    host_downloads_cmd = f"$HOME/Downloads/{file_name}"

    entitlements = EntitlementAction(
        profile_id="minimal",
        probe_id="fs_op",
        probe_args=[
            "--op",
            "create",
            "--path",
            str(host_downloads),
            "--allow-unsafe-path",
        ],
        plan_id=plan_id,
        row_id="entitlements.fs_op_create_direct",
    )

    sbpl_profile = Path("book/evidence/experiments/runtime-final-final/suites/sbpl-graph-runtime/profiles/allow_all.sb")
    sbpl = SbplAction(
        command=CommandSpec(
            argv=["/bin/sh", "-c", f'echo test > "{host_downloads_cmd}"; rm -f "{host_downloads_cmd}"']
        ),
        sbpl_path=sbpl_profile,
        preflight="enforce",
    )

    none = CommandSpec(
        argv=["/bin/sh", "-c", f'echo test > "{host_downloads_cmd}"; rm -f "{host_downloads_cmd}"']
    )

    action = ActionSpec(action_id=action_id, entitlements=entitlements, sbpl=sbpl, none=none)
    output_spec = outputs.OutputSpec(out_dir=out_root / "compare" / action_id)
    report = compare.compare_action(action, output=output_spec, observer=True)

    report_path = out_root / "compare" / action_id / "comparison.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n")

    manifest = {
        "schema_version": 1,
        "world_id": world_id,
        "run_id": run_id,
        "action_id": action_id,
        "plan_id": plan_id,
        "sbpl_profile": str(sbpl_profile),
        "comparison_path": path_utils.to_repo_relative(report_path, repo_root),
        "output_dir": path_utils.to_repo_relative(report_path.parent, repo_root),
    }
    manifest_path = out_root / "compare" / action_id / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")

    print(path_utils.to_repo_relative(report_path, repo_root))


if __name__ == "__main__":
    main()
