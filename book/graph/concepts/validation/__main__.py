"""
Single entrypoint for validation jobs.

Usage examples:
- python -m book.graph.concepts.validation --all
- python -m book.graph.concepts.validation --tag vocab
- python -m book.graph.concepts.validation --experiment field2
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List

# Ensure repo root on sys.path for book.* imports.
ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.graph.concepts.validation import registry


def select_jobs(
    jobs: List[registry.ValidationJob],
    ids: List[str],
    tags: List[str],
    experiments: List[str],
    run_all: bool,
) -> List[registry.ValidationJob]:
    if run_all or (not ids and not tags and not experiments):
        return jobs

    selected: List[registry.ValidationJob] = []
    for job in jobs:
        if ids and job.id not in ids:
            continue
        if tags and not any(
            tag in job.tags or job.id.startswith(f"{tag}:") for tag in tags
        ):
            continue
        if experiments and not any(f"experiment:{exp}" in job.tags for exp in experiments):
            continue
        selected.append(job)
    return selected


def run_job(job: registry.ValidationJob, skip_missing_inputs: bool) -> Dict:
    if skip_missing_inputs and not job.has_inputs():
        return {
            "id": job.id,
            "status": "skipped",
            "tags": job.tags,
            "reason": "inputs missing",
            "inputs": job.inputs,
            "outputs": job.outputs,
        }
    try:
        result = job.runner() or {}
        status = result.get("status", "ok")
        return {
            "id": job.id,
            "status": status,
            "tags": job.tags,
            "inputs": job.inputs,
            "outputs": result.get("outputs", job.outputs),
            "metadata": {k: v for k, v in result.items() if k not in {"status", "outputs"}},
        }
    except Exception as exc:  # pragma: no cover
        return {
            "id": job.id,
            "status": "blocked",
            "tags": job.tags,
            "inputs": job.inputs,
            "outputs": job.outputs,
            "error": f"{exc}",
        }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="run all registered jobs")
    ap.add_argument("--id", action="append", default=[], help="run a specific job id (repeatable)")
    ap.add_argument("--tag", action="append", default=[], help="select jobs by tag (repeatable)")
    ap.add_argument("--experiment", action="append", default=[], help="select jobs tagged with experiment:<name>")
    ap.add_argument("--skip-missing-inputs", action="store_true", help="skip jobs whose inputs are absent")
    ap.add_argument("--list", action="store_true", help="list available jobs and exit")
    args = ap.parse_args()

    jobs = registry.load_all_jobs()

    if args.list:
        for job in jobs:
            tags = ",".join(job.tags) if job.tags else "-"
            print(f"{job.id} [{tags}]")
        return

    selected = select_jobs(jobs, args.id, args.tag, args.experiment, args.all)
    if not selected:
        print("No jobs selected; use --all or --list to see options.")
        sys.exit(1)

    results = [run_job(job, args.skip_missing_inputs) for job in selected]
    status_path = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"
    status_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "jobs": results,
    }
    status_path.write_text(json.dumps(payload, indent=2))

    # Human-friendly summary
    for res in results:
        print(f"{res['id']}: {res['status']}")


if __name__ == "__main__":
    main()
