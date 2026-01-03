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
from pathlib import Path
from typing import Dict, List

# Ensure repo root on sys.path for book.* imports.
from book.api.path_utils import ensure_absolute, find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.graph.concepts.validation import registry

METADATA_PATH = ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "out" / "metadata.json"
STATUS_PATH = ROOT / "book" / "evidence" / "graph" / "concepts" / "validation" / "out" / "validation_status.json"
ALLOWED_STATUS = {
    "ok",
    "partial",
    "brittle",
    "blocked",
    "skipped",
}


def load_host_meta() -> Dict:
    if METADATA_PATH.exists():
        try:
            data = json.loads(METADATA_PATH.read_text())
            return data.get("os", {})
        except Exception:
            return {}
    return {}


def load_world_id() -> str | None:
    if METADATA_PATH.exists():
        try:
            data = json.loads(METADATA_PATH.read_text())
            return data.get("world_id")
        except Exception:
            return None
    return None


def load_prev_status() -> Dict[str, Dict]:
    if not STATUS_PATH.exists():
        return {}
    try:
        data = json.loads(STATUS_PATH.read_text())
        return {rec.get("job_id") or rec.get("id"): rec for rec in data.get("jobs", [])}
    except Exception:
        return {}


def compute_hashes(paths: List[str]) -> Dict[str, str]:
    import hashlib

    hashes: Dict[str, str] = {}
    for p in paths or []:
        path = ensure_absolute(p, ROOT)
        if not path.exists():
            continue
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        hashes[to_repo_relative(path, ROOT)] = h.hexdigest()
    return hashes


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


def normalize_record(job: registry.ValidationJob, result: Dict, host_meta: Dict, prev_record: Dict | None) -> Dict:
    status = str(result.get("status", "ok"))
    raw_outputs = result.get("outputs", job.outputs)
    raw_inputs = result.get("inputs", job.inputs)
    hashes = compute_hashes(raw_outputs)
    change = "unknown"
    if prev_record and prev_record.get("hashes"):
        if hashes == prev_record.get("hashes"):
            change = "unchanged"
        else:
            change = "changed"
    if status not in ALLOWED_STATUS:
        status = "blocked"
    error = result.get("error")
    inputs = [to_repo_relative(p, ROOT) for p in raw_inputs]
    outputs = [to_repo_relative(p, ROOT) for p in raw_outputs]

    record = {
        "job_id": job.id,
        "status": status,
        "host": result.get("host") or host_meta,
        "inputs": inputs,
        "outputs": outputs,
        "tags": job.tags,
        "hashes": hashes,
    }
    if "notes" in result:
        record["notes"] = result["notes"]
    if "metrics" in result:
        record["metrics"] = result["metrics"]
    if error:
        record["error"] = error
    if change in {"unchanged", "changed"}:
        record["change"] = change
    return record


def run_job(job: registry.ValidationJob, skip_missing_inputs: bool, host_meta: Dict, prev_record: Dict | None) -> Dict:
    if skip_missing_inputs and not job.has_inputs():
        return normalize_record(
            job,
            {"status": "skipped", "notes": "inputs missing"},
            host_meta,
            prev_record,
        )
    try:
        result = job.runner() or {}
        return normalize_record(job, result, host_meta, prev_record)
    except Exception as exc:  # pragma: no cover
        return normalize_record(job, {"status": "blocked", "error": f"{exc}"}, host_meta, prev_record)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="run all registered jobs")
    ap.add_argument("--id", action="append", default=[], help="run a specific job id (repeatable)")
    ap.add_argument("--tag", action="append", default=[], help="select jobs by tag (repeatable)")
    ap.add_argument("--experiment", action="append", default=[], help="select jobs tagged with experiment:<name>")
    ap.add_argument("--skip-missing-inputs", action="store_true", help="skip jobs whose inputs are absent")
    ap.add_argument("--list", action="store_true", help="list available jobs and exit")
    ap.add_argument("--describe", help="show details for a specific job id and exit")
    args = ap.parse_args()

    jobs = registry.load_all_jobs()
    prev_status = load_prev_status()

    if args.describe:
        job = next((j for j in jobs if j.id == args.describe), None)
        if not job:
            print(f"unknown job id: {args.describe}")
            sys.exit(1)
        print(f"job: {job.id}")
        print(f"tags: {', '.join(job.tags) if job.tags else '-'}")
        print(f"inputs: {job.inputs or '-'}")
        print(f"outputs: {job.outputs or '-'}")
        print(f"description: {job.description or '-'}")
        if job.example_command:
            print(f"example: {job.example_command}")
        return

    if args.list:
        for job in jobs:
            tags = ",".join(job.tags) if job.tags else "-"
            desc = f" – {job.description}" if job.description else ""
            print(f"{job.id} [{tags}]{desc}")
        return

    selected = select_jobs(jobs, args.id, args.tag, args.experiment, args.all)
    if not selected:
        print("No jobs selected; use --all or --list to see options.")
        sys.exit(1)

    host_meta = load_host_meta()
    world_id = load_world_id()
    results = [run_job(job, args.skip_missing_inputs, host_meta, prev_status.get(job.id)) for job in selected]
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": {
            "job_id": "string",
            "status": "ok|partial|brittle|blocked|skipped",
            "host": "object",
            "inputs": "list[str]",
            "outputs": "list[str]",
            "tags": "list[str]",
            "notes": "string?",
            "metrics": "object?",
            "error": "string?",
            "change": "changed|unchanged?",
        },
        "world_id": world_id,
        "jobs": results,
    }
    STATUS_PATH.write_text(json.dumps(payload, indent=2))

    # Human-friendly summary
    for res in results:
        print(f"{res['job_id']}: {res['status']}")


if __name__ == "__main__":
    main()
