"""
Validation job for the golden-corpus experiment: re-runs decoder and
profile inspectors against the corpus manifest (including static-only
platform profiles such as platform_airlock) and checks that key structural
signals match the recorded summary. Success means decoder/IR stay aligned
with on-disk blobs; it does not validate runtime behavior or applyability.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Any, List

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.profile import decode_profile_dict
from book.api.profile.inspect import summarize_blob

from book.integration.carton.validation import registry
from book.integration.carton.validation.registry import ValidationJob

ROOT = find_repo_root(Path(__file__))
MANIFEST_PATH = ROOT / "book/evidence/syncretic/validation/golden_corpus/corpus_manifest.json"
SUMMARY_PATH = ROOT / "book/evidence/syncretic/validation/golden_corpus/corpus_summary.json"
STATUS_PATH = ROOT / "book/evidence/syncretic/validation/out/experiments/golden-corpus/status.json"
IR_PATH = ROOT / "book/evidence/syncretic/validation/out/experiments/golden-corpus/rerun_summary.json"
META_PATH = ROOT / "book/evidence/syncretic/validation/out/metadata.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"missing required input: {path}")
    return json.loads(path.read_text())


def _resolve_path(path_str: str) -> Path:
    path = Path(path_str)
    if not path.is_absolute():
        path = ROOT / path_str
    return path


def run_golden_corpus_job() -> Dict[str, Any]:
    manifest = _load_json(MANIFEST_PATH)
    summary = _load_json(SUMMARY_PATH)
    host = json.loads(META_PATH.read_text()).get("os", {}) if META_PATH.exists() else {}
    entries: List[Dict[str, Any]] = manifest.get("entries", [])
    recorded = {rec["id"]: rec for rec in summary.get("records", [])}
    mismatches: List[str] = []
    rerun_records: List[Dict[str, Any]] = []

    for entry in entries:
        rec_id = entry.get("id")
        compiled_path = entry.get("compiled_path") or entry.get("source_path")
        if not rec_id or not compiled_path:
            mismatches.append(f"entry missing id or compiled_path: {entry}")
            continue
        blob_path = _resolve_path(compiled_path)
        if not blob_path.exists():
            mismatches.append(f"{rec_id}: blob missing at {rel(blob_path)}")
            continue
        data = blob_path.read_bytes()

        decoded = decode_profile_dict(data)
        inspect_summary = summarize_blob(data)
        sections = decoded.get("sections") or {}

        rerun = {
            "id": rec_id,
            "op_count_decoded": decoded.get("op_count"),
            "node_bytes_decoded": sections.get("nodes"),
            "literal_start_decoded": sections.get("literal_start"),
            "tag_counts_decoded": decoded.get("tag_counts"),
            "op_count_inspect": inspect_summary.op_count,
            "node_bytes_inspect": inspect_summary.section_lengths.get("nodes"),
            "literal_bytes_inspect": inspect_summary.section_lengths.get("literals"),
            "tag_counts_stride12": inspect_summary.tag_counts_stride12,
        }
        rerun_records.append(rerun)

        recorded_rec = recorded.get(rec_id)
        if not recorded_rec:
            mismatches.append(f"{rec_id}: missing in recorded summary")
            continue
        rec_dec = recorded_rec.get("decoder", {})
        rec_inspect = recorded_rec.get("inspect", {})

        # Comparisons for key signals (normalize dict keys to strings for stable comparison)
        def _canon(val: Any) -> Any:
            if isinstance(val, dict):
                return {str(k): v for k, v in val.items()}
            return val

        def _cmp(label: str, a: Any, b: Any):
            if _canon(a) != _canon(b):
                mismatches.append(f"{rec_id}: {label} mismatch (expected {_canon(b)}, got {_canon(a)})")

        _cmp("op_count(decoder)", decoded.get("op_count"), rec_dec.get("op_count"))
        _cmp("node_bytes(decoder)", sections.get("nodes"), rec_dec.get("node_bytes"))
        _cmp("literal_start(decoder)", sections.get("literal_start"), rec_dec.get("literal_start"))
        _cmp("tag_counts(decoder)", decoded.get("tag_counts"), rec_dec.get("tag_counts"))
        _cmp("op_count(inspect)", inspect_summary.op_count, rec_inspect.get("op_count"))
        _cmp("node_bytes(inspect)", inspect_summary.section_lengths.get("nodes"), rec_inspect.get("node_bytes"))
        _cmp("literal_bytes(inspect)", inspect_summary.section_lengths.get("literals"), rec_inspect.get("literal_bytes"))
        _cmp("tag_counts_stride12(inspect)", inspect_summary.tag_counts_stride12, rec_inspect.get("tag_counts_stride12"))

    IR_PATH.parent.mkdir(parents=True, exist_ok=True)
    IR_PATH.write_text(json.dumps({"rerun_records": rerun_records}, indent=2))

    status = "ok" if not mismatches else "brittle"
    payload = {
        "job_id": "experiment:golden-corpus",
        "status": status,
        "host": host,
        "inputs": [rel(MANIFEST_PATH), rel(SUMMARY_PATH)],
        "outputs": [rel(IR_PATH)],
        "metrics": {"entries": len(entries), "mismatches": len(mismatches)},
        "notes": "Replayed decoder/profile against golden-corpus manifest; mismatches mark brittleness.",
        "tags": ["experiment:golden-corpus", "experiment", "static-format", "golden"],
        "mismatches": mismatches,
    }
    STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    STATUS_PATH.write_text(json.dumps(payload, indent=2))
    return payload


registry.register(
    ValidationJob(
        id="experiment:golden-corpus",
        inputs=[rel(MANIFEST_PATH), rel(SUMMARY_PATH)],
        outputs=[rel(IR_PATH), rel(STATUS_PATH)],
        tags=["experiment:golden-corpus", "experiment", "static-format", "golden"],
        description="Re-run decoder/profile on the golden corpus manifest and compare to recorded summary.",
        example_command="python -m book.integration.carton validate --experiment golden-corpus",
        runner=run_golden_corpus_job,
    )
)
