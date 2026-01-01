import json
import subprocess
import sys
from pathlib import Path

from book.api import path_utils
from book.api.runtime.analysis import packet_utils

ROOT = path_utils.find_repo_root(Path(__file__))
PACKET_PATH = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "promotion_packet.json"
REQUIRED_EXPORTS = ("runtime_events", "baseline_results", "run_manifest")


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    records = []
    for line in path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def _packet_context():
    assert PACKET_PATH.exists(), f"missing promotion packet: {PACKET_PATH}"
    return packet_utils.resolve_packet_context(PACKET_PATH, required_exports=REQUIRED_EXPORTS, repo_root=ROOT)


def _run_atlas_build(tmp_path: Path, run_id: str) -> Path:
    script = ROOT / "book" / "experiments" / "field2-atlas" / "atlas_build.py"
    subprocess.check_call(
        [
            sys.executable,
            str(script),
            "--packet",
            str(PACKET_PATH),
            "--out-root",
            str(tmp_path),
        ]
    )
    return tmp_path / run_id


def test_field2_atlas_packet_consumer(tmp_path):
    ctx = _packet_context()

    seeds_doc = load_json(ROOT / "book" / "experiments" / "field2-atlas" / "field2_seeds.json")
    seeds = seeds_doc.get("seeds") or []
    seed_ids = {entry["field2"] for entry in seeds}

    assert seeds, "expected a non-empty seed manifest"
    assert {0, 5, 7}.issubset(seed_ids), "baseline field2 seeds should remain present"

    static_records = load_jsonl(ROOT / "book" / "experiments" / "field2-atlas" / "out" / "static" / "field2_records.jsonl")
    static_by_id = {entry["field2"]: entry for entry in static_records}
    for fid in seed_ids:
        assert fid in static_by_id, f"no static record for seed field2={fid}"
        has_anchor = bool(static_by_id[fid].get("anchor_hits"))
        has_profile = bool(static_by_id[fid].get("profiles"))
        assert has_anchor or has_profile, f"seed field2={fid} missing static witnesses"

    derived_root = _run_atlas_build(tmp_path, ctx.run_id)
    runtime_path = derived_root / "runtime" / "field2_runtime_results.json"
    atlas_path = derived_root / "atlas" / "field2_atlas.json"
    summary_path = derived_root / "atlas" / "summary.json"
    summary_md_path = derived_root / "atlas" / "summary.md"
    receipt_path = derived_root / "consumption_receipt.json"

    runtime_doc = load_json(runtime_path)
    prov = runtime_doc.get("provenance") or {}
    assert prov.get("run_id") == ctx.run_id
    assert prov.get("artifact_index_sha256") == ctx.artifact_index_sha256
    assert prov.get("packet") == path_utils.to_repo_relative(ctx.packet_path, repo_root=ROOT)
    assert prov.get("consumption_receipt") == path_utils.to_repo_relative(receipt_path, repo_root=ROOT)

    receipt = load_json(receipt_path)
    outputs = receipt.get("outputs") or {}
    assert outputs.get("runtime_results") == path_utils.to_repo_relative(runtime_path, repo_root=ROOT)
    assert outputs.get("atlas") == path_utils.to_repo_relative(atlas_path, repo_root=ROOT)
    assert outputs.get("summary") == path_utils.to_repo_relative(summary_path, repo_root=ROOT)
    assert outputs.get("summary_md") == path_utils.to_repo_relative(summary_md_path, repo_root=ROOT)

    atlas_doc = load_json(atlas_path)
    atlas_entries = atlas_doc.get("atlas") or []
    atlas_ids = {entry["field2"] for entry in atlas_entries}
    assert seed_ids == atlas_ids, f"atlas missing seeds: {sorted(seed_ids - atlas_ids)}"
    allowed_statuses = {
        "runtime_backed",
        "runtime_backed_historical",
        "runtime_attempted_blocked",
        "static_only",
        "no_runtime_candidate",
        "missing_probe",
        "missing_actual",
    }
    assert all(entry.get("status") in allowed_statuses for entry in atlas_entries), "unexpected atlas status present"

    runtime_results = runtime_doc.get("results") or []
    runtime_attempted = [
        entry
        for entry in runtime_results
        if entry.get("status") in {"runtime_backed", "runtime_backed_historical", "runtime_attempted_blocked"}
    ]
    assert runtime_attempted, "expected at least one runtime-attempted seed"

    for fid in (0, 5, 7):
        entry = next((e for e in runtime_results if e.get("field2") == fid), None)
        assert entry, f"missing runtime record for baseline seed {fid}"
        assert entry.get("status") in {"runtime_backed", "runtime_backed_historical", "runtime_attempted_blocked"}, (
            f"baseline seed {fid} missing runtime attempt"
        )

    summary = load_json(summary_path)
    summary_block = summary.get("summary") or {}
    total_from_status = sum(summary_block.get("by_status", {}).values())
    assert total_from_status == summary_block.get("total"), "summary total does not match by_status counts"
    assert total_from_status == len(atlas_entries), "summary total does not match atlas entries"

    header = summary_md_path.read_text(encoding="utf-8").splitlines()[0]
    assert ctx.run_id in header
    assert ctx.artifact_index_sha256 in header
