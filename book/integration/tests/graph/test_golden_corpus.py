import hashlib
import json
from pathlib import Path


from book.api import path_utils
REPO_ROOT = path_utils.find_repo_root(Path(__file__))
BOOK_ROOT = path_utils.find_repo_root(Path(__file__)) / "book"
MANIFEST_PATH = BOOK_ROOT / "evidence/graph/concepts/validation/golden_corpus/corpus_manifest.json"
SUMMARY_PATH = BOOK_ROOT / "evidence/graph/concepts/validation/golden_corpus/corpus_summary.json"
TAG_LAYOUTS_PATH = BOOK_ROOT / "integration/carton/bundle/relationships/mappings/tag_layouts/tag_layouts.json"
WORLD_ID = "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"


def _load(path: Path):
    return json.loads(path.read_text())


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _blob_path(comp_path: str) -> Path:
    path = Path(comp_path)
    if not path.is_absolute():
        path = REPO_ROOT / comp_path
    return path


def test_golden_corpus_manifest_summary_alignment():
    manifest = _load(MANIFEST_PATH)
    summary = _load(SUMMARY_PATH)

    assert manifest["world_id"] == WORLD_ID
    assert summary["world_id"] == WORLD_ID
    assert manifest["tag_layouts_sha256"] == summary["tag_layouts_sha256"]
    assert manifest["tag_layouts_sha256"] == _sha256(TAG_LAYOUTS_PATH)

    entries = manifest.get("entries", [])
    assert entries, "manifest must contain entries"

    records = summary.get("records", [])
    summary_by_id = {rec["id"]: rec for rec in records}
    assert len(summary_by_id) == len(records), "duplicate ids in summary records"

    for entry in entries:
        rec_id = entry["id"]
        assert rec_id in summary_by_id, f"missing summary for {rec_id}"
        rec = summary_by_id[rec_id]
        assert rec["sha256"] == entry["sha256"]
        assert rec["size_bytes"] == entry["size_bytes"]
        assert rec.get("mode") == entry.get("mode"), f"mode mismatch for {rec_id}"

        comp_path = entry.get("compiled_path") or entry.get("source_path")
        assert comp_path, f"missing compiled path for {rec_id}"
        blob_path = _blob_path(comp_path)
        assert blob_path.exists(), f"blob missing on disk for {rec_id}: {blob_path}"


def test_platform_entries_are_static_only():
    manifest = _load(MANIFEST_PATH)
    entries = manifest.get("entries", [])
    static_only = [e for e in entries if e.get("mode") == "static-only"]
    assert static_only, "expected at least one static-only platform entry"

    for entry in static_only:
        rec_id = entry["id"]
        # Ensure decodes exist for static-only entries.
        decode_path = BOOK_ROOT / f"evidence/graph/concepts/validation/golden_corpus/decodes/{rec_id}.json"
        assert decode_path.exists(), f"decode missing for static-only entry {rec_id}"
        # Ensure we are not silently treating static-only entries as runtime-capable.
        assert entry.get("mode") == "static-only", f"static-only mode not set for {rec_id}"
