import json
from pathlib import Path


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json
ROOT = path_utils.find_repo_root(Path(__file__))
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world.json"


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_normalized_runtime_event_files_marker_free_and_world_stamped():
    world_id = load_json(BASELINE).get("world_id")
    assert world_id, "baseline world_id missing"

    event_sources = [
        (
            "runtime-adversarial",
            load_bundle_json(ROOT / "book" / "experiments" / "runtime-adversarial" / "out", "runtime_events.normalized.json"),
        ),
        (
            "metadata-runner",
            load_json(ROOT / "book" / "experiments" / "metadata-runner" / "out" / "runtime_events.normalized.json"),
        ),
        (
            "vfs-canonicalization",
            load_bundle_json(ROOT / "book" / "experiments" / "vfs-canonicalization" / "out", "runtime_events.normalized.json"),
        ),
    ]

    for label, rows in event_sources:
        assert isinstance(rows, list) and rows, f"{label} should be a non-empty list"
        for row in rows:
            assert row.get("world_id") == world_id, f"{label} world mismatch"
            stderr = row.get("stderr") or ""
            assert '"tool":"sbpl-apply"' not in stderr, f"{label} stderr contains sbpl-apply markers"
            assert '"tool":"seatbelt-callout"' not in stderr, f"{label} stderr contains seatbelt-callout markers"
            assert '"tool":"sbpl-compile"' not in stderr, f"{label} stderr contains sbpl-compile markers"
            if row.get("runtime_status") != "success":
                stage = row.get("failure_stage")
                kind = row.get("failure_kind")
                assert stage in {"apply", "bootstrap", "preflight", "probe"}, f"{label} missing/invalid failure_stage"
                assert isinstance(kind, str) and kind, f"{label} missing failure_kind"
                if stage == "apply":
                    report = row.get("apply_report") or {}
                    assert report.get("api") in {"sandbox_init", "sandbox_apply"}, f"{label} apply failure missing api"
