import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_normalized_runtime_event_files_marker_free_and_world_stamped():
    world_id = load_json(BASELINE).get("world_id")
    assert world_id, "baseline world_id missing"

    event_files = [
        ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "runtime_events.normalized.json",
        ROOT / "book" / "experiments" / "metadata-runner" / "out" / "runtime_events.normalized.json",
        ROOT / "book" / "experiments" / "vfs-canonicalization" / "out" / "runtime_events.normalized.json",
    ]

    for path in event_files:
        rows = load_json(path)
        assert isinstance(rows, list) and rows, f"{path} should be a non-empty list"
        for row in rows:
            assert row.get("world_id") == world_id, f"{path} world mismatch"
            stderr = row.get("stderr") or ""
            assert '"tool":"sbpl-apply"' not in stderr, f"{path} stderr contains sbpl-apply markers"
            assert '"tool":"seatbelt-callout"' not in stderr, f"{path} stderr contains seatbelt-callout markers"
            assert '"tool":"sbpl-compile"' not in stderr, f"{path} stderr contains sbpl-compile markers"
            if row.get("runtime_status") != "success":
                stage = row.get("failure_stage")
                kind = row.get("failure_kind")
                assert stage in {"apply", "bootstrap", "preflight", "probe"}, f"{path} missing/invalid failure_stage"
                assert isinstance(kind, str) and kind, f"{path} missing failure_kind"
                if stage == "apply":
                    report = row.get("apply_report") or {}
                    assert report.get("api") in {"sandbox_init", "sandbox_apply"}, f"{path} apply failure missing api"
