import json
from pathlib import Path

from book.api.runtime.contracts import models
from book.api.runtime.execution import workflow
from book.api.runtime.analysis.mapping import story as runtime_story


def _write_fixture(matrix_path: Path, results_path: Path) -> None:
    world = models.WORLD_ID
    expected_matrix = {
        "world_id": world,
        "profiles": {
            "test:allow": {
                "blob": "book/experiments/runtime-checks/strict_1.sb",
                "mode": "sbpl",
                "probes": [
                    {
                        "name": "read_ok",
                        "operation": "file-read*",
                        "target": "/tmp/foo",
                        "expected": "allow",
                        "expectation_id": "test:allow:read_ok",
                    }
                ],
            }
        },
    }
    runtime_results = {
        "test:allow": {
            "probes": [
                {
                    "name": "read_ok",
                    "operation": "file-read*",
                    "path": "/tmp/foo",
                    "expected": "allow",
                    "actual": "allow",
                    "match": True,
                    "expectation_id": "test:allow:read_ok",
                    "runtime_result": {"status": "success", "errno": 0},
                }
            ]
        }
    }
    matrix_path.write_text(__import__("json").dumps(expected_matrix))
    results_path.write_text(__import__("json").dumps(runtime_results))


def test_generate_runtime_cut_and_indexes(tmp_path: Path) -> None:
    matrix_path = tmp_path / "expected_matrix.json"
    results_path = tmp_path / "runtime_results.json"
    _write_fixture(matrix_path, results_path)

    staging_root = tmp_path / "runtime_mappings"
    artifacts = workflow.build_cut(matrix_path, results_path, staging_root)

    events_index = (artifacts.events_index).read_text()
    scenarios_doc = __import__("json").loads((artifacts.scenarios).read_text())
    ops_doc = __import__("json").loads((artifacts.ops).read_text())

    # events index ↔ scenario IDs consistency
    scenario_ids = set(scenarios_doc.get("scenarios", {}).keys())
    assert scenario_ids, "expected at least one scenario"
    index_data = __import__("json").loads((artifacts.events_index).read_text())
    assert scenario_ids == set(index_data.get("traces", {}).keys())

    # every scenario references an op that appears in op mapping
    op_names = set(ops_doc.get("ops", {}).keys())
    scenario_ops = {
        expect.get("operation")
        for scenario in scenarios_doc.get("scenarios", {}).values()
        for expect in scenario.get("expectations", [])
        if expect.get("operation")
    }
    assert scenario_ops.issubset(op_names)

    # metadata envelope invariants
    for doc in [index_data, scenarios_doc, ops_doc]:
        meta = doc.get("meta") or {}
        assert meta.get("world_id") == models.WORLD_ID
        assert meta.get("schema_version")
        assert meta.get("runtime_log_schema")


def test_promote_runtime_cut(tmp_path: Path) -> None:
    matrix_path = tmp_path / "expected_matrix.json"
    results_path = tmp_path / "runtime_results.json"
    _write_fixture(matrix_path, results_path)

    staging_root = tmp_path / "runtime_mappings"
    artifacts = workflow.build_cut(matrix_path, results_path, staging_root)
    promoted = workflow.promote_cut(staging_root, tmp_path / "runtime_cuts")

    # ensure promoted artifacts are readable via loaders
    events = list(workflow.load_observations_from_index(promoted.events_index))
    assert events and events[0].scenario_id
    assert promoted.scenarios.exists()
    assert promoted.ops.exists()


def test_full_cut_lifecycle_and_story(tmp_path: Path) -> None:
    matrix_path = tmp_path / "expected_matrix.json"
    results_path = tmp_path / "runtime_results.json"
    _write_fixture(matrix_path, results_path)

    staging_root = tmp_path / "runtime_mappings"
    artifacts = workflow.build_cut(matrix_path, results_path, staging_root)
    promoted = workflow.promote_cut(staging_root, tmp_path / "runtime_cuts")

    story = runtime_story.build_story(promoted.ops, promoted.scenarios)
    coverage_view = runtime_story.story_to_coverage(story)
    signatures_view = runtime_story.story_to_signatures(story)

    # index consistency
    idx_doc = json.loads(promoted.indexes.read_text())
    scenarios_doc = json.loads(promoted.scenarios.read_text())
    assert set(idx_doc.get("scenario_to_traces", {}).keys()) == set((scenarios_doc.get("scenarios") or {}).keys())

    # metadata invariants
    assert (story.get("meta") or {}).get("world_id") == models.WORLD_ID
    for meta in [coverage_view.get("metadata"), signatures_view.get("metadata")]:
        assert meta.get("world_id") == models.WORLD_ID

    # events stream aligns with scenario/op mappings
    ops_doc = json.loads(promoted.ops.read_text())
    op_names = set((ops_doc.get("ops") or {}).keys())
    events = list(workflow.load_observations_from_index(promoted.events_index))
    assert events, "expected promoted events to stream"
    assert any(ev.operation in op_names for ev in events)
    assert all(ev.scenario_id in idx_doc.get("scenario_to_traces", {}) for ev in events)
