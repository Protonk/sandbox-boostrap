import json
from pathlib import Path

from book.api import path_utils
from book.api.ghidra import registry


def test_registry_tasks_have_groups_and_scripts():
    repo_root = path_utils.find_repo_root()
    tasks = registry.all_tasks()
    assert tasks

    for name, task in tasks.items():
        assert task.group, f"task {name} missing group"
        script_path = repo_root / "book" / "api" / "ghidra" / "scripts" / task.script
        assert script_path.exists(), f"missing script for task {name}: {script_path}"


def _load_manifest(repo_root: Path, rel_path: str) -> dict:
    manifest_path = repo_root / rel_path
    return json.loads(manifest_path.read_text())


def test_manifest_tasks_are_registered():
    repo_root = path_utils.find_repo_root()
    tasks = registry.all_tasks()

    for rel in (
        "book/integration/tests/ghidra/fixtures/shape_catalog/manifest.json",
        "book/integration/tests/ghidra/fixtures/shape_catalog/manifest.strict.json",
    ):
        manifest = _load_manifest(repo_root, rel)
        for entry in manifest.get("entries", []):
            task = entry.get("task")
            assert task, f"{rel} entry missing task"
            assert task in tasks, f"{rel} task missing from registry: {task}"
