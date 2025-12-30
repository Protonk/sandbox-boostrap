from __future__ import annotations

import json
from pathlib import Path


def test_trace_shrink_run_example_schema() -> None:
    sample = Path("book/tools/sbpl/trace_shrink/run_example.json")
    data = json.loads(sample.read_text())
    for key in ("world_id", "knobs", "paths", "trace", "shrink", "timing"):
        assert key in data
    assert "host" not in data
    assert "world_baseline" not in data
    timing = data["timing"]
    assert isinstance(timing.get("duration_s"), (int, float))
    paths = data["paths"]
    for path in (
        paths["run_dir"],
        paths["profiles"]["trace"],
        paths["phases"]["trace"],
        paths["phases"]["shrink"],
    ):
        assert not str(path).startswith("/")


def test_trace_shrink_tool_has_guardrails() -> None:
    source = Path("book/tools/sbpl/trace_shrink/trace_shrink.py").read_text()
    assert "workflow" in source
    assert "trace" in source
    assert "shrink" in source
    assert "lint_profile.py" in source
