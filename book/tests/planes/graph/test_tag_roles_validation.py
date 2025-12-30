import json
from pathlib import Path

from book.graph.concepts.validation.tag_role_layout_job import run_tag_role_layout_job, STATUS_PATH


def test_tag_roles_validation_canonical_corpus():
    result = run_tag_role_layout_job()
    assert result["status"] == "ok"
    metrics = result["metrics"]
    assert metrics["missing_roles_total"] == 0
    assert metrics["missing_layout_total"] == 0
    assert metrics["fallback_nodes_total"] == 0
    # Status file should exist and mirror the run result.
    assert STATUS_PATH.exists()
    status = json.loads(STATUS_PATH.read_text())
    assert status.get("status") == "ok"
