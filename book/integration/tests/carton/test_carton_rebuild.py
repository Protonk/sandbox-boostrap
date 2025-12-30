import hashlib
import json
import sys
from pathlib import Path

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def test_carton_generators_are_idempotent(tmp_path, monkeypatch, run_cmd):
    targets = [
        ROOT / "book/graph/mappings/carton/operation_coverage.json",
        ROOT / "book/graph/mappings/carton/operation_index.json",
        ROOT / "book/graph/mappings/carton/profile_layer_index.json",
        ROOT / "book/graph/mappings/carton/filter_index.json",
    ]
    before = {path: sha256(path) for path in targets}
    before_story = {
        "op": run_cmd(
            [
                sys.executable,
                "-c",
                "from book.api.carton import carton_query as cq; import json; print(json.dumps(cq.operation_story('file-read*')) )",
            ],
            cwd=ROOT,
            check=True,
            label="carton operation story",
        ).stdout,
        "profile": run_cmd(
            [
                sys.executable,
                "-c",
                "from book.api.carton import carton_query as cq; import json; print(json.dumps(cq.profile_story('sys:bsd')) )",
            ],
            cwd=ROOT,
            check=True,
            label="carton profile story",
        ).stdout,
        "filter": run_cmd(
            [
                sys.executable,
                "-c",
                "from book.api.carton import carton_query as cq; import json; print(json.dumps(cq.filter_story('path')) )",
            ],
            cwd=ROOT,
            check=True,
            label="carton filter story",
        ).stdout,
    }

    cmd = [
        sys.executable,
        "-m",
        "book.graph.mappings.run_promotion",
        "--generators",
        "carton-coverage,carton-indices",
    ]
    run_cmd(cmd, cwd=ROOT, check=True, label="run promotion carton generators")

    after = {path: sha256(path) for path in targets}
    after_story = {
        "op": run_cmd(
            [
                sys.executable,
                "-c",
                "from book.api.carton import carton_query as cq; import json; print(json.dumps(cq.operation_story('file-read*')) )",
            ],
            cwd=ROOT,
            check=True,
            label="carton operation story (after)",
        ).stdout,
        "profile": run_cmd(
            [
                sys.executable,
                "-c",
                "from book.api.carton import carton_query as cq; import json; print(json.dumps(cq.profile_story('sys:bsd')) )",
            ],
            cwd=ROOT,
            check=True,
            label="carton profile story (after)",
        ).stdout,
        "filter": run_cmd(
            [
                sys.executable,
                "-c",
                "from book.api.carton import carton_query as cq; import json; print(json.dumps(cq.filter_story('path')) )",
            ],
            cwd=ROOT,
            check=True,
            label="carton filter story (after)",
        ).stdout,
    }
    assert before == after, json.dumps({"before": before, "after": after}, indent=2)
    assert before_story == after_story, json.dumps({"before_story": before_story, "after_story": after_story}, indent=2)
