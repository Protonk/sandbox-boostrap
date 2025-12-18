"""
Decode curated fixtures to ensure the heuristic decoder still works on known blobs.
Emits a small status JSON in validation/out/.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

# Ensure repo root on sys.path for book.* imports.
from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api.profile_tools import decoder
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

FIXTURES_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "fixtures" / "fixtures.json"
OUT_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "fixtures_status.json"
META_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "metadata.json"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


def load_host():
    if META_PATH.exists():
        try:
            return json.loads(META_PATH.read_text()).get("os", {})
        except Exception:
            return {}
    return {}


def run_fixtures_job():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    status = "ok"
    entries = []
    host = load_host()
    if not FIXTURES_PATH.exists():
        status = "blocked"
        payload = {
            "job_id": "graph:fixtures",
            "status": status,
            "host": host,
            "error": f"missing fixtures file: {rel(FIXTURES_PATH)}",
            "entries": [],
            "inputs": [rel(FIXTURES_PATH)],
            "outputs": [rel(OUT_PATH)],
        }
        OUT_PATH.write_text(json.dumps(payload, indent=2))
        return {"status": status, "outputs": [rel(OUT_PATH)], "notes": payload.get("error")}

    try:
        fixtures = json.loads(FIXTURES_PATH.read_text()).get("blobs", [])
    except Exception as exc:  # pragma: no cover
        status = "blocked"
        payload = {
            "job_id": "graph:fixtures",
            "status": status,
            "host": host,
            "error": f"failed to parse fixtures: {exc}",
            "entries": [],
            "inputs": [rel(FIXTURES_PATH)],
            "outputs": [rel(OUT_PATH)],
        }
        OUT_PATH.write_text(json.dumps(payload, indent=2))
        return {"status": status, "outputs": [rel(OUT_PATH)], "notes": payload.get("error")}

    for entry in fixtures:
        path = ROOT / entry["path"]
        rec = {
            "path": rel(path),
            "exists": path.exists(),
            "status": "ok",
            "node_count": None,
            "op_count": None,
            "format_variant": None,
            "error": None,
        }
        if not path.exists():
            rec["status"] = "blocked"
            rec["error"] = "missing blob"
            status = "partial"
        else:
            try:
                decoded = decoder.decode_profile_dict(path.read_bytes())
                rec["node_count"] = decoded.get("node_count")
                rec["op_count"] = decoded.get("op_count")
                rec["format_variant"] = decoded.get("format_variant")
            except Exception as exc:  # pragma: no cover
                rec["status"] = "blocked"
                rec["error"] = f"decode failed: {exc}"
                status = "partial"
        entries.append(rec)

    payload = {
        "job_id": "graph:fixtures",
        "status": status,
        "host": host,
        "inputs": [rel(FIXTURES_PATH)],
        "outputs": [rel(OUT_PATH)],
        "entries": entries,
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2))
    return {"status": status, "outputs": [rel(OUT_PATH)], "metrics": {"entries": len(entries)}, "host": host}


registry.register(
    ValidationJob(
        id="graph:fixtures",
        inputs=[rel(FIXTURES_PATH)],
        outputs=[rel(OUT_PATH)],
        tags=["graph", "fixtures"],
        description="Decode curated fixtures to ensure decoder stays in sync with known blobs.",
        example_command="python -m book.graph.concepts.validation --id graph:fixtures",
        runner=run_fixtures_job,
    )
)
