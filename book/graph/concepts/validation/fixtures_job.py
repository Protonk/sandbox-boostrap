"""
Decode curated fixtures to ensure the heuristic decoder still works on known blobs.
Emits a small status JSON in validation/out/.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
import traceback
import time

# Ensure repo root on sys.path for book.* imports.
ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import book.api.decoder as decoder
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

FIXTURES_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "fixtures" / "fixtures.json"
OUT_PATH = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "fixtures_status.json"


def run_fixtures_job():
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    status = "ok"
    entries = []
    if not FIXTURES_PATH.exists():
        status = "blocked"
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": status,
            "error": f"missing fixtures file: {FIXTURES_PATH}",
            "entries": [],
        }
        OUT_PATH.write_text(json.dumps(payload, indent=2))
        return payload

    try:
        fixtures = json.loads(FIXTURES_PATH.read_text()).get("blobs", [])
    except Exception as exc:  # pragma: no cover
        status = "blocked"
        payload = {
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": status,
            "error": f"failed to parse fixtures: {exc}",
            "entries": [],
        }
        OUT_PATH.write_text(json.dumps(payload, indent=2))
        return payload

    for entry in fixtures:
        path = ROOT / entry["path"]
        rec = {
            "path": str(path),
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
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": status,
        "entries": entries,
    }
    OUT_PATH.write_text(json.dumps(payload, indent=2))
    return payload


registry.register(
    ValidationJob(
        id="graph:fixtures",
        inputs=[str(FIXTURES_PATH)],
        outputs=[str(OUT_PATH)],
        tags=["graph", "fixtures"],
        description="Decode curated fixtures to ensure decoder stays in sync with known blobs.",
        runner=run_fixtures_job,
    )
)
