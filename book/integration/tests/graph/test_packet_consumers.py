import json
import subprocess
import sys
from pathlib import Path

from book.api import path_utils
from book.api.runtime.analysis import packet_utils

ROOT = path_utils.find_repo_root(Path(__file__))
PACKET_PATH = ROOT / "book" / "experiments" / "runtime-adversarial" / "out" / "promotion_packet.json"
GRAPH_PACKET_EXPORTS = ("runtime_results", "run_manifest")


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def _packet_context(required_exports):
    assert PACKET_PATH.exists(), f"missing promotion packet: {PACKET_PATH}"
    return packet_utils.resolve_packet_context(PACKET_PATH, required_exports=required_exports, repo_root=ROOT)


def test_graph_shape_semantics_packet_consumer(tmp_path):
    ctx = _packet_context(GRAPH_PACKET_EXPORTS)
    script = ROOT / "book" / "experiments" / "graph-shape-vs-semantics" / "summarize_struct_variants.py"
    subprocess.check_call(
        [
            sys.executable,
            str(script),
            "--packet",
            str(PACKET_PATH),
            "--out-root",
            str(tmp_path),
        ]
    )

    derived_root = tmp_path / ctx.run_id
    summary_path = derived_root / "graph_shape_semantics_summary.json"
    receipt_path = derived_root / "consumption_receipt.json"

    summary_doc = load_json(summary_path)
    provenance = summary_doc.get("provenance") or {}
    assert provenance.get("run_id") == ctx.run_id
    assert provenance.get("artifact_index_sha256") == ctx.artifact_index_sha256
    assert provenance.get("packet") == path_utils.to_repo_relative(ctx.packet_path, repo_root=ROOT)
    assert provenance.get("consumption_receipt") == path_utils.to_repo_relative(receipt_path, repo_root=ROOT)

    receipt = load_json(receipt_path)
    outputs = receipt.get("outputs") or {}
    assert outputs.get("summary") == path_utils.to_repo_relative(summary_path, repo_root=ROOT)


def _iter_consumer_files() -> list[Path]:
    roots = [
        ROOT / "book" / "experiments" / "field2-atlas",
        ROOT / "book" / "experiments" / "graph-shape-vs-semantics",
    ]
    files: list[Path] = []
    for root in roots:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if "out" in path.parts:
                continue
            files.append(path)
    return sorted(files)


def _first_match_line(text: str, match) -> int:
    return text.count("\n", 0, match.start()) + 1


def test_packet_consumers_no_legacy_coupling():
    import re

    forbidden = {
        "runtime_adversarial_out": re.compile(r"runtime-adversarial/out"),
        "latest_pointer": re.compile(r"out/LATEST"),
    }
    violations: list[str] = []
    for path in _iter_consumer_files():
        rel = path.relative_to(ROOT)
        text = path.read_text(encoding="utf-8", errors="ignore")
        for kind, pattern in forbidden.items():
            match = pattern.search(text)
            if not match:
                continue
            line = _first_match_line(text, match)
            violations.append(f"{rel}:{line} contains forbidden {kind} reference")
    assert not violations, "legacy coupling references found:\n" + "\n".join(violations)
