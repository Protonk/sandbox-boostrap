import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))


def test_sbpl_graph_runtime_ingested_has_profiles():
    out = (
        ROOT
        / "book"
        / "evidence"
        / "experiments"
        / "runtime-final-final"
        / "suites"
        / "sbpl-graph-runtime"
        / "out"
        / "ingested.json"
    )
    assert out.exists(), "missing ingested.json"
    records = {rec["profile"]: rec for rec in json.loads(out.read_text())}
    for name in ["allow_all.sb.bin", "deny_all.sb.bin", "deny_except_tmp.sb.bin", "metafilter_any.sb.bin"]:
        assert name in records, f"missing ingested entry for {name}"
        blob_path = ROOT / records[name]["source"]
        assert blob_path.exists(), f"missing compiled blob for {name}"
        assert records[name]["format_variant"], "expected format_variant"
        assert records[name]["section_lengths"]["op_table"] >= 0
