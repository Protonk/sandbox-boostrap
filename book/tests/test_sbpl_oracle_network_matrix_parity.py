import json
from pathlib import Path

from book.api.profile.oracles import WORLD_ID, extract_network_tuple, run_network_matrix


def test_sbpl_oracle_network_matrix_matches_experiment_oracle_values():
    root = Path(__file__).resolve().parents[2]
    golden_path = root / "book/experiments/libsandbox-encoder/out/network_matrix/oracle_tuples.json"
    golden = json.loads(golden_path.read_text())

    assert golden["world_id"] == WORLD_ID

    for entry in golden["entries"]:
        blob_path = root / entry["blob"]
        res = extract_network_tuple(blob_path.read_bytes())
        assert res.conflicts == []
        assert res.domain == entry["domain"]
        assert res.type == entry["type"]
        assert res.proto == entry["proto"]


def test_sbpl_oracle_network_matrix_runner_parity():
    root = Path(__file__).resolve().parents[2]
    manifest = root / "book/experiments/libsandbox-encoder/sb/network_matrix/MANIFEST.json"
    blob_dir = root / "book/experiments/libsandbox-encoder/out/network_matrix"
    out = run_network_matrix(manifest, blob_dir)

    assert out["world_id"] == WORLD_ID
    assert out["oracle_id"] == "sbpl_oracle.network_tuple.v1"
    by_spec = {e["spec_id"]: e for e in out["entries"]}

    golden_path = root / "book/experiments/libsandbox-encoder/out/network_matrix/oracle_tuples.json"
    golden = json.loads(golden_path.read_text())
    for entry in golden["entries"]:
        got = by_spec[entry["spec_id"]]
        assert got["conflicts"] == []
        assert got["domain"] == entry["domain"]
        assert got["type"] == entry["type"]
        assert got["proto"] == entry["proto"]
