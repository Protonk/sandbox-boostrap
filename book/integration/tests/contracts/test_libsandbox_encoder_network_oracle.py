from pathlib import Path

from book.api.profile.oracles import extract_network_tuple

from book.api import path_utils
def _load_blob(root: Path, spec_id: str) -> bytes:
    blob = root / "book/evidence/experiments/field2-final-final/libsandbox-encoder/out/network_matrix" / f"{spec_id}.sb.bin"
    assert blob.exists(), f"missing {blob}"
    return blob.read_bytes()


def test_libsandbox_encoder_network_oracle_extracts_expected_tuples():
    root = path_utils.find_repo_root(Path(__file__))
    cases = {
        # single-arg
        "proto_256": {"domain": None, "type": None, "proto": 256},
        # pairwise combined
        "pair_dp_all_inet_256": {"domain": 2, "type": None, "proto": 256},
        "pair_tp_any_stream_256": {"domain": None, "type": 1, "proto": 256},
        # triple combined
        "triple_all_inet_stream_256": {"domain": 2, "type": 1, "proto": 256},
        "triple_any_256": {"domain": 2, "type": 1, "proto": 256},
        "triple_nested_256": {"domain": 2, "type": 1, "proto": 256},
    }

    for spec_id, expected in cases.items():
        res = extract_network_tuple(_load_blob(root, spec_id))
        assert res.conflicts == []
        assert res.domain == expected["domain"]
        assert res.type == expected["type"]
        assert res.proto == expected["proto"]
