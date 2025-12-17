import json
from pathlib import Path


def _load_json(path: Path):
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_libsandbox_encoder_network_matrix_blob_diffs():
    root = Path(__file__).resolve().parents[2]
    diffs_path = root / "book/experiments/libsandbox-encoder/out/network_matrix/blob_diffs.json"
    diffs = _load_json(diffs_path)

    assert diffs["world_id"] == "sonoma-14.4.1-23E224-arm64-dyld-2c0602c5"
    by_pair = {entry["pair_id"]: entry for entry in diffs["pairs"]}

    cross = diffs["cross_pair"]
    assert cross["single_arg_pairs"] == [
        "domain_af_inet_vs_af_system",
        "type_sock_stream_vs_sock_dgram",
        "proto_tcp_vs_udp",
    ]
    shared = cross["shared_diff_offsets"]
    assert isinstance(shared, list)
    assert len(shared) == 1
    shared_off = shared[0]

    for pair_id in cross["single_arg_pairs"]:
        pair = by_pair[pair_id]
        assert pair["diff_byte_count"] == 1
        assert pair["diff_counts_by_section"] == {"nodes:records": 1}
        diff = pair["diffs"][0]
        assert diff["section"] == "nodes:records"
        assert diff["offset"] == shared_off
        assert diff["record"]["u16_index"] == 1

    # Witnessed macro expansions (from compile blobs on this world baseline).
    assert by_pair["domain_af_inet_vs_af_system"]["diffs"][0]["a_byte"] == 2  # AF_INET
    assert by_pair["domain_af_inet_vs_af_system"]["diffs"][0]["b_byte"] == 32  # AF_SYSTEM
    assert by_pair["type_sock_stream_vs_sock_dgram"]["diffs"][0]["a_byte"] == 1  # SOCK_STREAM
    assert by_pair["type_sock_stream_vs_sock_dgram"]["diffs"][0]["b_byte"] == 2  # SOCK_DGRAM
    assert by_pair["proto_tcp_vs_udp"]["diffs"][0]["a_byte"] == 6  # IPPROTO_TCP
    assert by_pair["proto_tcp_vs_udp"]["diffs"][0]["b_byte"] == 17  # IPPROTO_UDP

