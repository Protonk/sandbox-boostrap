import json
from pathlib import Path


from book.api import path_utils
def _load_json(path: Path):
    assert path.exists(), f"missing {path}"
    return json.loads(path.read_text())


def test_libsandbox_encoder_network_matrix_blob_diffs():
    root = path_utils.find_repo_root(Path(__file__))
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

    # Proto high-byte witness: TCP (0x0006) ↔ numeric 256 (0x0100) must flip both bytes
    # in the same u16 field slot for the minimal single-filter specimen.
    proto_hi = by_pair["proto_tcp_vs_256"]
    assert proto_hi["diff_byte_count"] == 2
    assert proto_hi["diff_counts_by_section"] == {"nodes:records": 2}
    assert proto_hi["diffs"][0]["offset"] == shared_off
    assert proto_hi["diffs"][1]["offset"] == shared_off + 1
    assert proto_hi["diffs"][0]["record"]["u16_index"] == 1
    assert proto_hi["diffs"][0]["record"]["within_record_offset"] == 4
    assert proto_hi["diffs"][1]["record"]["within_record_offset"] == 5
    assert proto_hi["diffs"][0]["a_byte"] == 6
    assert proto_hi["diffs"][0]["b_byte"] == 0
    assert proto_hi["diffs"][1]["a_byte"] == 0
    assert proto_hi["diffs"][1]["b_byte"] == 1

    # Combined (pairwise) forms: argument deltas land in u16_index=0, with kind byte
    # indicating the argument family (0x0b domain, 0x0c type, 0x0d proto).
    dt_domain = by_pair["pair_dt_all_inet_stream_vs_system_stream"]["diffs"][0]
    assert dt_domain["section"] == "nodes:records"
    assert dt_domain["record"]["tag"] == 0
    assert dt_domain["record"]["kind"] == 11
    assert dt_domain["record"]["u16_index"] == 0
    assert dt_domain["record"]["within_record_offset"] == 2
    assert dt_domain["a_byte"] == 2
    assert dt_domain["b_byte"] == 32

    dt_type = by_pair["pair_dt_all_inet_stream_vs_inet_dgram"]["diffs"][0]
    assert dt_type["section"] == "nodes:records"
    assert dt_type["record"]["tag"] == 0
    assert dt_type["record"]["kind"] == 12
    assert dt_type["record"]["u16_index"] == 0
    assert dt_type["record"]["within_record_offset"] == 2
    assert dt_type["a_byte"] == 1
    assert dt_type["b_byte"] == 2

    dp_proto = by_pair["pair_dp_all_inet_tcp_vs_inet_udp"]["diffs"][0]
    assert dp_proto["section"] == "nodes:records"
    assert dp_proto["record"]["tag"] == 0
    assert dp_proto["record"]["kind"] == 13
    assert dp_proto["record"]["u16_index"] == 0
    assert dp_proto["record"]["within_record_offset"] == 2
    assert dp_proto["a_byte"] == 6
    assert dp_proto["b_byte"] == 17

    # Combined (pairwise) proto high-byte witness: TCP (0x0006) ↔ numeric 256
    # (0x0100) must flip both bytes in the same u16[0] slot for the pairwise form.
    dp_hi = by_pair["pair_dp_all_inet_tcp_vs_inet_256"]
    assert dp_hi["diff_byte_count"] == 2
    assert dp_hi["diff_counts_by_section"] == {"nodes:records": 2}
    assert dp_hi["diffs"][0]["record"]["tag"] == 0
    assert dp_hi["diffs"][0]["record"]["kind"] == 13
    assert dp_hi["diffs"][0]["record"]["u16_index"] == 0
    assert dp_hi["diffs"][0]["record"]["within_record_offset"] == 2
    assert dp_hi["diffs"][1]["record"]["within_record_offset"] == 3
    assert dp_hi["diffs"][0]["a_byte"] == 6
    assert dp_hi["diffs"][0]["b_byte"] == 0
    assert dp_hi["diffs"][1]["a_byte"] == 0
    assert dp_hi["diffs"][1]["b_byte"] == 1

    # Triple (require-all) form: the argument deltas for the witnessed small values
    # land in the record tag byte (within_record_offset==0), not the u16 payload slots.
    tri_domain = by_pair["triple_all_tcp_vs_system_stream_tcp"]["diffs"][0]
    assert tri_domain["section"] == "nodes:records"
    assert tri_domain["record"]["within_record_offset"] == 0
    assert tri_domain["a_byte"] == 2
    assert tri_domain["b_byte"] == 32
    assert tri_domain["record"]["tag"] == tri_domain["a_byte"]

    tri_type = by_pair["triple_all_tcp_vs_inet_dgram_tcp"]["diffs"][0]
    assert tri_type["section"] == "nodes:records"
    assert tri_type["record"]["within_record_offset"] == 0
    assert tri_type["a_byte"] == 1
    assert tri_type["b_byte"] == 2
    assert tri_type["record"]["tag"] == tri_type["a_byte"]

    tri_proto = by_pair["triple_all_tcp_vs_inet_stream_udp"]["diffs"][0]
    assert tri_proto["section"] == "nodes:records"
    assert tri_proto["record"]["within_record_offset"] == 0
    assert tri_proto["a_byte"] == 6
    assert tri_proto["b_byte"] == 17
    assert tri_proto["record"]["tag"] == tri_proto["a_byte"]

    # Triple proto high-byte witness: numeric 256 (0x0100) is encoded in the record
    # header bytes (tag=lo, kind=hi) for the triple form.
    tri_hi = by_pair["triple_all_tcp_vs_inet_stream_256"]
    assert tri_hi["diff_byte_count"] == 2
    assert tri_hi["diff_counts_by_section"] == {"nodes:records": 2}
    assert tri_hi["diffs"][0]["record"]["within_record_offset"] == 0
    assert tri_hi["diffs"][1]["record"]["within_record_offset"] == 1
    assert tri_hi["diffs"][0]["a_byte"] == 6
    assert tri_hi["diffs"][0]["b_byte"] == 0
    assert tri_hi["diffs"][1]["a_byte"] == 0
    assert tri_hi["diffs"][1]["b_byte"] == 1
