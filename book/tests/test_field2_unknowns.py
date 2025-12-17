import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UNKNOWN_NODES_PATH = ROOT / "book/experiments/field2-filters/out/unknown_nodes.json"
MATRIX_RECORDS_PATH = ROOT / "book/experiments/flow-divert-2560/out/matrix_records.jsonl"

# Stable set of high/unknown field2 payloads on this host baseline.
EXPECTED_UNKNOWN_RAW = {
    165,    # opaque out-of-vocab payload in filter_vocab_id role
    256,    # composite/opaque payload surfaced in sample + probes
    1281,   # composite/opaque payload surfaced in sample + probes
    3584,   # composite/opaque payload surfaced in sample + probes
    12096,  # composite/opaque payload surfaced in network probes
    49171,  # hi-bit / composite payload surfaced in airlock
}

FLOW_DIVERT_TRIPLE_SPECS = {
    "fd_domain_type_proto_all_tcp_order1.sb",
    "fd_domain_type_proto_all_tcp_order2.sb",
    "fd_domain_type_proto_all_udp_order1.sb",
    "fd_domain_type_proto_all_udp_order2.sb",
    "fd_domain_type_proto_any_tcp.sb",
    "fd_domain_type_proto_nested_tcp.sb",
}


def test_expected_unknown_field2_values_present_and_stable():
    raw = json.loads(UNKNOWN_NODES_PATH.read_text())
    observed = set()
    for entries in raw.values():
        for node in entries:
            observed.add(node["raw"])
    # Guard against accidental loss or drift of known unknowns.
    assert EXPECTED_UNKNOWN_RAW.issubset(
        observed
    ), f"missing expected unknowns: {sorted(EXPECTED_UNKNOWN_RAW - observed)}"
    # Prevent silent introduction of new unknowns; adjust EXPECTED_UNKNOWN_RAW deliberately when warranted.
    assert observed.issubset(
        EXPECTED_UNKNOWN_RAW
    ), f"unexpected new unknowns observed: {sorted(observed - EXPECTED_UNKNOWN_RAW)}"


def test_flow_divert_2560_is_triple_only_with_expected_shape():
    seen: dict[str, set[int]] = {}
    with MATRIX_RECORDS_PATH.open() as fh:
        for line in fh:
            rec = json.loads(line)
            spec = rec["spec_id"]
            raw = rec.get("field2_raw")
            seen.setdefault(spec, set()).add(raw)
            if raw == 2560:
                # Structural witness: tag0, filter_vocab_id role, literal contains flow-divert.
                assert rec.get("tag") == 0
                assert rec.get("u16_role") == "filter_vocab_id"
                literal_refs = rec.get("literal_refs") or []
                assert any("flow-divert" in lit for lit in literal_refs)

    specs_with_2560 = {spec for spec, payloads in seen.items() if 2560 in payloads}
    assert specs_with_2560 == FLOW_DIVERT_TRIPLE_SPECS, f"unexpected specs with 2560: {sorted(specs_with_2560)}"

    for spec, payloads in seen.items():
        if spec in FLOW_DIVERT_TRIPLE_SPECS:
            assert 2560 in payloads, f"missing 2560 in triple spec {spec}"
        else:
            assert 2560 not in payloads, f"2560 leaked into non-triple spec {spec}"


def test_flow_divert_2816_is_triple_only():
    seen: dict[str, set[int]] = {}
    with MATRIX_RECORDS_PATH.open() as fh:
        for line in fh:
            rec = json.loads(line)
            spec = rec["spec_id"]
            raw = rec.get("field2_raw")
            seen.setdefault(spec, set()).add(raw)

    specs_with_2816 = {spec for spec, payloads in seen.items() if 2816 in payloads}
    assert specs_with_2816 == FLOW_DIVERT_TRIPLE_SPECS, f"unexpected specs with 2816: {sorted(specs_with_2816)}"

    for spec, payloads in seen.items():
        if spec in FLOW_DIVERT_TRIPLE_SPECS:
            assert 2816 in payloads, f"missing 2816 in triple spec {spec}"
        else:
            assert 2816 not in payloads, f"2816 leaked into non-triple spec {spec}"
