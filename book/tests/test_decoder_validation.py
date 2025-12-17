import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

import book.api.decoder as decoder  # type: ignore


SAMPLE = ROOT / "book" / "examples" / "sb" / "build" / "sample.sb.bin"


def test_decoder_emits_validation_fields():
    if not SAMPLE.exists():
        return  # skip if sample blob missing in this checkout
    data = SAMPLE.read_bytes()
    dec = decoder.decode_profile_dict(data)
    validation = dec.get("validation") or {}
    assert "node_remainder_bytes" in validation
    assert "edge_fields_in_bounds" in validation
    assert "edge_fields_total" in validation
    assert "nodes_start" in validation
    assert "literal_start" in validation
    assert validation["edge_fields_total"] >= validation["edge_fields_in_bounds"]
    assert validation["node_remainder_bytes"] < 12
    # Tag validation should exist even if empty for this blob
    assert "tag_validation" in validation


def test_decoder_sections_present():
    if not SAMPLE.exists():
        return
    dec = decoder.decode_profile_dict(SAMPLE.read_bytes())
    sections = dec.get("sections") or {}
    required = {"op_table", "nodes", "literal_pool"}
    assert required.issubset(set(sections.keys()))


def test_decoder_literals_and_refs():
    if not SAMPLE.exists():
        return
    dec = decoder.decode_profile_dict(SAMPLE.read_bytes())
    literal_strings = dec.get("literal_strings") or []
    literal_with_offsets = dec.get("literal_strings_with_offsets") or []
    assert len(literal_strings) == len(literal_with_offsets)
    assert all(isinstance(off, int) for off, _ in literal_with_offsets)
    nodes = dec.get("nodes") or []
    if nodes:
        assert "literal_refs" in nodes[0]


def test_decoder_op_table_scaling_witness_present():
    """Guardrail: decoder emits op-table scaling witness data to catch mis-scaling."""
    airlock = ROOT / "book" / "examples" / "extract_sbs" / "build" / "profiles" / "airlock.sb.bin"
    if not airlock.exists():
        return
    dec = decoder.decode_profile_dict(airlock.read_bytes())
    validation = dec.get("validation") or {}
    witness = validation.get("op_table_scaling_witness") or {}
    assert "scale8" in witness and "scale12" in witness
    s8 = witness["scale8"]
    s12 = witness["scale12"]
    for key in ("ascii_pair_count", "in_range", "total"):
        assert key in s8 and key in s12
    # On canonical sys:airlock, scale=12 produces many ASCII-looking starts, while scale=8 does not.
    assert s12["ascii_pair_count"] > 20
    assert s8["ascii_pair_count"] < s12["ascii_pair_count"]


def test_decoder_stride8_mode_covers_op_table_targets():
    """Guardrail: fixed stride=8 mode slices enough nodes to cover op-table roots."""
    airlock = ROOT / "book" / "examples" / "extract_sbs" / "build" / "profiles" / "airlock.sb.bin"
    bsd = ROOT / "book" / "examples" / "extract_sbs" / "build" / "profiles" / "bsd.sb.bin"
    for path in (airlock, bsd):
        if not path.exists():
            continue
        dec = decoder.decode_profile_dict(path.read_bytes(), node_stride_bytes=8)
        op_table = dec.get("op_table") or []
        if not op_table:
            continue
        assert max(op_table) < dec.get("node_count", 0)
