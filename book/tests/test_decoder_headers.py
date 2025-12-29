import json
import subprocess
from pathlib import Path

from book.api.profile import decoder


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "book" / "experiments" / "sbpl-graph-runtime" / "out" / "allow_all.sb.bin"


def test_decode_profile_header_fields_shape():
    data = FIXTURE.read_bytes()
    prof = decoder.decode_profile(data, header_window=64)

    # Basic presence and types
    assert isinstance(prof.preamble_words_full, list)
    assert len(prof.preamble_words_full) >= len(prof.preamble_words)
    assert isinstance(prof.header_bytes, (bytes, bytearray))
    assert len(prof.header_bytes) == 64

    hf = prof.header_fields
    for key in ("magic", "op_count_word", "maybe_flags", "unknown_words"):
        assert key in hf
    assert isinstance(hf.get("unknown_words"), list)

    # op_count should align with op_count_word when parsed
    if prof.op_count is not None:
        assert prof.op_count == hf.get("op_count_word")

    # Sections should be present and sum to less than or equal blob length
    sections = prof.sections
    assert all(k in sections for k in ("op_table", "nodes", "literal_pool"))
    total = sections["op_table"] + sections["nodes"] + sections["literal_pool"]
    assert total <= len(data)


def test_decode_profile_dict_serialization_keys():
    data = FIXTURE.read_bytes()
    d = decoder.decode_profile_dict(data)
    for key in ("preamble_words_full", "header_bytes", "header_fields"):
        assert key in d


def test_decoder_cli_dump_and_summary(tmp_path):
    # Full dump
    cmd = ["python3", "-m", "book.api.profile", "decode", "dump", str(FIXTURE), "--bytes", "32"]
    res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    items = json.loads(res.stdout)
    assert isinstance(items, list) and items
    entry = items[0]
    assert "path" in entry and "op_count" in entry and "preamble_words_full" in entry

    # Summary mode
    cmd_summary = ["python3", "-m", "book.api.profile", "decode", "dump", str(FIXTURE), "--summary"]
    res_sum = subprocess.run(cmd_summary, capture_output=True, text=True, check=True)
    items_sum = json.loads(res_sum.stdout)
    assert "maybe_flags" in items_sum[0]
