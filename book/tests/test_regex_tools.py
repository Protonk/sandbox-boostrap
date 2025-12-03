from pathlib import Path

from book.api.regex_tools import extract_legacy, re_to_dot


def _make_legacy_profile(path: Path, regex_blob: bytes) -> None:
    """
    Build a tiny legacy-format profile that contains a single regex blob.
    Layout matches resnarf/extract_legacy expectations:
    - u16 re_table_offset_words (word=8 bytes)
    - u16 re_count
    - regex table at offset * 8: u16 word-offset to regex blob
    - regex blob header: u32 length followed by blob bytes
    """
    re_table_offset_words = 1
    re_count = 1
    table_offset_bytes = re_table_offset_words * 8
    regex_offset_words = 2  # place regex blob at byte offset 16
    data = bytearray(b"\x00" * (table_offset_bytes + 2))  # table has 1 entry (u16)
    data[0:2] = re_table_offset_words.to_bytes(2, "little")
    data[2:4] = re_count.to_bytes(2, "little")
    data[table_offset_bytes : table_offset_bytes + 2] = regex_offset_words.to_bytes(2, "little")
    regex_offset = regex_offset_words * 8
    # ensure buffer reaches regex payload start
    if len(data) < regex_offset:
        data.extend(b"\x00" * (regex_offset - len(data)))
    data.extend(len(regex_blob).to_bytes(4, "little"))
    data.extend(regex_blob)
    path.write_bytes(data)


def test_extract_legacy_writes_re_files(tmp_path):
    fake_regex = b"ABCD"
    profile_path = tmp_path / "legacy.sb.bin"
    _make_legacy_profile(profile_path, fake_regex)
    out_dir = tmp_path / "out"
    extract_legacy.extract_regexes(profile_path, out_dir)
    outputs = list(out_dir.glob("*.re"))
    assert outputs, "no regex files extracted"
    blob = outputs[0].read_bytes()
    assert blob == fake_regex


def test_re_to_dot_parses_minimal_accept(tmp_path):
    # Minimal AppleMatch NFA: header with one ACCEPT node.
    header = (
        0,  # magic/unused
        1,  # node_count
        0,  # start offset
        0,  # flags
        0,  # cclass_count
        0,  # padding
    )
    header_bytes = b"".join(int(h).to_bytes(4, "big") for h in header)
    node_bytes = (0x22).to_bytes(4, "big") + (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
    blob = header_bytes + node_bytes
    re_path = tmp_path / "accept.re"
    re_path.write_bytes(blob)
    g = re_to_dot.parse_re(blob)
    assert 0 in g.tags
    assert g.tags[0][0] == "ACCEPT"
    dot = re_to_dot.graph_to_dot(g)
    assert "ACCEPT" in dot
    assert "n0" in dot
