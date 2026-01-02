import os
from pathlib import Path

from book.api.profile import decoder
from book.api.profile import ingestion as pi

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
FIXTURE = (
    ROOT
    / "book"
    / "evidence"
    / "experiments"
    / "runtime-final-final"
    / "suites"
    / "sbpl-graph-runtime"
    / "out"
    / "allow_all.sb.bin"
)


def test_decoder_slicing_matches_ingestion_offsets():
    data = FIXTURE.read_bytes()
    dec = decoder.decode_profile(data)
    profile = pi.ProfileBlob(bytes=data, source="test")
    header = pi.parse_header(profile)
    if header.format_variant != "legacy-decision-tree":
        header.operation_count = dec.op_count
    _sections, offsets = pi.slice_sections_with_offsets(profile, header)
    assert dec.sections["nodes_start"] == offsets.nodes_start
    assert dec.sections["literal_start"] == offsets.literal_start
    assert dec.sections["nodes"] == offsets.nodes_end - offsets.nodes_start
    assert dec.sections["literal_pool"] == offsets.literal_end - offsets.literal_start


def test_decoder_does_not_depend_on_cwd(tmp_path):
    data = FIXTURE.read_bytes()
    old = os.getcwd()
    os.chdir(tmp_path)
    try:
        decoded = decoder.decode_profile_dict(data)
    finally:
        os.chdir(old)
    assert decoded.get("op_table") is not None
