import subprocess
from pathlib import Path

import pytest

from book.api import profile as pt
from book.api.profile import ingestion as pi

ROOT = Path(__file__).resolve().parents[2]
SAMPLE_SB = ROOT / "book" / "examples" / "sb" / "sample.sb"


@pytest.mark.system
def test_compile_sbpl_file_writes_blob(tmp_path):
    """Compile sample SBPL and ensure metadata matches the written blob."""
    out = tmp_path / "sample.sb.bin"
    res = pt.compile_sbpl_file(SAMPLE_SB, out)
    assert out.exists()
    blob = out.read_bytes()
    assert blob == res.blob
    assert res.length == len(blob)
    # profile_type is expected to be 0 on this host; tolerate nonzero but stable output
    assert res.profile_type in (0, 1)
    assert pt.hex_preview(blob).strip() != ""


@pytest.mark.system
def test_cli_compiles_to_specified_path(tmp_path):
    """CLI should accept explicit output paths."""
    out = tmp_path / "cli_sample.sb.bin"
    cmd = [
        "python3",
        "-m",
        "book.api.profile.cli",
        "compile",
        str(SAMPLE_SB),
        "--out",
        str(out),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    assert res.returncode == 0, res.stderr
    assert out.exists()
    blob = out.read_bytes()
    assert len(blob) > 0


@pytest.mark.system
def test_compile_string_matches_compile_file_header():
    """
    SBPL compilation has two entry points:
    - SBPL text via `sandbox_compile_string`
    - SBPL file via `sandbox_compile_file`

    For a simple SBPL specimen without imports/params, both should produce
    structurally identical headers (format/op_count/node_count).
    """
    text = SAMPLE_SB.read_text()
    res_string = pt.compile_sbpl_string(text)
    res_file = pt.compile_sbpl_file(SAMPLE_SB)

    header_string = pi.parse_header(pi.ProfileBlob(bytes=res_string.blob, source="test:string"))
    header_file = pi.parse_header(pi.ProfileBlob(bytes=res_file.blob, source="test:file"))

    assert header_string.format_variant == header_file.format_variant
    assert header_string.operation_count == header_file.operation_count
    assert header_string.node_count == header_file.node_count
