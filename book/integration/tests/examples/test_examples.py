import sys
from pathlib import Path

import pytest

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))


@pytest.mark.system
def test_compile_sample_sb(tmp_path: Path, run_cmd):
    src = ROOT / "book/examples/sb/sample.sb"
    if not src.exists():
        pytest.skip("missing sample SBPL fixture")
    out = tmp_path / "sample.sb.bin"
    cmd = [sys.executable, "-m", "book.api.profile", "compile", str(src), "--out", str(out), "--no-preview"]
    run_cmd(cmd, check=True, label="compile sample SBPL")
    assert out.exists(), "sample.sb.bin not generated"


@pytest.mark.system
def test_extract_system_profiles(tmp_path: Path, run_cmd):
    profiles_dir = Path("/System/Library/Sandbox/Profiles")
    airlock = profiles_dir / "airlock.sb"
    bsd = profiles_dir / "bsd.sb"
    if not (airlock.exists() and bsd.exists()):
        pytest.skip("missing /System/Library/Sandbox/Profiles/{airlock,bsd}.sb")

    out_dir = tmp_path / "profiles"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable,
        "-m",
        "book.api.profile",
        "compile",
        str(airlock),
        str(bsd),
        "--out-dir",
        str(out_dir),
        "--no-preview",
    ]
    run_cmd(cmd, check=True, label="compile system profiles")
    assert (out_dir / "airlock.sb.bin").exists()
    assert (out_dir / "bsd.sb.bin").exists()
