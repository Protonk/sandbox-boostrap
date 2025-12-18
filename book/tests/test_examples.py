import subprocess
import pytest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]

@pytest.mark.system
def test_compile_sample_sb(tmp_path: Path):
    src = ROOT / "book/examples/sb/sample.sb"
    if not src.exists():
        pytest.skip("missing sample SBPL fixture")
    out = tmp_path / "sample.sb.bin"
    cmd = [sys.executable, "-m", "book.api.profile_tools", "compile", str(src), "--out", str(out), "--no-preview"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert out.exists(), "sample.sb.bin not generated"


@pytest.mark.system
def test_extract_system_profiles(tmp_path: Path):
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
        "book.api.profile_tools",
        "compile",
        str(airlock),
        str(bsd),
        "--out-dir",
        str(out_dir),
        "--no-preview",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (out_dir / "airlock.sb.bin").exists()
    assert (out_dir / "bsd.sb.bin").exists()
