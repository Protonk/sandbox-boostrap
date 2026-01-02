from __future__ import annotations

from pathlib import Path

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
PROBE_DIR = ROOT / "book" / "api" / "runtime" / "native" / "probes"


def test_sandbox_mach_probe_is_documented_and_built():
    readme = PROBE_DIR / "README.md"
    build_script = PROBE_DIR / "build.sh"
    assert readme.exists(), "missing probes README"
    assert build_script.exists(), "missing probes build script"

    readme_text = readme.read_text()
    build_text = build_script.read_text()
    assert "sandbox_mach_probe" in readme_text, "sandbox_mach_probe missing from probes README"
    assert "sandbox_mach_probe.c" in build_text, "sandbox_mach_probe missing from probes build script"


def test_sandbox_mach_probe_binary_present():
    source = PROBE_DIR / "sandbox_mach_probe.c"
    binary = PROBE_DIR / "sandbox_mach_probe"
    assert source.exists(), "sandbox_mach_probe source missing"
    assert binary.exists(), "sandbox_mach_probe binary missing"
    assert binary.stat().st_mode & 0o111, "sandbox_mach_probe binary is not executable"
