import sys
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))


def test_dyld_libs_manifest_matches_slices(run_cmd):
    checker = ROOT / "book" / "graph" / "mappings" / "dyld-libs" / "check_manifest.py"
    assert checker.exists(), "missing dyld-libs manifest checker"
    res = run_cmd([sys.executable, str(checker)], check=False, label="dyld-libs manifest check")
    if res.returncode != 0:
        msg = (res.stdout or "") + (res.stderr or "")
        raise AssertionError(f"dyld-libs manifest check failed: {msg.strip()}")
