import sys
from pathlib import Path

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))


def test_carton_check_smoke(run_cmd):
    res = run_cmd(
        [sys.executable, "-m", "book.integration.carton.tools.check"],
        cwd=ROOT,
        check=True,
        label="carton check",
    )
    assert "CARTON check OK" in (res.stdout or "")
