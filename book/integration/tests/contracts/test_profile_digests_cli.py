import json
import sys
from pathlib import Path

from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
EXPECTED_IR = (
    ROOT
    / "book"
    / "evidence"
    / "graph"
    / "concepts"
    / "validation"
    / "out"
    / "experiments"
    / "system-profile-digest"
    / "digests_ir.json"
)


def test_profile_digest_system_profiles_matches_experiment(tmp_path, run_cmd):
    out_path = tmp_path / "digests.json"
    cmd = [sys.executable, "-m", "book.api.profile", "digest", "system-profiles", "--out", str(out_path)]
    run_cmd(cmd, check=True, label="profile digest system-profiles")

    ir = json.loads(EXPECTED_IR.read_text())
    expected = {k.replace("sys:", ""): v for k, v in (ir.get("profiles") or {}).items()}
    observed = json.loads(out_path.read_text())
    assert observed == expected
