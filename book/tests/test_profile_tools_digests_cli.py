import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED = ROOT / "book" / "experiments" / "system-profile-digest" / "out" / "digests.json"


def test_profile_tools_digest_system_profiles_matches_experiment(tmp_path):
    out_path = tmp_path / "digests.json"
    cmd = ["python3", "-m", "book.api.profile_tools", "digest", "system-profiles", "--out", str(out_path)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)

    expected = json.loads(EXPECTED.read_text())
    observed = json.loads(out_path.read_text())
    assert observed == expected

