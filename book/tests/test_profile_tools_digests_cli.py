import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_IR = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "experiments" / "system-profile-digest" / "digests_ir.json"


def test_profile_tools_digest_system_profiles_matches_experiment(tmp_path):
    out_path = tmp_path / "digests.json"
    cmd = ["python3", "-m", "book.api.profile", "digest", "system-profiles", "--out", str(out_path)]
    subprocess.run(cmd, check=True, capture_output=True, text=True)

    ir = json.loads(EXPECTED_IR.read_text())
    expected = {k.replace("sys:", ""): v for k, v in (ir.get("profiles") or {}).items()}
    observed = json.loads(out_path.read_text())
    assert observed == expected
