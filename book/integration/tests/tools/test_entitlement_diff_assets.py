import plistlib
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


def test_entitlement_dumps_present():
    server_path = ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "entitlement_sample.entitlements.plist"
    unsigned_path = ROOT / "book" / "experiments" / "entitlement-diff" / "out" / "entitlement_sample_unsigned.entitlements.plist"
    assert server_path.exists(), "missing server entitlement dump"
    assert unsigned_path.exists(), "missing unsigned entitlement dump"

    server_plist = plistlib.loads(server_path.read_bytes())
    unsigned_plist = plistlib.loads(unsigned_path.read_bytes())

    assert server_plist.get("com.apple.security.network.server") is True
    assert unsigned_plist == {} or unsigned_plist.get("com.apple.security.network.server") is None
