import importlib.util
from pathlib import Path
import sys

from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))
sys.path.insert(0, str(ROOT))


def load_anchor_scan():
    path = ROOT / "book" / "experiments" / "probe-op-structure" / "anchor_scan.py"
    spec = importlib.util.spec_from_file_location("anchor_scan", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)  # type: ignore
    return mod


def test_anchor_offsets_present():
    profile = ROOT / "book" / "experiments" / "probe-op-structure" / "sb" / "build" / "v1_file_require_any.sb.bin"
    if not profile.exists():
        return
    anchor_scan = load_anchor_scan()
    filter_names = anchor_scan.load_filter_names()
    summary = anchor_scan.summarize(profile, ["/tmp/foo"], filter_names)
    hits = summary["anchors"][0]
    assert hits["offsets"], "expected anchor offsets to be located in literal pool"
    assert hits["node_indices"], "expected at least one node to reference the anchor"
