import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))
DECODE = ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "runtime" / "golden_decodes.json"


def _load():
    assert DECODE.exists(), "missing golden_decodes.json; run decode_golden.py"
    data = json.loads(DECODE.read_text())
    decodes = data.get("decodes") or []
    return {entry["key"]: entry for entry in decodes}


def test_golden_decodes_present():
    decodes = _load()
    expected_keys = {
        "bucket4:v1_read",
        "bucket5:v11_read_subpath",
        "runtime:metafilter_any",
        "runtime:strict_1",
        "sys:bsd",
        "sys:airlock",
    }
    assert expected_keys.issubset(decodes.keys())
    for key in expected_keys:
        entry = decodes[key]
        assert entry.get("node_count") is not None
        assert entry.get("op_count") is not None


def test_metafilter_literals_present():
    decodes = _load()
    meta = decodes["runtime:metafilter_any"]
    literals = meta.get("literal_strings") or []
    joined = " ".join(literals)
    assert "foo" in joined
    assert "bar" in joined
    assert "baz" in joined


def test_strict_literals_present():
    decodes = _load()
    strict = decodes["runtime:strict_1"]
    literals = strict.get("literal_strings") or []
    joined = " ".join(literals)
    assert "strict_ok" in joined
    assert "/etc/hosts" in joined


def test_bsd_airlock_decode():
    decodes = _load()
    for key in ["sys:bsd", "sys:airlock"]:
        entry = decodes[key]
        assert entry.get("node_count", 0) > 0
