from pathlib import Path

from book.api.ghidra import refresh_canonical


def test_refresh_is_idempotent(tmp_path: Path):
    sentinel = refresh_canonical.SENTINELS.get("offset_inst_scan_0xc0_write_classify")
    if not sentinel:
        raise AssertionError("missing canonical sentinel definition")

    fixture_path = tmp_path / "fixture.json"
    meta_path = tmp_path / "meta.json"

    entry = dict(sentinel)
    entry["fixture_path"] = str(fixture_path)
    entry["meta_path"] = str(meta_path)

    original = refresh_canonical.SENTINELS
    try:
        refresh_canonical.SENTINELS = {"tmp": entry}
        refresh_canonical.main(["--name", "tmp"])
        if not fixture_path.exists() or not meta_path.exists():
            raise AssertionError("refresh did not emit fixture or metadata")
        first_fixture = fixture_path.read_bytes()
        first_meta = meta_path.read_bytes()
        refresh_canonical.main(["--name", "tmp"])
        second_fixture = fixture_path.read_bytes()
        second_meta = meta_path.read_bytes()
        assert first_fixture == second_fixture
        assert first_meta == second_meta
    finally:
        refresh_canonical.SENTINELS = original
