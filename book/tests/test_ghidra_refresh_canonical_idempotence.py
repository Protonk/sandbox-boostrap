import tempfile
import unittest
from pathlib import Path

from book.api import path_utils
from book.api.ghidra import refresh_canonical


class RefreshCanonicalIdempotenceTests(unittest.TestCase):
    def test_refresh_is_idempotent(self):
        repo_root = path_utils.find_repo_root()
        sentinel = refresh_canonical.SENTINELS.get("offset_inst_scan_0xc0_write_classify")
        if not sentinel:
            self.fail("missing canonical sentinel definition")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            fixture_path = tmp_root / "fixture.json"
            meta_path = tmp_root / "meta.json"

            entry = dict(sentinel)
            entry["fixture_path"] = str(fixture_path)
            entry["meta_path"] = str(meta_path)

            original = refresh_canonical.SENTINELS
            try:
                refresh_canonical.SENTINELS = {"tmp": entry}
                refresh_canonical.main(["--name", "tmp"])
                if not fixture_path.exists() or not meta_path.exists():
                    self.fail("refresh did not emit fixture or metadata")
                first_fixture = fixture_path.read_bytes()
                first_meta = meta_path.read_bytes()
                refresh_canonical.main(["--name", "tmp"])
                second_fixture = fixture_path.read_bytes()
                second_meta = meta_path.read_bytes()
                self.assertEqual(first_fixture, second_fixture)
                self.assertEqual(first_meta, second_meta)
            finally:
                refresh_canonical.SENTINELS = original


if __name__ == "__main__":
    unittest.main()
