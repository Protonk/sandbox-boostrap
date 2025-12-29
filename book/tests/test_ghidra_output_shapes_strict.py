import os
import unittest
from pathlib import Path

from book.api import path_utils
from book.api.ghidra import shape_snapshot


@unittest.skipUnless(os.environ.get("GHIDRA_STRICT_SHAPES"), "strict ghidra shapes not enabled")
class GhidraOutputShapeStrictTests(unittest.TestCase):
    def test_ghidra_output_shapes_strict(self):
        repo_root = path_utils.find_repo_root()
        manifest_path = repo_root / "book" / "tests" / "fixtures" / "ghidra_shapes" / "manifest.strict.json"
        if not manifest_path.exists():
            self.fail("missing strict manifest: %s" % manifest_path)
        manifest = shape_snapshot.load_manifest(manifest_path)

        failures = []
        checked = 0
        for entry in manifest.get("entries", []):
            ok, msg = shape_snapshot.validate_entry(entry, repo_root)
            checked += 1
            if not ok:
                failures.append(msg or "shape mismatch for %s" % entry.get("name"))

        if failures:
            self.fail("\n".join(failures))
        if checked == 0:
            self.fail("no ghidra strict shape entries were checked")


if __name__ == "__main__":
    unittest.main()
