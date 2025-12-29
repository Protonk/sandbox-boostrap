import unittest

from book.api import path_utils
from book.api.ghidra import shape_snapshot


class GhidraOutputShapeStrictGateTests(unittest.TestCase):
    def test_ghidra_strict_shapes_are_required(self):
        repo_root = path_utils.find_repo_root()
        manifest_path = repo_root / "book" / "tests" / "fixtures" / "ghidra_shapes" / "manifest.strict.json"
        full_manifest_path = repo_root / "book" / "tests" / "fixtures" / "ghidra_shapes" / "manifest.json"
        if not manifest_path.exists():
            self.fail(f"missing strict manifest: {manifest_path}")
        if not full_manifest_path.exists():
            self.fail(f"missing manifest: {full_manifest_path}")

        manifest = shape_snapshot.load_manifest(manifest_path)
        full_manifest = shape_snapshot.load_manifest(full_manifest_path)
        full_outputs = {entry.get("output_path") for entry in full_manifest.get("entries", [])}
        failures = []
        checked = 0
        for entry in manifest.get("entries", []):
            checked += 1
            if entry.get("required") is not True:
                failures.append(
                    f"strict entry not required: {entry.get('name')} (strict entries must be present and required)"
                )
                continue
            if entry.get("output_path") not in full_outputs:
                failures.append(
                    f"strict entry missing from manifest.json: {entry.get('name')} (strict entries must be present and required)"
                )
                continue
            output_path = path_utils.ensure_absolute(entry.get("output_path"), repo_root)
            if not output_path.exists():
                failures.append(
                    f"strict entry missing output: {entry.get('name')} expected {entry.get('output_path')} (strict entries must be present and required)"
                )
                continue
            snapshot_path = path_utils.ensure_absolute(entry.get("snapshot_path"), repo_root)
            if not snapshot_path.exists() or snapshot_path.stat().st_size == 0:
                failures.append(
                    f"strict snapshot missing or empty: {entry.get('name')} expected {entry.get('snapshot_path')} (strict entries must be present and required)"
                )
                continue
            ok, msg = shape_snapshot.validate_entry(entry, repo_root)
            if not ok:
                failures.append(msg or f"shape mismatch for {entry.get('name')}")

        if failures:
            self.fail("\n".join(failures))
        if checked == 0:
            self.fail("no ghidra strict shape entries were checked")


if __name__ == "__main__":
    unittest.main()
