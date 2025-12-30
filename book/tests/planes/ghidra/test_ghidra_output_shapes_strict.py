from book.api import path_utils
from book.api.ghidra import shape_snapshot


def test_ghidra_output_shapes_strict():
    repo_root = path_utils.find_repo_root()
    manifest_path = (
        repo_root / "book" / "tests" / "planes" / "ghidra" / "fixtures" / "shape_catalog" / "manifest.strict.json"
    )
    if not manifest_path.exists():
        raise AssertionError(f"missing strict manifest: {manifest_path}")
    manifest = shape_snapshot.load_manifest(manifest_path)

    failures = []
    checked = 0
    for entry in manifest.get("entries", []):
        ok, msg = shape_snapshot.validate_entry(entry, repo_root)
        checked += 1
        if not ok:
            failures.append(msg or "shape mismatch for %s" % entry.get("name"))

    if failures:
        raise AssertionError("\n".join(failures))
    if checked == 0:
        raise AssertionError("no ghidra strict shape entries were checked")
