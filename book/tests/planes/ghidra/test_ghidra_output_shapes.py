from book.api import path_utils
from book.api.ghidra import shape_snapshot


def test_ghidra_output_shapes():
    repo_root = path_utils.find_repo_root()
    manifest_path = (
        repo_root / "book" / "tests" / "planes" / "ghidra" / "fixtures" / "shape_catalog" / "manifest.json"
    )
    manifest = shape_snapshot.load_manifest(manifest_path)

    failures = []
    checked = 0
    skipped = 0
    for entry in manifest.get("entries", []):
        output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
        if not output_path.exists():
            if entry.get("required"):
                failures.append("missing output %s" % entry.get("name"))
            else:
                skipped += 1
            continue
        ok, msg = shape_snapshot.validate_entry(entry, repo_root)
        checked += 1
        if not ok:
            failures.append(msg or "shape mismatch for %s" % entry.get("name"))

    if failures:
        raise AssertionError("\n".join(failures))
    # Ensure we exercised at least one shape when outputs are present.
    if checked == 0 and skipped == 0:
        raise AssertionError("no ghidra shape entries were checked")
