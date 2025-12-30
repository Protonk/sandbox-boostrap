from book.api import path_utils
from book.api.ghidra import shape_snapshot


def test_ghidra_output_shapes_and_strict_gating():
    repo_root = path_utils.find_repo_root()
    fixtures = repo_root / "book" / "integration" / "tests" / "ghidra" / "fixtures" / "shape_catalog"
    full_manifest_path = fixtures / "manifest.json"
    strict_manifest_path = fixtures / "manifest.strict.json"
    assert full_manifest_path.exists(), f"missing manifest: {full_manifest_path}"
    assert strict_manifest_path.exists(), f"missing strict manifest: {strict_manifest_path}"

    manifest = shape_snapshot.load_manifest(full_manifest_path)
    strict_manifest = shape_snapshot.load_manifest(strict_manifest_path)

    failures: list[str] = []

    checked = 0
    skipped = 0
    for entry in manifest.get("entries", []):
        output_path = path_utils.ensure_absolute(entry["output_path"], repo_root)
        if not output_path.exists():
            if entry.get("required"):
                failures.append(f"missing output {entry.get('name')}")
            else:
                skipped += 1
            continue
        ok, msg = shape_snapshot.validate_entry(entry, repo_root)
        checked += 1
        if not ok:
            failures.append(msg or f"shape mismatch for {entry.get('name')}")

    strict_entries = strict_manifest.get("entries", [])
    if not strict_entries:
        failures.append("no ghidra strict shape entries were checked")

    full_outputs = {entry.get("output_path") for entry in manifest.get("entries", [])}
    for entry in strict_entries:
        name = entry.get("name")
        if entry.get("required") is not True:
            failures.append(f"strict entry not required: {name} (strict entries must be present and required)")
            continue
        if entry.get("output_path") not in full_outputs:
            failures.append(f"strict entry missing from manifest.json: {name} (strict entries must be present and required)")
            continue
        output_path = path_utils.ensure_absolute(entry.get("output_path"), repo_root)
        if not output_path.exists():
            failures.append(
                f"strict entry missing output: {name} expected {entry.get('output_path')} (strict entries must be present and required)"
            )
            continue
        snapshot_path = path_utils.ensure_absolute(entry.get("snapshot_path"), repo_root)
        if not snapshot_path.exists() or snapshot_path.stat().st_size == 0:
            failures.append(
                f"strict snapshot missing or empty: {name} expected {entry.get('snapshot_path')} (strict entries must be present and required)"
            )
            continue
        ok, msg = shape_snapshot.validate_entry(entry, repo_root)
        if not ok:
            failures.append(msg or f"shape mismatch for {name}")

    if failures:
        raise AssertionError("\n".join(failures))

    # Ensure we exercised at least one shape when outputs are present.
    if checked == 0 and skipped == 0:
        raise AssertionError("no ghidra shape entries were checked")
