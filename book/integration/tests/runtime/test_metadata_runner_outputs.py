from pathlib import Path


from book.api import path_utils
from book.integration.tests.runtime.runtime_bundle_helpers import load_bundle_json
ROOT = path_utils.find_repo_root(Path(__file__))
OUT_ROOT = ROOT / "book" / "experiments" / "runtime-final-final" / "suites" / "metadata-runner" / "out"


def load_results():
    data = load_bundle_json(OUT_ROOT, "runtime_events.normalized.json")
    assert isinstance(data, list) and data, "runtime_events.normalized.json should be a non-empty list"
    return data


def test_metadata_anchor_forms_allowlists():
    """
    Guardrail: metadata-runner anchor variants should keep alias vs canonical behavior stable.

    Expectations (from latest runs on this host):
    - literal/regex/subpath canonical-only profiles allow canonical paths; alias paths denied.
    - literal/regex canonical+alias profiles still only allow canonical paths (alias denied).
    - subpath/regex both-path profiles allow both canonical and alias paths.
    - alias-only profiles allow nothing.
    """
    alias_tmp_paths = {"/tmp/foo", "/tmp/bar", "/tmp/nested/child"}
    alias_var_path = {"/var/tmp/canon"}
    canonical_paths = {
        "/private/tmp/foo",
        "/private/tmp/bar",
        "/private/tmp/nested/child",
        "/private/var/tmp/canon",
    }

    allowed = {
        "literal_alias_only": set(),
        "literal_canonical_only": canonical_paths,
        "literal_both_paths": canonical_paths,
        "subpath_alias_only": set(),
        "subpath_canonical_only": canonical_paths,
        "subpath_both_paths": canonical_paths | alias_tmp_paths,
        "regex_alias_only": set(),
        "regex_canonical_only": canonical_paths,
        "regex_both_paths": canonical_paths | alias_tmp_paths,
    }

    required = {
        "literal_alias_only": set(),
        "literal_canonical_only": canonical_paths,
        "literal_both_paths": canonical_paths,
        "subpath_alias_only": set(),
        "subpath_canonical_only": canonical_paths,
        "subpath_both_paths": canonical_paths | alias_tmp_paths,
        "regex_alias_only": set(),
        "regex_canonical_only": canonical_paths,
        "regex_both_paths": canonical_paths | alias_tmp_paths,
    }

    results = load_results()
    by_profile = {}
    for row in results:
        pid = row.get("profile_id")
        if not pid:
            continue
        if row.get("actual") != "allow":
            continue
        by_profile.setdefault(pid, set()).add(row.get("target"))

    for pid, ok_paths in by_profile.items():
        assert ok_paths.issubset(allowed.get(pid, set())), f"{pid} allowed unexpected paths: {ok_paths - allowed.get(pid, set())}"
        missing = required.get(pid, set()) - ok_paths
        assert not missing, f"{pid} missing ok results for: {missing}"

    # Ensure profiles we care about are present even if they had no ok entries.
    present_profiles = set(by_profile.keys()) | {row["profile_id"] for row in results}
    for pid in allowed.keys():
        assert pid in present_profiles, f"missing runtime rows for profile {pid}"
