import json
from pathlib import Path


from book.api import path_utils
ROOT = path_utils.find_repo_root(Path(__file__))


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def load_jsonl(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    records = []
    for line in path.read_text().splitlines():
        if line.strip():
            records.append(json.loads(line))
    return records


def test_field2_atlas_covers_seed_set_and_runtime():
    seeds_doc = load_json(ROOT / "book" / "experiments" / "field2-atlas" / "field2_seeds.json")
    seeds = seeds_doc.get("seeds") or []
    seed_ids = {entry["field2"] for entry in seeds}

    # Seed manifest must be stable and contain the anchor-backed baseline slice.
    assert seeds, "expected a non-empty seed manifest"
    assert {0, 5, 7}.issubset(seed_ids), "baseline field2 seeds should remain present"

    atlas_entries = load_json(ROOT / "book" / "experiments" / "field2-atlas" / "out" / "atlas" / "field2_atlas.json")
    atlas_ids = {entry["field2"] for entry in atlas_entries}

    # The atlas must carry every seed (no dropouts).
    assert seed_ids == atlas_ids, f"atlas missing seeds: {sorted(seed_ids - atlas_ids)}"
    allowed_statuses = {
        "runtime_backed",
        "runtime_backed_historical",
        "runtime_attempted_blocked",
        "static_only",
        "no_runtime_candidate",
        "missing_probe",
        "missing_actual",
    }
    assert all(entry.get("status") in allowed_statuses for entry in atlas_entries), "unexpected atlas status present"

    static_records = load_jsonl(ROOT / "book" / "experiments" / "field2-atlas" / "out" / "static" / "field2_records.jsonl")
    static_by_id = {entry["field2"]: entry for entry in static_records}
    for fid in seed_ids:
        assert fid in static_by_id, f"no static record for seed field2={fid}"
        # Each static record should retain at least one anchor or profile witness.
        has_anchor = bool(static_by_id[fid].get("anchor_hits"))
        has_profile = bool(static_by_id[fid].get("profiles"))
        assert has_anchor or has_profile, f"seed field2={fid} missing static witnesses"

    runtime_doc = load_json(ROOT / "book" / "experiments" / "field2-atlas" / "out" / "runtime" / "field2_runtime_results.json")
    runtime_results = runtime_doc.get("results") or []
    runtime_backed = [entry for entry in runtime_results if entry.get("status") == "runtime_backed"]
    runtime_attempted = [
        entry
        for entry in runtime_results
        if entry.get("status") in {"runtime_backed", "runtime_backed_historical", "runtime_attempted_blocked"}
    ]

    # At least one seed must be attempted at runtime, and none should silently drop unless explicitly marked.
    assert runtime_attempted, "expected at least one runtime-attempted seed"

    # Baseline seeds must stay runtime-backed; later seeds can be static-only/no-runtime.
    for fid in (0, 5, 7):
        entry = next((e for e in runtime_results if e.get("field2") == fid), None)
        assert entry, f"missing runtime record for baseline seed {fid}"
        assert entry.get("status") in {"runtime_backed", "runtime_backed_historical", "runtime_attempted_blocked"}, (
            f"baseline seed {fid} missing runtime attempt"
        )

    candidate_entry = next((entry for entry in runtime_attempted if (entry.get("runtime_candidate") or {}).get("result") is not None), None)
    assert candidate_entry, "expected a runtime candidate with a recorded result"
    candidate = candidate_entry.get("runtime_candidate") or {}
    source_rel = candidate.get("result_source") or candidate.get("source")
    assert source_rel, "runtime candidate missing source reference"
    source_path = ROOT / source_rel
    assert source_path.exists(), f"runtime result source missing: {source_path}"

    profile_id = candidate.get("profile_id")
    probe_name = candidate.get("probe_name")
    actual = candidate.get("result")

    assert profile_id and probe_name, "runtime candidate missing profile/probe identifiers"
    if source_rel.endswith("runtime_signatures.json"):
        runtime_signatures = load_json(source_path)
        recorded_actual = (runtime_signatures.get("signatures") or {}).get(profile_id, {}).get(probe_name)
        assert recorded_actual == actual, (
            f"runtime result for {profile_id}:{probe_name} does not match runtime_signatures "
            f"(result={actual}, runtime_signatures={recorded_actual})"
        )
    else:
        events = load_json(source_path)
        event = next((e for e in events if e.get("profile_id") == profile_id and e.get("probe_name") == probe_name), None)
        assert event, f"missing historical event for {profile_id}:{probe_name}"
        assert event.get("actual") == actual, (
            f"runtime result for {profile_id}:{probe_name} does not match historical events "
            f"(result={actual}, historical={event.get('actual')})"
        )

    # Summary should mirror atlas statuses.
    summary = load_json(ROOT / "book" / "experiments" / "field2-atlas" / "out" / "atlas" / "summary.json")
    total_from_status = sum(summary.get("by_status", {}).values())
    assert total_from_status == summary.get("total"), "summary total does not match by_status counts"
    assert total_from_status == len(atlas_entries), "summary total does not match atlas entries"

    # Canonicalization guardrail for field2=0.
    field2_zero = next((e for e in runtime_results if e.get("field2") == 0), None)
    assert field2_zero, "missing runtime record for field2=0"
    cand = field2_zero.get("runtime_candidate") or {}
    obs = cand.get("path_observation") or {}
    requested = obs.get("requested_path") or ""
    if cand.get("result") == "deny" and isinstance(requested, str) and requested.startswith("/tmp/"):
        normalized = obs.get("normalized_path") or ""
        observed = obs.get("observed_path") or ""
        assert isinstance(normalized, str) and isinstance(observed, str)
        assert normalized.startswith("/private/tmp") or observed.startswith("/private/tmp"), (
            "field2=0 deny should retain /private/tmp canonicalization evidence"
        )
        assert cand.get("path_canonicalization_detected") is True, "missing canonicalization flag for field2=0"
