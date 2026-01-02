import json
from pathlib import Path


from book.api import path_utils

ROOT = path_utils.find_repo_root(Path(__file__))

CFPREFSD_SERVICE = "com.apple.cfprefsd.agent"
BOGUS_SERVICE = "com.apple.sandbox-lore.anchor-filter-map.bogus"


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def parse_kr(stdout: str) -> int | None:
    try:
        obj = json.loads(stdout.strip())
    except Exception:
        return None
    kr = obj.get("kr") if isinstance(obj, dict) else None
    return int(kr) if isinstance(kr, int) else None


def scenario_probe(runtime_results: dict, scenario_id: str) -> dict:
    rec = runtime_results.get(scenario_id) or {}
    probes = rec.get("probes") or []
    assert isinstance(probes, list) and probes, f"missing probes for scenario {scenario_id}"
    for probe in probes:
        if isinstance(probe, dict) and probe.get("expectation_id") == scenario_id:
            return probe
    assert isinstance(probes[0], dict)
    return probes[0]


def kr_for_baseline_target(baseline_results: list[dict], *, target: str) -> int | None:
    for result in baseline_results:
        if not isinstance(result, dict):
            continue
        if result.get("operation") != "mach-lookup" or result.get("target") != target:
            continue
        kr = parse_kr(result.get("stdout") or "")
        if kr is not None:
            return kr
    return None


def test_cfprefsd_anchor_ctx_is_backed_by_used_packet_and_discriminating_matrix():
    receipt = load_json(ROOT / "book" / "evidence" / "graph" / "mappings" / "runtime" / "promotion_receipt.json")
    considered = ((receipt.get("packets") or {}).get("considered") or []) if isinstance(receipt, dict) else []
    want = "book/evidence/experiments/runtime-final-final/evidence/packets/anchor-filter-map.promotion_packet.json"
    matched = [rec for rec in considered if isinstance(rec, dict) and rec.get("path") == want]
    assert matched and matched[0].get("status") == "used"

    packet = load_json(ROOT / want)
    assert packet.get("schema_version") == "runtime-tools.promotion_packet.v0.2"
    baseline = load_json(ROOT / packet["baseline_results"])
    runtime = load_json(ROOT / packet["runtime_results"])

    baseline_results = baseline.get("results") or []
    assert isinstance(baseline_results, list)
    assert kr_for_baseline_target(baseline_results, target=CFPREFSD_SERVICE) == 0
    assert kr_for_baseline_target(baseline_results, target=BOGUS_SERVICE) == 1102

    s0 = scenario_probe(runtime, "anchor-filter-map:cfprefsd:S0_allow_any")
    runner_info = ((s0.get("runtime_result") or {}).get("runner_info") or {}) if isinstance(s0, dict) else {}
    assert runner_info.get("entrypoint") == "sandbox_mach_probe"
    assert runner_info.get("apply_model") == "self_apply"

    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:S0_allow_any").get("stdout") or "") == 0
    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:S1_allow_global").get("stdout") or "") == 0
    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:S2_allow_local").get("stdout") or "") == 1100
    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:S3_allow_both").get("stdout") or "") == 0
    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:N1_deny_default").get("stdout") or "") == 1100
    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:C1_deny_global").get("stdout") or "") == 1100
    assert parse_kr(scenario_probe(runtime, "anchor-filter-map:cfprefsd:C2_deny_local").get("stdout") or "") == 0

    ctx_map = load_json(ROOT / "book" / "evidence" / "graph" / "mappings" / "anchors" / "anchor_ctx_filter_map.json")
    entries = ctx_map.get("entries") or {}
    assert isinstance(entries, dict)
    global_ctx_ids = [
        cid
        for cid, ent in entries.items()
        if isinstance(ent, dict)
        and ent.get("literal") == CFPREFSD_SERVICE
        and ent.get("filter_id") == 5
        and ent.get("filter_name") == "global-name"
    ]
    assert global_ctx_ids, "expected at least one ctx entry for com.apple.cfprefsd.agent@global-name"

    legacy = load_json(ROOT / "book" / "evidence" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json")
    legacy_ent = legacy.get(CFPREFSD_SERVICE) or {}
    assert isinstance(legacy_ent, dict)
    assert legacy_ent.get("status") == "blocked"
    assert set(global_ctx_ids) <= set(legacy_ent.get("ctx_ids") or [])
