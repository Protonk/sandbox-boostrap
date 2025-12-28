import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def load_json(path: Path):
    assert path.exists(), f"missing expected file: {path}"
    return json.loads(path.read_text())


def test_cfprefsd_anchor_lift_is_backed_by_used_packet_and_matrix():
    from book.graph.mappings.anchors import generate_anchor_filter_map as gen

    amap = load_json(ROOT / "book" / "graph" / "mappings" / "anchors" / "anchor_filter_map.json")
    entry = amap.get("com.apple.cfprefsd.agent") or {}
    assert entry.get("filter_id") == 5
    assert entry.get("filter_name") == "global-name"

    receipt = load_json(ROOT / "book" / "graph" / "mappings" / "runtime" / "promotion_receipt.json")
    considered = ((receipt.get("packets") or {}).get("considered") or []) if isinstance(receipt, dict) else []
    want = "book/experiments/anchor-filter-map/out/promotion_packet.json"
    matched = [rec for rec in considered if isinstance(rec, dict) and rec.get("path") == want]
    assert matched and matched[0].get("status") == "used"

    packet = load_json(ROOT / want)
    assert packet.get("schema_version") == "runtime-tools.promotion_packet.v0.2"
    baseline = load_json(ROOT / packet["baseline_results"])
    runtime = load_json(ROOT / packet["runtime_results"])

    filter_id, reason = gen._evaluate_cfprefsd_runtime_matrix(
        baseline_results=baseline.get("results") or [],
        runtime_results=runtime,
    )
    assert filter_id == 5 and reason is None

    # Execution-shape guardrail: the runtime discriminator must use the in-process
    # self-applying Mach probe (not apply-then-exec).
    s0 = runtime.get("anchor-filter-map:cfprefsd:S0_allow_any") or {}
    probes = s0.get("probes") or []
    assert probes, "expected at least one runtime probe record for S0"
    runner_info = ((probes[0].get("runtime_result") or {}).get("runner_info") or {}) if isinstance(probes[0], dict) else {}
    assert runner_info.get("entrypoint") == "sandbox_mach_probe"
    assert runner_info.get("apply_model") == "self_apply"


def test_cfprefsd_matrix_refuses_when_baseline_service_unobservable():
    from book.graph.mappings.anchors import generate_anchor_filter_map as gen

    baseline_results = [
        {"operation": "mach-lookup", "target": gen.CFPREFSD_SERVICE, "stdout": "{\"kr\":1102}\n"},
        {"operation": "mach-lookup", "target": gen.CFPREFSD_BOGUS_SERVICE, "stdout": "{\"kr\":1102}\n"},
    ]
    filter_id, reason = gen._evaluate_cfprefsd_runtime_matrix(baseline_results=baseline_results, runtime_results={})
    assert filter_id is None
    assert reason == gen.REASON_BASELINE_SERVICE_UNOBSERVABLE


def test_cfprefsd_matrix_refuses_when_predicate_not_discriminating():
    from book.graph.mappings.anchors import generate_anchor_filter_map as gen

    baseline_results = [
        {"operation": "mach-lookup", "target": gen.CFPREFSD_SERVICE, "stdout": "{\"kr\":0}\n"},
        {"operation": "mach-lookup", "target": gen.CFPREFSD_BOGUS_SERVICE, "stdout": "{\"kr\":1102}\n"},
    ]
    probes = [
        {"expectation_id": "anchor-filter-map:cfprefsd:S0_allow_any", "stdout": "{\"kr\":0}\n"},
        {"expectation_id": "anchor-filter-map:cfprefsd:S1_allow_global", "stdout": "{\"kr\":0}\n"},
        {"expectation_id": "anchor-filter-map:cfprefsd:S2_allow_local", "stdout": "{\"kr\":0}\n"},
        {"expectation_id": "anchor-filter-map:cfprefsd:S3_allow_both", "stdout": "{\"kr\":0}\n"},
        {"expectation_id": "anchor-filter-map:cfprefsd:N1_deny_default", "stdout": "{\"kr\":1100}\n"},
        {"expectation_id": "anchor-filter-map:cfprefsd:C1_deny_global", "stdout": "{\"kr\":1100}\n"},
        {"expectation_id": "anchor-filter-map:cfprefsd:C2_deny_local", "stdout": "{\"kr\":0}\n"},
    ]
    runtime_results = {"dummy": {"probes": probes}}
    filter_id, reason = gen._evaluate_cfprefsd_runtime_matrix(baseline_results=baseline_results, runtime_results=runtime_results)
    assert filter_id is None
    assert reason == gen.REASON_PREDICATE_NOT_DISCRIMINATING


def test_cfprefsd_upgrade_requires_used_packet():
    from book.graph.mappings.anchors import generate_anchor_filter_map as gen

    original = gen._receipt_packet_used
    try:
        gen._receipt_packet_used = lambda: (False, gen.REASON_PACKET_NOT_USED)  # type: ignore[assignment]
        upgraded, reason = gen._upgrade_cfprefsd_from_runtime({})
        assert upgraded == {}
        assert reason == gen.REASON_PACKET_NOT_USED
    finally:
        gen._receipt_packet_used = original  # type: ignore[assignment]

