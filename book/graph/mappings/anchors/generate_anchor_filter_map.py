#!/usr/bin/env python3
"""
Refresh `anchor_filter_map.json` against current `anchor_hits.json`.

This generator preserves the curated pinned `filter_id` decisions, but updates
each entry's recorded `field2_values` to cover all observed values across the
entry's declared `sources`.

If a pinned `filter_id` is no longer witnessed in its sources, the entry is
conservatively demoted to `status: blocked` (no pinned filter id).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Set

REPO_ROOT = Path(__file__).resolve().parents[4]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api import world as world_mod  # type: ignore
HITS_PATH = REPO_ROOT / "book/experiments/probe-op-structure/out/anchor_hits.json"
OUT_PATH = REPO_ROOT / "book/graph/mappings/anchors/anchor_filter_map.json"
RUNTIME_RECEIPT_PATH = REPO_ROOT / "book/graph/mappings/runtime/promotion_receipt.json"
CFPREFSD_PACKET_PATH = REPO_ROOT / "book/experiments/anchor-filter-map/out/promotion_packet.json"
CFPREFSD_SERVICE = "com.apple.cfprefsd.agent"
CFPREFSD_BOGUS_SERVICE = "com.apple.sandbox-lore.anchor-filter-map.bogus"
IOKIT_CLASS_PACKET_PATH = REPO_ROOT / "book/experiments/anchor-filter-map/iokit-class/out/promotion_packet.json"
IOKIT_CLASS_ANCHOR = "IOUSBHostInterface"
IOKIT_CLASS_BOGUS = "IOSandboxLoreAnchorFilterBogus"

REASON_MISSING_PROMOTION_RECEIPT = "missing_promotion_receipt"
REASON_PACKET_MISSING_FROM_RECEIPT = "packet_missing_from_receipt"
REASON_PACKET_NOT_USED = "packet_not_used"
REASON_MISSING_PROMOTION_PACKET = "missing_promotion_packet"
REASON_UNSUPPORTED_PACKET_SCHEMA = "unsupported_packet_schema"
REASON_PACKET_MISSING_ARTIFACT_PATHS = "packet_missing_artifact_paths"
REASON_PACKET_ARTIFACTS_MISSING = "packet_artifacts_missing"
REASON_WORLD_ID_MISMATCH = "world_id_mismatch"
REASON_BASELINE_SERVICE_UNOBSERVABLE = "baseline_service_unobservable"
REASON_BASELINE_BOGUS_NOT_UNREGISTERED = "baseline_bogus_not_unregistered"
REASON_MISSING_RUNTIME_KR = "missing_runtime_kr"
REASON_DENY_DEFAULT_REACHABILITY_FAILED = "deny_default_reachability_failed"
REASON_PREDICATE_NOT_DISCRIMINATING = "predicate_not_discriminating"
REASON_STATIC_FIELD2_MISMATCH = "static_field2_mismatch"

_BASELINE_WORLD_ID: str | None = None


def _baseline_world_id() -> str:
    global _BASELINE_WORLD_ID
    if _BASELINE_WORLD_ID is None:
        world_doc, resolution = world_mod.load_world(repo_root=REPO_ROOT)
        _BASELINE_WORLD_ID = world_mod.require_world_id(world_doc, world_path=resolution.entry.world_path)
    return _BASELINE_WORLD_ID


def _parse_kr(stdout: str) -> int | None:
    try:
        doc = json.loads(stdout.strip().splitlines()[-1])
    except Exception:
        return None
    kr = doc.get("kr")
    return kr if isinstance(kr, int) else None


def _parse_iokit_open(stdout: str) -> tuple[bool | None, int | None]:
    try:
        doc = json.loads(stdout.strip().splitlines()[-1])
    except Exception:
        return None, None
    found = doc.get("found")
    open_kr = doc.get("open_kr")
    found_val = found if isinstance(found, bool) else None
    open_kr_val = open_kr if isinstance(open_kr, int) else None
    return found_val, open_kr_val


def _load_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text())


def _attempt_provenance(packet_path: Path) -> Dict[str, Any]:
    """
    Best-effort provenance bundle for an attempted runtime validation.

    This is used only to bound "still blocked" anchors with a concrete packet
    + receipt pointer; it must not upgrade semantics.
    """

    prov: Dict[str, Any] = {
        "reason": None,
        "packet": str(path_utils.to_repo_relative(packet_path, REPO_ROOT)),
        "receipt": str(path_utils.to_repo_relative(RUNTIME_RECEIPT_PATH, REPO_ROOT)),
        "run_id": None,
    }
    try:
        if packet_path.exists():
            packet = _load_json(packet_path)
            run_manifest_rel = packet.get("run_manifest")
            if isinstance(run_manifest_rel, str):
                manifest_path = path_utils.ensure_absolute(run_manifest_rel, REPO_ROOT)
                if manifest_path.exists():
                    manifest = _load_json(manifest_path)
                    run_id = manifest.get("run_id")
                    if isinstance(run_id, str):
                        prov["run_id"] = run_id
    except Exception:
        pass
    return prov


def _receipt_packet_used_for(packet_path: Path) -> tuple[bool, str | None]:
    if not RUNTIME_RECEIPT_PATH.exists():
        return False, REASON_MISSING_PROMOTION_RECEIPT
    receipt = _load_json(RUNTIME_RECEIPT_PATH)
    considered = ((receipt.get("packets") or {}).get("considered") or []) if isinstance(receipt, dict) else []
    want = str(path_utils.to_repo_relative(packet_path, REPO_ROOT))
    for ent in considered:
        if not isinstance(ent, dict):
            continue
        if ent.get("path") != want:
            continue
        if ent.get("status") == "used":
            return True, None
        reasons = ent.get("reasons") or []
        if isinstance(reasons, list) and reasons:
            return False, f"{REASON_PACKET_NOT_USED}:{reasons[0]}"
        return False, REASON_PACKET_NOT_USED
    return False, REASON_PACKET_MISSING_FROM_RECEIPT


def _receipt_packet_used() -> tuple[bool, str | None]:
    return _receipt_packet_used_for(CFPREFSD_PACKET_PATH)


def _scenario_kr(runtime_results: Dict[str, Any], expectation_id: str) -> int | None:
    for entry in runtime_results.values():
        if not isinstance(entry, dict):
            continue
        for probe in entry.get("probes") or []:
            if not isinstance(probe, dict):
                continue
            if probe.get("expectation_id") != expectation_id:
                continue
            stdout = probe.get("stdout") or ""
            if not isinstance(stdout, str):
                return None
            return _parse_kr(stdout)
    return None


def _evaluate_cfprefsd_runtime_matrix(
    *, baseline_results: list[Any], runtime_results: Dict[str, Any]
) -> tuple[int | None, str | None]:
    baseline_ok = False
    bogus_unregistered = False
    for rec in baseline_results:
        if not isinstance(rec, dict):
            continue
        if rec.get("operation") != "mach-lookup":
            continue
        target = rec.get("target")
        kr = _parse_kr(rec.get("stdout") or "")
        if target == CFPREFSD_SERVICE and kr == 0:
            baseline_ok = True
        if target == CFPREFSD_BOGUS_SERVICE and kr == 1102:
            bogus_unregistered = True
    if not baseline_ok:
        return None, REASON_BASELINE_SERVICE_UNOBSERVABLE
    if not bogus_unregistered:
        return None, REASON_BASELINE_BOGUS_NOT_UNREGISTERED

    kr_s0 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:S0_allow_any")
    kr_s1 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:S1_allow_global")
    kr_s2 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:S2_allow_local")
    kr_s3 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:S3_allow_both")
    kr_n1 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:N1_deny_default")
    kr_c1 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:C1_deny_global")
    kr_c2 = _scenario_kr(runtime_results, "anchor-filter-map:cfprefsd:C2_deny_local")

    required = [kr_s0, kr_s1, kr_s2, kr_s3, kr_n1, kr_c1, kr_c2]
    if any(v is None for v in required):
        return None, REASON_MISSING_RUNTIME_KR

    # BOOTSTRAP_SUCCESS=0; BOOTSTRAP_NOT_PRIVILEGED=1100 on this host for sandbox denies.
    if not (kr_s0 == 0 and kr_s3 == 0 and kr_n1 == 1100):
        return None, REASON_DENY_DEFAULT_REACHABILITY_FAILED

    if kr_s1 == 0 and kr_s2 == 1100 and kr_c1 == 1100 and kr_c2 == 0:
        return 5, None
    if kr_s1 == 1100 and kr_s2 == 0 and kr_c1 == 0 and kr_c2 == 1100:
        return 6, None
    return None, REASON_PREDICATE_NOT_DISCRIMINATING


def _upgrade_cfprefsd_from_runtime(entry: Dict[str, Any]) -> tuple[Dict[str, Any], str | None]:
    """
    Attempt to lift the `com.apple.cfprefsd.agent` anchor out of blocked using the
    promoted runtime discriminator matrix.

    Contract (bounded): upgrade only when the promotion receipt says the packet
    was used, the baseline proves the service is observable (kr==0) and the bogus
    name is unregistered (kr==1102), and the deny-default matrix discriminates
    global-name vs local-name.
    """

    used, reason = _receipt_packet_used()
    if not used:
        return entry, reason

    if not CFPREFSD_PACKET_PATH.exists():
        return entry, REASON_MISSING_PROMOTION_PACKET
    packet = _load_json(CFPREFSD_PACKET_PATH)
    if packet.get("schema_version") != "runtime-tools.promotion_packet.v0.2":
        return entry, REASON_UNSUPPORTED_PACKET_SCHEMA

    def _abs_from_packet(key: str) -> Path | None:
        rel = packet.get(key)
        if not isinstance(rel, str):
            return None
        return path_utils.ensure_absolute(rel, REPO_ROOT)

    run_manifest_path = _abs_from_packet("run_manifest")
    baseline_path = _abs_from_packet("baseline_results")
    runtime_results_path = _abs_from_packet("runtime_results")
    if not run_manifest_path or not baseline_path or not runtime_results_path:
        return entry, REASON_PACKET_MISSING_ARTIFACT_PATHS
    if not run_manifest_path.exists() or not baseline_path.exists() or not runtime_results_path.exists():
        return entry, REASON_PACKET_ARTIFACTS_MISSING

    run_manifest = _load_json(run_manifest_path)
    if run_manifest.get("world_id") != _baseline_world_id():
        return entry, REASON_WORLD_ID_MISMATCH

    baseline = _load_json(baseline_path)
    baseline_results = baseline.get("results") or []
    rr = _load_json(runtime_results_path)
    filter_id, matrix_reason = _evaluate_cfprefsd_runtime_matrix(
        baseline_results=baseline_results if isinstance(baseline_results, list) else [],
        runtime_results=rr if isinstance(rr, dict) else {},
    )

    if filter_id == 5:
        upgraded = dict(entry)
        upgraded.pop("candidates", None)
        upgraded["filter_id"] = 5
        upgraded["filter_name"] = "global-name"
        upgraded["status"] = "partial"
        note_bits = [
            "runtime-validated mach-lookup predicate discriminator for com.apple.cfprefsd.agent",
            f"packet={path_utils.to_repo_relative(CFPREFSD_PACKET_PATH, REPO_ROOT)}",
            f"receipt={path_utils.to_repo_relative(RUNTIME_RECEIPT_PATH, REPO_ROOT)}",
            f"run_id={run_manifest.get('run_id')}",
        ]
        upgraded["notes"] = "; ".join(note_bits)
        return upgraded, None

    if filter_id == 6:
        upgraded = dict(entry)
        upgraded.pop("candidates", None)
        upgraded["filter_id"] = 6
        upgraded["filter_name"] = "local-name"
        upgraded["status"] = "partial"
        note_bits = [
            "runtime-validated mach-lookup predicate discriminator for com.apple.cfprefsd.agent",
            f"packet={path_utils.to_repo_relative(CFPREFSD_PACKET_PATH, REPO_ROOT)}",
            f"receipt={path_utils.to_repo_relative(RUNTIME_RECEIPT_PATH, REPO_ROOT)}",
            f"run_id={run_manifest.get('run_id')}",
        ]
        upgraded["notes"] = "; ".join(note_bits)
        return upgraded, None

    return entry, matrix_reason or REASON_PREDICATE_NOT_DISCRIMINATING


def _upgrade_iokit_class_from_runtime(entry: Dict[str, Any], observed_static_field2: Set[int]) -> tuple[Dict[str, Any], str | None]:
    """
    Attempt to lift the IOUSBHostInterface anchor out of blocked using the
    promoted runtime discriminator matrix.

    Contract (bounded): do not lift unless the promotion receipt says the packet
    was used, baseline lane shows the class is observable in this process context
    (found=true, open_kr==0), the bogus class is unobservable (found=false), and
    the deny-default matrix discriminates iokit-registry-entry-class vs
    iokit-property.
    """

    used, reason = _receipt_packet_used_for(IOKIT_CLASS_PACKET_PATH)
    if not used:
        return entry, reason

    if not IOKIT_CLASS_PACKET_PATH.exists():
        return entry, REASON_MISSING_PROMOTION_PACKET
    packet = _load_json(IOKIT_CLASS_PACKET_PATH)
    if packet.get("schema_version") != "runtime-tools.promotion_packet.v0.2":
        return entry, REASON_UNSUPPORTED_PACKET_SCHEMA

    def _abs_from_packet(key: str) -> Path | None:
        rel = packet.get(key)
        if not isinstance(rel, str):
            return None
        return path_utils.ensure_absolute(rel, REPO_ROOT)

    run_manifest_path = _abs_from_packet("run_manifest")
    baseline_path = _abs_from_packet("baseline_results")
    runtime_results_path = _abs_from_packet("runtime_results")
    if not run_manifest_path or not baseline_path or not runtime_results_path:
        return entry, REASON_PACKET_MISSING_ARTIFACT_PATHS
    if not run_manifest_path.exists() or not baseline_path.exists() or not runtime_results_path.exists():
        return entry, REASON_PACKET_ARTIFACTS_MISSING

    run_manifest = _load_json(run_manifest_path)
    if run_manifest.get("world_id") != _baseline_world_id():
        return entry, REASON_WORLD_ID_MISMATCH

    baseline = _load_json(baseline_path)
    baseline_results = baseline.get("results") or []
    baseline_ok = False
    bogus_unobservable = False
    for rec in baseline_results:
        if not isinstance(rec, dict):
            continue
        if rec.get("operation") != "iokit-open-service":
            continue
        target = rec.get("target")
        found, open_kr = _parse_iokit_open(rec.get("stdout") or "")
        if target == IOKIT_CLASS_ANCHOR and found is True and open_kr == 0:
            baseline_ok = True
        if target == IOKIT_CLASS_BOGUS and found is False:
            bogus_unobservable = True
    if not baseline_ok:
        return entry, REASON_BASELINE_SERVICE_UNOBSERVABLE
    if not bogus_unobservable:
        return entry, REASON_BASELINE_BOGUS_NOT_UNREGISTERED

    rr = _load_json(runtime_results_path)
    if not isinstance(rr, dict):
        return entry, REASON_MISSING_RUNTIME_KR

    def _scenario_open(expectation_id: str) -> tuple[bool | None, int | None]:
        for prof in rr.values():
            if not isinstance(prof, dict):
                continue
            for probe in prof.get("probes") or []:
                if not isinstance(probe, dict):
                    continue
                if probe.get("expectation_id") != expectation_id:
                    continue
                return _parse_iokit_open(probe.get("stdout") or "")
        return None, None

    def _is_allow(found: bool | None, open_kr: int | None) -> bool | None:
        if found is None:
            return None
        if found is False:
            return None
        if open_kr is None:
            return None
        return open_kr == 0

    s0 = _scenario_open("anchor-filter-map:iokit_class:S0_allow_any")
    s1 = _scenario_open("anchor-filter-map:iokit_class:S1_allow_class")
    s2 = _scenario_open("anchor-filter-map:iokit_class:S2_allow_property_literal")
    s3 = _scenario_open("anchor-filter-map:iokit_class:S3_allow_both")
    n1 = _scenario_open("anchor-filter-map:iokit_class:N1_deny_default")
    c1 = _scenario_open("anchor-filter-map:iokit_class:C1_deny_class")
    c2 = _scenario_open("anchor-filter-map:iokit_class:C2_deny_property_literal")

    allow_s0 = _is_allow(*s0)
    allow_s1 = _is_allow(*s1)
    allow_s2 = _is_allow(*s2)
    allow_s3 = _is_allow(*s3)
    allow_n1 = _is_allow(*n1)
    allow_c1 = _is_allow(*c1)
    allow_c2 = _is_allow(*c2)
    if None in [allow_s0, allow_s1, allow_s2, allow_s3, allow_n1, allow_c1, allow_c2]:
        return entry, REASON_MISSING_RUNTIME_KR

    # Reachability: broad allow must succeed; deny-default negative must fail.
    if not (allow_s0 is True and allow_s3 is True and allow_n1 is False):
        return entry, REASON_DENY_DEFAULT_REACHABILITY_FAILED

    # Predicate discrimination + mapping fidelity controls.
    if allow_s1 is True and allow_s2 is False and allow_c1 is False and allow_c2 is True:
        filter_id = 16
        filter_name = "iokit-registry-entry-class"
    elif allow_s1 is False and allow_s2 is True and allow_c1 is True and allow_c2 is False:
        filter_id = 17
        filter_name = "iokit-property"
    else:
        return entry, REASON_PREDICATE_NOT_DISCRIMINATING

    if filter_id not in observed_static_field2:
        return entry, REASON_STATIC_FIELD2_MISMATCH

    upgraded = dict(entry)
    upgraded.pop("candidates", None)
    upgraded["filter_id"] = filter_id
    upgraded["filter_name"] = filter_name
    upgraded["status"] = "partial"
    note_bits = [
        "runtime-validated iokit-open-service predicate discriminator for IOUSBHostInterface",
        f"packet={path_utils.to_repo_relative(IOKIT_CLASS_PACKET_PATH, REPO_ROOT)}",
        f"receipt={path_utils.to_repo_relative(RUNTIME_RECEIPT_PATH, REPO_ROOT)}",
        f"run_id={run_manifest.get('run_id')}",
    ]
    upgraded["notes"] = "; ".join(note_bits)
    return upgraded, None


def observed_field2(anchor: str, sources: list[str], hits_doc: dict) -> Set[int]:
    observed: Set[int] = set()
    for src in sources:
        profile_hits = hits_doc.get(src)
        if not profile_hits:
            continue
        for ah in profile_hits.get("anchors") or []:
            if ah.get("anchor") != anchor:
                continue
            for val in ah.get("field2_values") or []:
                if isinstance(val, int):
                    observed.add(val)
    return observed


def main() -> None:
    if not OUT_PATH.exists():
        raise FileNotFoundError(f"missing anchor_filter_map at {OUT_PATH}")
    amap = json.loads(OUT_PATH.read_text())
    hits_doc = json.loads(HITS_PATH.read_text())

    out: Dict[str, Any] = {}
    for anchor, entry in amap.items():
        if anchor == "metadata":
            meta = dict(entry) if isinstance(entry, dict) else {}
            meta["world_id"] = _baseline_world_id()
            meta.pop("status", None)
            meta["tier"] = "mapped"
            out[anchor] = meta
            continue
        if not isinstance(entry, dict):
            out[anchor] = entry
            continue
        if anchor == CFPREFSD_SERVICE and entry.get("status") == "blocked":
            upgraded, reason = _upgrade_cfprefsd_from_runtime(entry)
            entry = upgraded
            if reason:
                attempted = dict(entry)
                prov = _attempt_provenance(CFPREFSD_PACKET_PATH)
                prov["reason"] = reason
                attempted["runtime_validation_attempt"] = prov
                attempted["notes"] = (attempted.get("notes") or "") + f" (runtime validation attempted: {reason})"
                out[anchor] = attempted
                continue
        if anchor == IOKIT_CLASS_ANCHOR and entry.get("status") == "blocked":
            sources = entry.get("sources") or []
            observed = observed_field2(anchor, sources, hits_doc)
            upgraded, reason = _upgrade_iokit_class_from_runtime(entry, observed)
            entry = upgraded
            if reason:
                attempted = dict(entry)
                prov = _attempt_provenance(IOKIT_CLASS_PACKET_PATH)
                prov["reason"] = reason
                attempted["runtime_validation_attempt"] = prov
                attempted["notes"] = (attempted.get("notes") or "") + f" (runtime validation attempted: {reason})"
                out[anchor] = attempted
                continue
        if entry.get("status") == "blocked":
            out[anchor] = entry
            continue

        filter_id = entry.get("filter_id")
        sources = entry.get("sources") or []
        if filter_id is None or not sources:
            out[anchor] = entry
            continue

        observed = observed_field2(anchor, sources, hits_doc)
        if not observed:
            demoted = dict(entry)
            demoted["status"] = "blocked"
            demoted.pop("filter_id", None)
            demoted.pop("filter_name", None)
            demoted["notes"] = (demoted.get("notes") or "") + " (demoted: no anchor_hits observations for sources)"
            out[anchor] = demoted
            continue

        if filter_id not in observed:
            demoted = dict(entry)
            demoted["status"] = "blocked"
            demoted.pop("filter_id", None)
            demoted.pop("filter_name", None)
            demoted["notes"] = (demoted.get("notes") or "") + " (demoted: pinned filter_id not witnessed in anchor_hits)"
            out[anchor] = demoted
            continue

        mapped = set(entry.get("field2_values") or [])
        mapped.update(observed)
        refreshed = dict(entry)
        refreshed["field2_values"] = sorted(mapped)
        out[anchor] = refreshed

    OUT_PATH.write_text(json.dumps(out, indent=2, sort_keys=True))
    print(f"[+] wrote {path_utils.to_repo_relative(OUT_PATH, REPO_ROOT)}")


if __name__ == "__main__":
    main()
