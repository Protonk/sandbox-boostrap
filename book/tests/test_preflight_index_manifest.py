from __future__ import annotations

import hashlib
import json
from pathlib import Path

from book.tools.preflight import preflight as preflight_mod


ROOT = Path(__file__).resolve().parents[2]
BASELINE = ROOT / "book" / "world" / "sonoma-14.4.1-23E224-arm64" / "world-baseline.json"
MANIFEST_PATH = ROOT / "book" / "experiments" / "preflight-index" / "out" / "preflight_enterability_manifest.json"
SUMMARY_PATH = ROOT / "book" / "experiments" / "preflight-index" / "out" / "summary.json"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _discover_profiles_sbpl() -> set[str]:
    out: set[str] = set()
    root = ROOT / "book" / "profiles"
    for p in root.rglob("*.sb"):
        if p.is_file():
            out.add(str(p.relative_to(ROOT)))
    return out


def _discover_experiments_sbpl() -> set[str]:
    out: set[str] = set()
    root = ROOT / "book" / "experiments"
    for p in root.rglob("*.sb"):
        if not p.is_file():
            continue
        # Exclude derived artifacts under out/; these tend to churn as harnesses evolve.
        if "out" in p.parts:
            continue
        out.add(str(p.relative_to(ROOT)))
    return out


def _discover_examples_sbpl() -> set[str]:
    out: set[str] = set()
    root = ROOT / "book" / "examples"
    for p in root.rglob("*.sb"):
        if p.is_file():
            out.add(str(p.relative_to(ROOT)))
    return out


def _discover_book_blobs() -> set[str]:
    out: set[str] = set()
    root = ROOT / "book"
    for p in root.rglob("*.sb.bin"):
        if p.is_file():
            out.add(str(p.relative_to(ROOT)))
    return out


def _discover_inventory() -> set[str]:
    return _discover_profiles_sbpl() | _discover_experiments_sbpl() | _discover_examples_sbpl() | _discover_book_blobs()


def test_preflight_index_manifest_covers_current_inventory_and_is_current():
    world_id = json.loads(BASELINE.read_text()).get("world_id")
    assert world_id, "baseline world_id missing"
    assert MANIFEST_PATH.exists(), f"missing manifest: {MANIFEST_PATH}"
    assert SUMMARY_PATH.exists(), f"missing summary: {SUMMARY_PATH}"

    manifest = json.loads(MANIFEST_PATH.read_text())
    assert manifest.get("world_id") == world_id
    assert manifest.get("preflight_schema_version") == preflight_mod.PREFLIGHT_SCHEMA_VERSION
    assert isinstance(manifest.get("records"), list) and manifest["records"], "manifest.records must be a non-empty list"

    inventory = _discover_inventory()

    by_path = {}
    for rec in manifest["records"]:
        assert isinstance(rec, dict)
        path = rec.get("path")
        assert isinstance(path, str) and path
        assert not path.startswith("/"), f"manifest path must be repo-relative: {path}"
        by_path[path] = rec

    # Coverage: manifest and inventory match exactly.
    missing = sorted(inventory - set(by_path.keys()))
    extra = sorted(set(by_path.keys()) - inventory)
    assert not missing, f"manifest missing {len(missing)} inputs, e.g. {missing[:5]}"
    assert not extra, f"manifest has {len(extra)} stale inputs, e.g. {extra[:5]}"

    allowed_classifications = {
        "likely_apply_gated_for_harness_identity",
        "no_known_apply_gate_signature",
        "invalid",
        "unsupported",
    }

    # Currentness: checked-in classification matches current preflight implementation.
    for rel in sorted(inventory):
        abs_path = ROOT / rel
        rec = by_path[rel]
        assert abs_path.exists()

        file_sha = rec.get("file_sha256")
        assert isinstance(file_sha, str) and len(file_sha) == 64
        assert _sha256_file(abs_path) == file_sha

        pf = rec.get("preflight")
        assert isinstance(pf, dict)
        assert pf.get("world_id") == world_id
        assert pf.get("input_ref") == rel
        assert pf.get("classification") in allowed_classifications

        live = preflight_mod.preflight_path(abs_path).to_json()
        assert live.get("classification") == pf.get("classification")
        assert live.get("signature") == pf.get("signature")

        if rel.endswith(".sb.bin"):
            findings = pf.get("findings") or []
            if isinstance(findings, list) and findings and isinstance(findings[0], dict):
                blob_sha = findings[0].get("blob_sha256")
                if isinstance(blob_sha, str):
                    assert blob_sha == file_sha

    summary = json.loads(SUMMARY_PATH.read_text())
    counts = (summary.get("counts") or {}) if isinstance(summary, dict) else {}
    assert counts.get("total_records") == len(inventory)
