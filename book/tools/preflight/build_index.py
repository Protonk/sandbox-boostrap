#!/usr/bin/env python3
"""
Build a static preflight index over in-repo profile inputs.

This is an operational artifact: it answers “which in-repo profile inputs are
known to carry apply-gate signatures for the harness identity on this world?”

It does not attempt to compile or apply profiles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence


REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile.identity import baseline_world_id  # type: ignore


BASE_DIR = Path(__file__).resolve().parent
DEFAULT_OUT_DIR = BASE_DIR / "index"
DEFAULT_MANIFEST_PATH = DEFAULT_OUT_DIR / "preflight_enterability_manifest.json"
DEFAULT_SUMMARY_PATH = DEFAULT_OUT_DIR / "summary.json"

MANIFEST_SCHEMA_VERSION = 1
EXCLUDED_EXPERIMENT_DIRS = {
    "entitlement-diff",
    "entitlement-jail-extension-semantics",
}
EXCLUDED_EXPERIMENTS_LABEL = ", ".join(sorted(EXCLUDED_EXPERIMENT_DIRS))


def _excluded_experiment_roots(experiments_root: Path) -> List[Path]:
    roots: List[Path] = []
    for name in sorted(EXCLUDED_EXPERIMENT_DIRS):
        roots.append(experiments_root / name)
        roots.append(experiments_root / "archive" / name)
    return roots


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class InputRef:
    path: Path
    sources: tuple[str, ...]


def _discover_profiles_sbpl() -> List[Path]:
    root = REPO_ROOT / "book" / "profiles"
    if not root.exists():
        return []
    return sorted([p for p in root.rglob("*.sb") if p.is_file()])


def _discover_experiments_sbpl() -> List[Path]:
    root = REPO_ROOT / "book" / "experiments"
    if not root.exists():
        return []
    excluded_roots = _excluded_experiment_roots(root)
    sbpls: List[Path] = []
    for p in root.rglob("*.sb"):
        if not p.is_file():
            continue
        # Exclude derived artifacts under out*/; these tend to churn as harnesses evolve.
        if any(part == "out" or part.startswith("out_") or part.startswith("out-") for part in p.parts):
            continue
        if any(p.is_relative_to(excluded) for excluded in excluded_roots):
            continue
        sbpls.append(p)
    return sorted(set(sbpls))


def _discover_examples_sbpl() -> List[Path]:
    root = REPO_ROOT / "book" / "examples"
    if not root.exists():
        return []
    return sorted([p for p in root.rglob("*.sb") if p.is_file()])


def _discover_tools_sbpl() -> List[Path]:
    root = REPO_ROOT / "book" / "tools" / "sbpl" / "corpus"
    if not root.exists():
        return []
    return sorted([p for p in root.rglob("*.sb") if p.is_file()])


def _discover_book_blobs() -> List[Path]:
    root = REPO_ROOT / "book"
    if not root.exists():
        return []
    # NOTE: `book/dumps/**` is host-local working material (often private) and must
    # not be pulled into the checked-in preflight index inventory. Similarly,
    # `book/integration/out/**` is a scratch directory for test runs.
    excluded_roots = [
        root / "dumps",
        root / "integration" / "out",
    ]
    excluded_roots.extend(_excluded_experiment_roots(root / "experiments"))

    blobs: List[Path] = []
    for path in root.rglob("*.sb.bin"):
        if not path.is_file():
            continue
        if any(path.is_relative_to(excluded) for excluded in excluded_roots):
            continue
        blobs.append(path)
    return sorted(blobs)


def discover_inputs() -> List[InputRef]:
    """
    Enumerate inputs deterministically, deduplicating on resolved path.

    Sources:
    - profiles_sbpl: book/profiles/**/*.sb
    - experiments_sbpl: book/evidence/experiments/**/*.sb (excluding out/, entitlement-diff, entitlement-jail-extension-semantics)
    - examples_sbpl: book/examples/**/*.sb
    - tools_sbpl: book/tools/sbpl/corpus/**/*.sb
    - book_blobs: book/**/*.sb.bin (excluding book/dumps/**, book/integration/out/**, and excluded experiments)
    """

    by_path: Dict[Path, set[str]] = {}
    for p in _discover_profiles_sbpl():
        by_path.setdefault(p.resolve(), set()).add("profiles_sbpl")
    for p in _discover_experiments_sbpl():
        by_path.setdefault(p.resolve(), set()).add("experiments_sbpl")
    for p in _discover_examples_sbpl():
        by_path.setdefault(p.resolve(), set()).add("examples_sbpl")
    for p in _discover_tools_sbpl():
        by_path.setdefault(p.resolve(), set()).add("tools_sbpl")
    for p in _discover_book_blobs():
        by_path.setdefault(p.resolve(), set()).add("book_blobs")

    out: List[InputRef] = []
    for p in sorted(by_path.keys()):
        out.append(InputRef(path=p, sources=tuple(sorted(by_path[p]))))
    return out


def build_manifest(inputs: Sequence[InputRef]) -> Dict[str, Any]:
    try:
        from book.tools.preflight import preflight as preflight_mod  # type: ignore
    except Exception as exc:  # pragma: no cover - repo integrity issue
        raise RuntimeError(f"failed to import preflight tool: {exc}") from exc

    world_id = baseline_world_id(REPO_ROOT)
    records: List[Dict[str, Any]] = []

    for ref in inputs:
        path = ref.path
        rel = to_repo_relative(path, REPO_ROOT)
        stat = path.stat()
        sha256 = _sha256_file(path)
        preflight_rec = preflight_mod.preflight_path(path).to_json()
        records.append(
            {
                "path": rel,
                "sources": list(ref.sources),
                "file_size": int(stat.st_size),
                "file_sha256": sha256,
                "preflight": preflight_rec,
            }
        )

    return {
        "world_id": world_id,
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "preflight_schema_version": preflight_mod.PREFLIGHT_SCHEMA_VERSION,
        "inputs": {
            "profiles_sbpl": "book/profiles/**/*.sb",
            "experiments_sbpl": f"book/evidence/experiments/**/*.sb (excluding out/ and {EXCLUDED_EXPERIMENTS_LABEL})",
            "examples_sbpl": "book/examples/**/*.sb",
            "tools_sbpl": "book/tools/sbpl/corpus/**/*.sb",
            "book_blobs": (
                "book/**/*.sb.bin (excluding book/dumps/**, book/integration/out/**, and "
                f"{EXCLUDED_EXPERIMENTS_LABEL})"
            ),
        },
        "records": records,
    }


def _count_by(records: Iterable[Mapping[str, Any]], key: str) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for rec in records:
        raw = rec.get(key)
        k = raw if isinstance(raw, str) else "null"
        out[k] = out.get(k, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def build_summary(manifest: Mapping[str, Any]) -> Dict[str, Any]:
    records = manifest.get("records") or []
    if not isinstance(records, list):
        raise AssertionError("manifest.records must be a list")

    flat: List[Dict[str, Any]] = []
    for rec in records:
        if not isinstance(rec, Mapping):
            continue
        preflight = rec.get("preflight") if isinstance(rec.get("preflight"), Mapping) else {}
        flat.append(
            {
                "path": rec.get("path"),
                "classification": preflight.get("classification"),
                "signature": preflight.get("signature"),
                "input_kind": preflight.get("input_kind"),
            }
        )

    by_classification = _count_by(flat, "classification")
    by_signature = _count_by(flat, "signature")
    by_input_kind = _count_by(flat, "input_kind")

    by_source: Dict[str, Dict[str, int]] = {}
    for rec in records:
        if not isinstance(rec, Mapping):
            continue
        sources = rec.get("sources") or []
        preflight = rec.get("preflight") if isinstance(rec.get("preflight"), Mapping) else {}
        classification = preflight.get("classification")
        cls = classification if isinstance(classification, str) else "null"
        for source in sources if isinstance(sources, list) else []:
            if not isinstance(source, str):
                continue
            by_source.setdefault(source, {})
            by_source[source][cls] = by_source[source].get(cls, 0) + 1
    by_source = {k: dict(sorted(v.items(), key=lambda kv: (-kv[1], kv[0]))) for k, v in sorted(by_source.items())}

    sets: Dict[str, List[str]] = {}
    for rec in flat:
        classification = rec.get("classification")
        if not isinstance(classification, str):
            classification = "null"
        path = rec.get("path")
        if isinstance(path, str):
            sets.setdefault(classification, []).append(path)
    for cls in sets:
        sets[cls] = sorted(sets[cls])

    digest_groups: List[Dict[str, Any]] = []
    apply_gate_paths: Dict[str, List[str]] = {}
    for rec in records:
        if not isinstance(rec, Mapping):
            continue
        pf = rec.get("preflight") if isinstance(rec.get("preflight"), Mapping) else {}
        if pf.get("signature") != "apply_gate_blob_digest":
            continue
        file_sha = rec.get("file_sha256")
        path = rec.get("path")
        if isinstance(file_sha, str) and isinstance(path, str):
            apply_gate_paths.setdefault(file_sha, []).append(path)
    for sha in sorted(apply_gate_paths.keys(), key=lambda k: (-len(apply_gate_paths[k]), k)):
        digest_groups.append(
            {
                "blob_sha256": sha,
                "count": len(apply_gate_paths[sha]),
                "paths": sorted(apply_gate_paths[sha]),
            }
        )

    return {
        "world_id": manifest.get("world_id"),
        "manifest_schema_version": manifest.get("manifest_schema_version"),
        "preflight_schema_version": manifest.get("preflight_schema_version"),
        "counts": {
            "total_records": len(flat),
            "by_classification": by_classification,
            "by_signature": by_signature,
            "by_input_kind": by_input_kind,
            "by_source": by_source,
        },
        "digest_groups": {"apply_gate_blob_digest": digest_groups},
        "sets": sets,
        "notes": [
            "no_known_apply_gate_signature is not a guarantee that apply will succeed",
            "likely_apply_gated_for_harness_identity is a host-scoped avoidance signal for harness-applied profiles",
        ],
    }


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="preflight-index")
    ap.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR, help="Output directory for artifacts.")
    ap.add_argument(
        "--manifest",
        type=Path,
        default=DEFAULT_MANIFEST_PATH,
        help="Path to write the enterability manifest JSON.",
    )
    ap.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY_PATH, help="Path to write summary counts JSON.")
    args = ap.parse_args(argv)

    inputs = discover_inputs()
    manifest = build_manifest(inputs)
    summary = build_summary(manifest)

    manifest_path = (args.out_dir / args.manifest) if not args.manifest.is_absolute() else args.manifest
    summary_path = (args.out_dir / args.summary) if not args.summary.is_absolute() else args.summary
    _write_json(manifest_path, manifest)
    _write_json(summary_path, summary)
    print(f"[+] wrote {to_repo_relative(manifest_path, REPO_ROOT)}")
    print(f"[+] wrote {to_repo_relative(summary_path, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
