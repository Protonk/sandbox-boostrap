#!/usr/bin/env python3
"""
Preflight tooling for profile enterability (apply-gate discipline).

This tool exists to prevent agents from repeatedly rediscovering that certain
SBPL profile shapes are apply-gated (sandbox_init/sandbox_apply fail with EPERM)
for the harness identity on this host baseline.

Subcommands:
- `scan`: cheap, static apply-gate avoidance (used by the SBPL wrapper in book/tools/sbpl/wrapper).
- `minimize-gate`: delta-debug an apply-gated SBPL into a minimal failing + passing neighbor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import to_repo_relative  # type: ignore
from book.api.profile_tools import identity as identity_mod  # type: ignore
from book.api.profile_tools import sbpl_scan  # type: ignore


PREFLIGHT_SCHEMA_VERSION = 1

_BLOB_DIGESTS_IR_PATH = (
    REPO_ROOT
    / "book"
    / "graph"
    / "concepts"
    / "validation"
    / "out"
    / "experiments"
    / "preflight-blob-digests"
    / "blob_digests_ir.json"
)

_SIGNATURE_POINTERS: Dict[str, Dict[str, Any]] = {
    "deny_message_filter": {
        "status": "partial",
        "pointers": [
            "troubles/EPERMx2.md",
            "book/experiments/gate-witnesses/Report.md",
            "book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json",
        ],
    },
    "apply_gate_blob_digest": {
        "status": "ok",
        "pointers": [
            "troubles/EPERMx2.md",
            "book/experiments/preflight-blob-digests/Report.md",
            "book/graph/concepts/validation/out/experiments/preflight-blob-digests/blob_digests_ir.json",
        ],
    },
}

_APPLY_GATE_BLOB_DIGEST_CACHE: Optional[set[str]] = None
_APPLY_GATE_BLOB_DIGEST_CACHE_ERROR: Optional[str] = None


@dataclass(frozen=True)
class PreflightRecord:
    world_id: str
    input_kind: str
    input_ref: str
    classification: str
    signature: Optional[str]
    findings: List[Dict[str, Any]]
    signature_meta: Optional[Dict[str, Any]]
    error: Optional[str]

    def to_json(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "tool": "book/tools/preflight",
            "preflight_schema_version": PREFLIGHT_SCHEMA_VERSION,
            "world_id": self.world_id,
            "input_kind": self.input_kind,
            "input_ref": self.input_ref,
            "classification": self.classification,
            "signature": self.signature,
            "findings": self.findings,
        }
        if self.signature_meta is not None:
            out["signature_meta"] = self.signature_meta
        if self.error is not None:
            out["error"] = self.error
        return out


def preflight_sbpl_text(sbpl_text: str, *, input_ref: str = "<sbpl_text>") -> PreflightRecord:
    world_id = identity_mod.baseline_world_id()
    try:
        rec = sbpl_scan.classify_enterability_for_harness_identity(sbpl_text)
    except Exception as exc:
        return PreflightRecord(
            world_id=world_id,
            input_kind="sbpl_text",
            input_ref=input_ref,
            classification="invalid",
            signature=None,
            findings=[],
            signature_meta=None,
            error=str(exc),
        )

    signature = rec.get("signature") if isinstance(rec, dict) else None
    sig_meta = _SIGNATURE_POINTERS.get(signature) if isinstance(signature, str) else None
    return PreflightRecord(
        world_id=world_id,
        input_kind="sbpl_text",
        input_ref=input_ref,
        classification=str(rec.get("classification")),
        signature=str(signature) if signature is not None else None,
        findings=list(rec.get("findings") or []),
        signature_meta=dict(sig_meta) if sig_meta else None,
        error=None,
    )


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_apply_gate_blob_digests() -> set[str]:
    global _APPLY_GATE_BLOB_DIGEST_CACHE, _APPLY_GATE_BLOB_DIGEST_CACHE_ERROR
    if _APPLY_GATE_BLOB_DIGEST_CACHE is not None:
        return _APPLY_GATE_BLOB_DIGEST_CACHE

    if not _BLOB_DIGESTS_IR_PATH.exists():
        _APPLY_GATE_BLOB_DIGEST_CACHE = set()
        _APPLY_GATE_BLOB_DIGEST_CACHE_ERROR = (
            f"missing digest corpus: {to_repo_relative(_BLOB_DIGESTS_IR_PATH, REPO_ROOT)}"
        )
        return _APPLY_GATE_BLOB_DIGEST_CACHE

    try:
        payload = json.loads(_BLOB_DIGESTS_IR_PATH.read_text())
    except Exception as exc:
        _APPLY_GATE_BLOB_DIGEST_CACHE = set()
        _APPLY_GATE_BLOB_DIGEST_CACHE_ERROR = f"failed to read digest corpus: {exc}"
        return _APPLY_GATE_BLOB_DIGEST_CACHE

    baseline_world = identity_mod.baseline_world_id()
    if payload.get("world_id") != baseline_world:
        _APPLY_GATE_BLOB_DIGEST_CACHE = set()
        _APPLY_GATE_BLOB_DIGEST_CACHE_ERROR = "digest corpus world_id mismatch"
        return _APPLY_GATE_BLOB_DIGEST_CACHE

    digests: set[str] = set()
    for entry in payload.get("apply_gate_digests") or []:
        if isinstance(entry, dict) and isinstance(entry.get("blob_sha256"), str):
            digests.add(entry["blob_sha256"])

    _APPLY_GATE_BLOB_DIGEST_CACHE = digests
    _APPLY_GATE_BLOB_DIGEST_CACHE_ERROR = None
    return digests


def preflight_sbpl_blob(path: Path) -> PreflightRecord:
    world_id = identity_mod.baseline_world_id()
    ref = to_repo_relative(path, REPO_ROOT)
    if not path.exists():
        return PreflightRecord(
            world_id=world_id,
            input_kind="path",
            input_ref=ref,
            classification="invalid",
            signature=None,
            findings=[],
            signature_meta=None,
            error="missing",
        )

    try:
        blob_sha256 = _sha256_file(path)
    except Exception as exc:
        return PreflightRecord(
            world_id=world_id,
            input_kind="sbpl_blob_path",
            input_ref=ref,
            classification="invalid",
            signature=None,
            findings=[],
            signature_meta=None,
            error=f"failed to read: {exc}",
        )

    digests = _load_apply_gate_blob_digests()
    if _APPLY_GATE_BLOB_DIGEST_CACHE_ERROR is not None:
        return PreflightRecord(
            world_id=world_id,
            input_kind="sbpl_blob_path",
            input_ref=ref,
            classification="unsupported",
            signature=None,
            findings=[{"blob_sha256": blob_sha256}],
            signature_meta=None,
            error=_APPLY_GATE_BLOB_DIGEST_CACHE_ERROR,
        )

    if blob_sha256 in digests:
        signature = "apply_gate_blob_digest"
        sig_meta = _SIGNATURE_POINTERS.get(signature)
        return PreflightRecord(
            world_id=world_id,
            input_kind="sbpl_blob_path",
            input_ref=ref,
            classification="likely_apply_gated_for_harness_identity",
            signature=signature,
            findings=[{"blob_sha256": blob_sha256, "matched": True}],
            signature_meta=dict(sig_meta) if sig_meta else None,
            error=None,
        )

    return PreflightRecord(
        world_id=world_id,
        input_kind="sbpl_blob_path",
        input_ref=ref,
        classification="no_known_apply_gate_signature",
        signature=None,
        findings=[{"blob_sha256": blob_sha256, "matched": False}],
        signature_meta=None,
        error=None,
    )


def preflight_path(path: Path) -> PreflightRecord:
    world_id = identity_mod.baseline_world_id()
    ref = to_repo_relative(path, REPO_ROOT)
    if not path.exists():
        return PreflightRecord(
            world_id=world_id,
            input_kind="path",
            input_ref=ref,
            classification="invalid",
            signature=None,
            findings=[],
            signature_meta=None,
            error="missing",
        )
    if path.suffixes[-2:] == [".sb", ".bin"]:
        return preflight_sbpl_blob(path)
    if path.suffix != ".sb":
        return PreflightRecord(
            world_id=world_id,
            input_kind="path",
            input_ref=ref,
            classification="unsupported",
            signature=None,
            findings=[],
            signature_meta=None,
            error="only .sb and .sb.bin inputs are supported",
        )

    try:
        text = path.read_text()
    except Exception as exc:
        return PreflightRecord(
            world_id=world_id,
            input_kind="path",
            input_ref=ref,
            classification="invalid",
            signature=None,
            findings=[],
            signature_meta=None,
            error=f"failed to read: {exc}",
        )

    rec = preflight_sbpl_text(text, input_ref=ref)
    return PreflightRecord(
        world_id=rec.world_id,
        input_kind="sbpl_path",
        input_ref=rec.input_ref,
        classification=rec.classification,
        signature=rec.signature,
        findings=rec.findings,
        signature_meta=rec.signature_meta,
        error=rec.error,
    )


def expand_paths(paths: Sequence[Path]) -> List[Path]:
    out: List[Path] = []
    for p in paths:
        if p.is_dir():
            out.extend(sorted(p.rglob("*.sb")))
            out.extend(sorted(p.rglob("*.sb.bin")))
        else:
            out.append(p)
    return sorted(set(out))


def scan_paths(paths: Sequence[Path]) -> List[PreflightRecord]:
    expanded = expand_paths(paths)
    return [preflight_path(p) for p in expanded]


def _json_dump(payload: Any, *, jsonl: bool) -> str:
    if jsonl:
        lines = [json.dumps(obj, sort_keys=True) for obj in payload]
        return "\n".join(lines) + ("\n" if lines else "")
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _exit_code(records: Iterable[PreflightRecord]) -> int:
    saw_gate = False
    saw_invalid = False
    for rec in records:
        if rec.classification == "likely_apply_gated_for_harness_identity":
            saw_gate = True
        if rec.classification in {"invalid", "unsupported"}:
            saw_invalid = True
    if saw_invalid:
        return 1
    if saw_gate:
        return 2
    return 0


def _scan_cmd(argv: argparse.Namespace) -> int:
    paths = [Path(p) for p in argv.paths]
    records = scan_paths(paths)
    serialized = _json_dump([r.to_json() for r in records], jsonl=argv.jsonl)
    if argv.out:
        argv.out.write_text(serialized)
    else:
        sys.stdout.write(serialized)
    return _exit_code(records)


def main(argv: Optional[Sequence[str]] = None) -> int:
    argv_list = list(sys.argv[1:] if argv is None else argv)
    if argv_list and argv_list[0] == "minimize-gate":
        from book.tools.preflight import gate_minimizer  # type: ignore

        return int(gate_minimizer.main(argv_list[1:]))

    ap = argparse.ArgumentParser(
        prog="preflight",
        epilog="Other command: minimize-gate (delta-debug apply gating). Run: preflight minimize-gate --help",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan profile inputs for known apply-gate signatures")
    scan.add_argument(
        "paths",
        nargs="+",
        help="SBPL .sb / .sb.bin files and/or directories (directories scanned recursively)",
    )
    scan.add_argument("--jsonl", action="store_true", help="emit JSONL (one record per line)")
    scan.add_argument("--out", type=Path, help="write output JSON to path instead of stdout")
    scan.set_defaults(func=_scan_cmd)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
