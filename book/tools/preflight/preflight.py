#!/usr/bin/env python3
"""
Static preflight for profile enterability (apply-gate avoidance).

This tool exists to prevent agents from repeatedly rediscovering that certain
SBPL profile shapes are apply-gated (sandbox_init/sandbox_apply fail with EPERM)
for the harness identity on this host baseline.
"""

from __future__ import annotations

import argparse
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

_SIGNATURE_POINTERS: Dict[str, Dict[str, Any]] = {
    "deny_message_filter": {
        "status": "partial",
        "pointers": [
            "troubles/EPERMx2.md",
            "book/experiments/gate-witnesses/Report.md",
            "book/graph/concepts/validation/out/experiments/gate-witnesses/witness_results.json",
        ],
    }
}


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
    if path.suffix != ".sb":
        return PreflightRecord(
            world_id=world_id,
            input_kind="path",
            input_ref=ref,
            classification="unsupported",
            signature=None,
            findings=[],
            signature_meta=None,
            error="only .sb inputs are supported (SBPL text)",
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
        else:
            out.append(p)
    return out


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
    ap = argparse.ArgumentParser(prog="preflight")
    sub = ap.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="scan SBPL inputs for known apply-gate signatures")
    scan.add_argument("paths", nargs="+", help="SBPL .sb files and/or directories (directories scanned recursively)")
    scan.add_argument("--jsonl", action="store_true", help="emit JSONL (one record per line)")
    scan.add_argument("--out", type=Path, help="write output JSON to path instead of stdout")
    scan.set_defaults(func=_scan_cmd)

    args = ap.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
