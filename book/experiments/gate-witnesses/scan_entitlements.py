#!/usr/bin/env python3
"""
Scan a small set of host executables for message-filter-related entitlements.

This is intentionally narrow: it records whether the private entitlement key
`com.apple.private.security.message-filter` exists on this world baseline and
which system services carry it, as a corroborating clue for apply-gated
`apply-message-filter` witnesses.

Output is a small, checked-in JSON artifact under this experiment's `out/`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api.path_utils import find_repo_root, to_repo_relative
from book.api.runtime_tools.core.models import WORLD_ID

ENTITLEMENT_MESSAGE_FILTER = "com.apple.private.security.message-filter"
ENTITLEMENT_MESSAGE_FILTER_MANAGER = "com.apple.private.security.message-filter-manager"


@dataclass(frozen=True)
class Target:
    label: str
    path: str


def _default_targets() -> List[Target]:
    return [
        Target("control:wrapper", "book/tools/sbpl/wrapper/wrapper"),
        Target("control:/usr/bin/true", "/usr/bin/true"),
        Target(
            "coregraphics:CGPDFService",
            "/System/Library/Frameworks/CoreGraphics.framework/Versions/A/XPCServices/CGPDFService.xpc/Contents/MacOS/CGPDFService",
        ),
        Target(
            "webkit:WebContent",
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent",
        ),
        Target(
            "webkit:GPU",
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.GPU.xpc/Contents/MacOS/com.apple.WebKit.GPU",
        ),
        Target(
            "webkit:Networking",
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
        ),
        Target(
            "blastdoor:MessagesBlastDoorService",
            "/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/Versions/A/XPCServices/MessagesBlastDoorService.xpc/Contents/MacOS/MessagesBlastDoorService",
        ),
        Target(
            "blastdoor:IDSBlastDoorService",
            "/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/Versions/A/XPCServices/IDSBlastDoorService.xpc/Contents/MacOS/IDSBlastDoorService",
        ),
        Target("apps:Safari", "/Applications/Safari.app/Contents/MacOS/Safari"),
    ]


def _record_path(path: Path, repo_root: Path) -> str:
    try:
        return to_repo_relative(path, repo_root)
    except Exception:
        return str(path)


def _target_abs_path(target_path: str, repo_root: Path) -> Path:
    path = Path(target_path)
    return path if path.is_absolute() else repo_root / path


def _codesign_entitlements_dump(path: Path, repo_root: Path, timeout_sec: int = 10) -> Dict[str, Any]:
    cmd = ["/usr/bin/codesign", "-d", "--entitlements", "-", str(path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
    # codesign writes most display output to stderr; keep both for robustness.
    combined = (proc.stderr or "") + (proc.stdout or "")

    executable: Optional[str] = None
    warnings: List[str] = []
    key_lines: List[str] = []

    for line in combined.splitlines():
        if line.startswith("Executable="):
            executable = line.split("=", 1)[1].strip()
            continue
        if line.startswith("warning:"):
            warnings.append(line.strip())
            continue
        m = re.match(r"^\s*\[Key\]\s+(.*)$", line)
        if m:
            key_lines.append(m.group(1).strip())

    keys = sorted(set(key_lines))
    message_filter_keys = sorted(k for k in keys if "message-filter" in k)
    return {
        "codesign_cmd": cmd[:-1],
        "rc": proc.returncode,
        "executable": _record_path(Path(executable), repo_root) if executable else None,
        "warnings": warnings,
        "has_entitlements_dump": bool(key_lines),
        "message_filter_keys": message_filter_keys,
        "has_message_filter": ENTITLEMENT_MESSAGE_FILTER in keys,
        "has_message_filter_manager": ENTITLEMENT_MESSAGE_FILTER_MANAGER in keys,
    }


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    repo_root = find_repo_root(Path(__file__))
    default_out = repo_root / "book/experiments/gate-witnesses/out/entitlements_scan.json"

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=str(default_out), help="Output JSON path.")
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Extra target in the form label=path (may be repeated).",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    repo_root = find_repo_root(Path(__file__))
    out_path = Path(args.out)

    targets = _default_targets()
    for item in args.target:
        if "=" not in item:
            raise SystemExit(f"--target must be label=path, got: {item!r}")
        label, path = item.split("=", 1)
        targets.append(Target(label.strip(), path.strip()))

    results: List[Dict[str, Any]] = []
    for t in targets:
        abs_path = _target_abs_path(t.path, repo_root)
        exists = abs_path.exists()
        entry: Dict[str, Any] = {"label": t.label, "path": t.path, "exists": exists}
        if exists:
            entry.update(_codesign_entitlements_dump(abs_path, repo_root))
        results.append(entry)

    payload: Dict[str, Any] = {
        "schema_version": "1.0",
        "world_id": WORLD_ID,
        "out_path": to_repo_relative(out_path, repo_root),
        "targets": results,
    }
    _write_json(out_path, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
