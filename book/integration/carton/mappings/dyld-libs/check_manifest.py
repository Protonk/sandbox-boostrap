#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict

REPO_ROOT = Path(__file__).resolve().parents[5]
MANIFEST = REPO_ROOT / "book" / "integration" / "carton" / "bundle" / "relationships" / "mappings" / "dyld-libs" / "manifest.json"


def load_manifest() -> Dict:
    if not MANIFEST.exists():
        raise SystemExit(f"missing manifest: {MANIFEST}")
    return json.loads(MANIFEST.read_text())


def sha256_hex(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def nm_symbols(path: Path) -> Dict[str, str]:
    out = subprocess.check_output(["nm", str(path)], text=True)
    symmap: Dict[str, str] = {}
    for line in out.splitlines():
        m = re.match(r"([0-9a-fA-F]+)\s+[A-Za-z]\s+(\S+)", line)
        if not m:
            continue
        addr, name = m.groups()
        symmap[name] = "0x" + addr.lower()
    return symmap


def check_entry(entry: Dict) -> None:
    path = REPO_ROOT / entry["path"]
    assert path.exists(), f"missing dyld slice: {path}"
    size = path.stat().st_size
    digest = sha256_hex(path)
    assert size == entry["size"], f"size mismatch for {path}: {size} != {entry['size']}"
    assert digest == entry["sha256"], f"sha mismatch for {path}: {digest} != {entry['sha256']}"
    expected_syms: Dict[str, str] = entry.get("symbols") or {}
    actual_syms = nm_symbols(path)
    for name, addr in expected_syms.items():
        actual = actual_syms.get(name)
        assert actual, f"symbol {name} missing in {path}"
        assert actual == addr, f"symbol {name} addr mismatch in {path}: {actual} != {addr}"


def main() -> int:
    manifest = load_manifest()
    for entry in manifest.get("libs") or []:
        check_entry(entry)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
