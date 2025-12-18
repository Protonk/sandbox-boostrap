"""
Decode the compiled App Sandbox variants for entitlement-diff and emit
structural deltas (ops, literals, tag counts).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, List, Set

from book.api.profile_tools import decoder
from book.api.path_utils import find_repo_root, to_repo_relative

REPO_ROOT = find_repo_root(Path(__file__))
OUT_DIR = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "out"
OPS_VOCAB_PATH = REPO_ROOT / "book" / "graph" / "mappings" / "vocab" / "ops.json"

BASELINE = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "sb" / "build" / "appsandbox-baseline.sb.bin"
VARIANT = REPO_ROOT / "book" / "experiments" / "entitlement-diff" / "sb" / "build" / "appsandbox-network-mach.sb.bin"


def load_ops_vocab() -> Dict[int, str]:
    data = json.loads(OPS_VOCAB_PATH.read_text())
    return {int(entry["id"]): entry["name"] for entry in data.get("operations", [])}


def decode_profile(path: Path) -> Dict:
    blob = path.read_bytes()
    dec = decoder.decode_profile_dict(blob)
    dec["path"] = to_repo_relative(path, REPO_ROOT)
    return dec


def op_ids(dec: Dict) -> List[int]:
    ops = dec.get("op_table") or []
    return [idx for idx, offset in enumerate(ops) if offset]


def literal_set(dec: Dict) -> Set[str]:
    return set(dec.get("literal_strings") or [])


def literal_refs(dec: Dict) -> Set[str]:
    out: Set[str] = set()
    for node in dec.get("nodes") or []:
        for lit in node.get("literal_refs") or []:
            out.add(lit)
    return out


def tag_counts(dec: Dict) -> Dict[int, int]:
    return {int(k): int(v) for k, v in (dec.get("tag_counts") or {}).items()}


def tag_literal_refs(dec: Dict) -> Dict[int, Set[str]]:
    out: Dict[int, Set[str]] = {}
    for node in dec.get("nodes") or []:
        tag = int(node.get("tag", -1))
        refs = set(node.get("literal_refs") or [])
        if refs:
            out.setdefault(tag, set()).update(refs)
    return out


def describe_ops(ids: Iterable[int], vocab: Dict[int, str]) -> List[Dict[str, object]]:
    out = []
    for op_id in sorted(ids):
        out.append({"id": op_id, "name": vocab.get(op_id)})
    return out


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"[+] wrote {to_repo_relative(path, REPO_ROOT)}")


def main() -> int:
    vocab = load_ops_vocab()
    baseline = decode_profile(BASELINE)
    variant = decode_profile(VARIANT)

    base_ops = set(op_ids(baseline))
    var_ops = set(op_ids(variant))
    base_literals = literal_set(baseline)
    var_literals = literal_set(variant)
    base_lit_refs = literal_refs(baseline)
    var_lit_refs = literal_refs(variant)
    base_tags = tag_counts(baseline)
    var_tags = tag_counts(variant)
    base_tag_lit_refs = tag_literal_refs(baseline)
    var_tag_lit_refs = tag_literal_refs(variant)

    diff = {
        "profiles": {
            "baseline": {
                "path": baseline["path"],
                "op_count": baseline.get("op_count"),
                "node_count": baseline.get("node_count"),
                "literal_count": len(base_literals),
                "tag_counts": base_tags,
            },
            "variant": {
                "path": variant["path"],
                "op_count": variant.get("op_count"),
                "node_count": variant.get("node_count"),
                "literal_count": len(var_literals),
                "tag_counts": var_tags,
            },
        },
        "ops": {
            "added": describe_ops(var_ops - base_ops, vocab),
            "removed": describe_ops(base_ops - var_ops, vocab),
            "baseline_total": len(base_ops),
            "variant_total": len(var_ops),
        },
        "literals": {
            "added": sorted(var_literals - base_literals),
            "removed": sorted(base_literals - var_literals),
        },
        "literal_refs": {
            "added": sorted(var_lit_refs - base_lit_refs),
            "removed": sorted(base_lit_refs - var_lit_refs),
        },
        "tag_literal_refs": {
            str(tag): {
                "added": sorted(var_tag_lit_refs.get(tag, set()) - base_tag_lit_refs.get(tag, set())),
                "removed": sorted(base_tag_lit_refs.get(tag, set()) - var_tag_lit_refs.get(tag, set())),
            }
            for tag in sorted(set(base_tag_lit_refs) | set(var_tag_lit_refs))
            if var_tag_lit_refs.get(tag, set()) != base_tag_lit_refs.get(tag, set())
        },
        "tag_counts": {
            str(tag): {"baseline": base_tags.get(tag, 0), "variant": var_tags.get(tag, 0)}
            for tag in sorted(set(base_tags) | set(var_tags))
            if base_tags.get(tag, 0) != var_tags.get(tag, 0)
        },
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    write_json(OUT_DIR / "decoded_profiles.json", {"baseline": baseline, "variant": variant})
    write_json(OUT_DIR / "profile_diffs.json", diff)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
