"""
Inventory evidence-tier surfaces across the repo.

Phase-1 deliverable for the evidence tier overhaul: find every JSON `status`/`tier`
field, classify it (tier vs operational vs ambiguous), and record remaining
references to deprecated tier vocabulary.

Outputs:
- book/graph/concepts/validation/out/evidence_tier_inventory.json
- book/graph/concepts/validation/out/evidence_tier_inventory.md
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from book.api.path_utils import find_repo_root, to_repo_relative

ROOT = find_repo_root(Path(__file__))
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import evidence_tiers
from book.graph.concepts.validation import registry
from book.graph.concepts.validation.registry import ValidationJob

OUT_JSON = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "evidence_tier_inventory.json"
OUT_MD = ROOT / "book" / "graph" / "concepts" / "validation" / "out" / "evidence_tier_inventory.md"


def rel(path: Path) -> str:
    return to_repo_relative(path, ROOT)


LEGACY_TIER_TERMS = list(evidence_tiers.LEGACY_TIER_TERMS)

# Deprecated evidence-tier-like status strings (used to spot stale tiering-by-status).
LEGACY_EVIDENCE_STATUS_PREFIXES: tuple[str, ...] = ()
LEGACY_EVIDENCE_STATUS_VALUES = set(LEGACY_TIER_TERMS)

# Don’t recurse on the output artifacts this job produces (once they are tracked).
EXCLUDED_TRACKED_PATHS = {
    "book/graph/concepts/validation/out/evidence_tier_inventory.json",
    "book/graph/concepts/validation/out/evidence_tier_inventory.md",
}


@dataclass(frozen=True)
class JsonHit:
    path: str
    json_pointer: str
    key: str
    value: Any
    container_pointer: str
    container_keys: List[str]
    classification: str
    reason: str


@dataclass(frozen=True)
class LineHit:
    path: str
    line: int
    kind: str
    terms: List[str]
    text: str


def git_ls_files() -> List[str]:
    try:
        out = subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True)
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"git ls-files failed: {exc}")
    paths = [line.strip() for line in out.splitlines() if line.strip()]
    return [p for p in paths if p not in EXCLUDED_TRACKED_PATHS]


def encode_json_pointer(parts: List[str | int]) -> str:
    def escape(seg: str) -> str:
        return seg.replace("~", "~0").replace("/", "~1")

    out = ""
    for seg in parts:
        out += "/" + escape(str(seg))
    return out or "/"


def iter_json_hits(obj: Any, parts: List[str | int], file_path: str) -> Iterable[Tuple[List[str | int], str, Any, Dict[str, Any]]]:
    """
    Yield (path_parts, key, value, container_dict) for every key=="status" or key=="tier"
    encountered in the JSON tree.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            child_parts = [*parts, key]
            if key in {"status", "tier"}:
                yield (child_parts, key, value, obj)
            if isinstance(value, (dict, list)):
                yield from iter_json_hits(value, child_parts, file_path)
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            child_parts = [*parts, idx]
            if isinstance(value, (dict, list)):
                yield from iter_json_hits(value, child_parts, file_path)


def is_legacy_evidence_status(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value in LEGACY_EVIDENCE_STATUS_VALUES:
        return True
    return value.startswith(LEGACY_EVIDENCE_STATUS_PREFIXES)


def classify_status_hit(file_path: str, pointer: str, key: str, value: Any, container: Dict[str, Any]) -> Tuple[str, str]:
    """
    Classify a JSON status/tier hit into:
    - evidence-tier
    - operational-status
    - ambiguous

    This is a best-effort heuristic classifier for phase 1. It intentionally
    errs on the side of "ambiguous" for unknown contexts to avoid rewriting
    operational status fields in later phases.
    """
    if key == "tier":
        return ("evidence-tier", "explicit tier field")

    # Schema blocks in validation outputs often contain a "status" field that is a
    # type description ("ok|partial|..."), not a tier.
    if "/schema/" in pointer:
        return ("operational-status", "schema field definition, not evidence")

    if is_legacy_evidence_status(value):
        # This should no longer appear; flag it for migration review.
        return ("ambiguous", "deprecated evidence-tiering vocabulary in status field")

    return ("operational-status", "non-tier status value")


def scan_json(tracked_paths: List[str]) -> List[JsonHit]:
    hits: List[JsonHit] = []
    json_paths = [p for p in tracked_paths if p.endswith(".json")]
    for p in sorted(json_paths):
        path = ROOT / p
        try:
            data = json.loads(path.read_text())
        except Exception:
            # Not all *.json are guaranteed to be JSON; treat parse failures as a scan miss.
            continue

        for parts, key, value, container in iter_json_hits(data, [], p):
            pointer = encode_json_pointer(parts)
            container_pointer = encode_json_pointer(parts[:-1])
            container_keys = []
            if isinstance(container, dict):
                container_keys = sorted(str(k) for k in container.keys())[:32]
            classification, reason = classify_status_hit(p, pointer, key, value, container)
            hits.append(
                JsonHit(
                    path=p,
                    json_pointer=pointer,
                    key=key,
                    value=value,
                    container_pointer=container_pointer,
                    container_keys=container_keys,
                    classification=classification,
                    reason=reason,
                )
            )
    return sorted(hits, key=lambda h: (h.path, h.json_pointer))


def scan_lines(tracked_paths: List[str], exts: Tuple[str, ...], kind: str) -> List[LineHit]:
    terms = sorted(set(LEGACY_TIER_TERMS), key=len, reverse=True)
    term_re = re.compile("|".join(re.escape(t) for t in terms), re.IGNORECASE)
    hits: List[LineHit] = []

    for p in sorted(tracked_paths):
        if not p.endswith(exts):
            continue
        path = ROOT / p
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            if not term_re.search(line):
                continue
            found = sorted({m.group(0) for m in term_re.finditer(line)}, key=str.lower)
            snippet = line.strip()
            if len(snippet) > 300:
                snippet = snippet[:297] + "..."
            hits.append(LineHit(path=p, line=idx, kind=kind, terms=found, text=snippet))

    return hits


def scan_code_interpreters(tracked_paths: List[str]) -> List[LineHit]:
    """
    Find code sites that interpret legacy status strings (as enums or gate logic).
    """
    patterns = [
        ("ALLOWED_STATUS", re.compile(r"\bALLOWED_STATUS\b")),
        ("status_startswith_ok", re.compile(r"status.*startswith\\(.*['\\\"]ok['\\\"]\\)")),
        ("startswith_ok", re.compile(r"startswith\\(.*['\\\"]ok['\\\"]\\)")),
        ("status_in_allowed", re.compile(r"status\\s+(not\\s+)?in\\s+ALLOWED_STATUS")),
        ("legacy_literals", re.compile(r"['\\\"](ok-unchanged|ok-changed)['\\\"]")),
    ]
    hits: List[LineHit] = []
    for p in sorted(tracked_paths):
        if not (p.endswith(".py") or p.endswith(".swift")):
            continue
        path = ROOT / p
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for idx, line in enumerate(text.splitlines(), start=1):
            matched = []
            for label, rx in patterns:
                if rx.search(line):
                    matched.append(label)
            if not matched:
                continue
            snippet = line.rstrip()
            if len(snippet) > 300:
                snippet = snippet[:297] + "..."
            hits.append(LineHit(path=p, line=idx, kind="code-interpreter", terms=matched, text=snippet))
    return hits


def render_summary_md(json_hits: List[JsonHit], doc_hits: List[LineHit], code_hits: List[LineHit]) -> str:
    total = len(json_hits)
    by_class: Dict[str, int] = {}
    for h in json_hits:
        by_class[h.classification] = by_class.get(h.classification, 0) + 1

    evidence_hits = [h for h in json_hits if h.classification == "evidence-tier"]
    ambiguous_hits = [h for h in json_hits if h.classification == "ambiguous"]

    by_value: Dict[str, int] = {}
    for h in evidence_hits:
        if isinstance(h.value, str):
            by_value[h.value] = by_value.get(h.value, 0) + 1
        else:
            by_value[str(type(h.value))] = by_value.get(str(type(h.value)), 0) + 1

    doc_by_file: Dict[str, int] = {}
    for h in doc_hits:
        doc_by_file[h.path] = doc_by_file.get(h.path, 0) + 1

    code_by_file: Dict[str, int] = {}
    for h in code_hits:
        code_by_file[h.path] = code_by_file.get(h.path, 0) + 1

    lines: List[str] = []
    lines.append("# Evidence tier inventory (phase 1)")
    lines.append("")
    lines.append("This is a repo-wide inventory of legacy evidence-tier surfaces and their current operationalization.")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- JSON `status`/`tier` hits: {total}")
    for cls in sorted(by_class):
        lines.append(f"- {cls}: {by_class[cls]}")
    lines.append(f"- doc tier-term hits: {len(doc_hits)}")
    lines.append(f"- code interpreter hits: {len(code_hits)}")
    lines.append("")

    lines.append("## Evidence-tier-like JSON values (top)")
    for value, count in sorted(by_value.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        lines.append(f"- `{value}`: {count}")
    lines.append("")

    lines.append("## Ambiguous JSON hits (review)")
    if not ambiguous_hits:
        lines.append("- none")
    else:
        for h in ambiguous_hits[:50]:
            v = h.value
            if isinstance(v, str):
                v = v.replace("\n", "\\n")
            lines.append(f"- `{h.path}` `{h.json_pointer}` = `{v}` ({h.reason})")
        if len(ambiguous_hits) > 50:
            lines.append(f"- … {len(ambiguous_hits) - 50} more")
    lines.append("")

    lines.append("## Code interpreter sites (top)")
    for path, count in sorted(code_by_file.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        lines.append(f"- `{path}`: {count}")
    lines.append("")

    lines.append("## Docs using legacy tier vocabulary (top)")
    for path, count in sorted(doc_by_file.items(), key=lambda kv: (-kv[1], kv[0]))[:20]:
        lines.append(f"- `{path}`: {count}")
    lines.append("")

    return "\n".join(lines)


def run_evidence_tier_inventory_job() -> Dict[str, Any]:
    tracked = git_ls_files()
    json_hits = scan_json(tracked)
    doc_hits = scan_lines(tracked, (".md",), "doc")
    code_hits = scan_code_interpreters(tracked)

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)

    payload = {
        "metadata": {
            "job_id": "validation:evidence-tier-inventory",
            "notes": "Phase-1 inventory of evidence-tier surfaces (JSON status/tier fields) plus legacy vocabulary usage in docs/code.",
        },
        "json_hits": [h.__dict__ for h in json_hits],
        "doc_hits": [h.__dict__ for h in doc_hits],
        "code_hits": [h.__dict__ for h in code_hits],
    }
    OUT_JSON.write_text(json.dumps(payload, indent=2))
    OUT_MD.write_text(render_summary_md(json_hits, doc_hits, code_hits))

    ambiguous = sum(1 for h in json_hits if h.classification == "ambiguous")
    return {
        "status": "ok",
        "tier": "mapped",
        "inputs": ["."],
        "outputs": [rel(OUT_JSON), rel(OUT_MD)],
        "notes": f"wrote inventory; ambiguous_json_hits={ambiguous}",
        "metrics": {
            "json_hits": len(json_hits),
            "doc_hits": len(doc_hits),
            "code_hits": len(code_hits),
            "ambiguous_json_hits": ambiguous,
        },
    }


registry.register(
    ValidationJob(
        id="validation:evidence-tier-inventory",
        inputs=["."],
        outputs=[rel(OUT_JSON), rel(OUT_MD)],
        tags=["meta", "inventory"],
        description="Inventory JSON status/tier fields and legacy tier vocabulary usage.",
        example_command="python -m book.graph.concepts.validation --tag inventory --tag smoke --tag system-profiles",
        runner=run_evidence_tier_inventory_job,
    )
)
