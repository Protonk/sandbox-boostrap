#!/usr/bin/env python3
"""
SBPL apply-gate delta-debug minimizer.

This tool lives alongside the static preflight scanner in `book/tools/preflight/`.
Invoke it via `python3 book/tools/preflight/preflight.py minimize-gate ...` so
apply-gate tooling stays discoverable in one place.

Given a starting SBPL profile that is apply-gated on this host
(sandbox_init fails with EPERM), shrink it by deleting structure while
preserving the predicate:

  failure_stage == "apply" and apply_report.errno == EPERM

Outputs:
- minimal failing SBPL
- minimal passing neighbor (one deletion away, apply succeeds)

This tool is intentionally contract-driven: it runs candidates through
book/tools/sbpl/wrapper/wrapper and parses JSONL tool markers via
book.api.runtime.core.contract, rather than inferring from stderr strings.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union

REPO_ROOT = Path(__file__).resolve().parents[3]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from book.api import path_utils  # type: ignore
from book.api.runtime.core import contract as rt_contract  # type: ignore
from book.api.runtime.core import models as runtime_models  # type: ignore


EPERM = 1


# --- SBPL s-expression parsing -------------------------------------------------


@dataclass(frozen=True)
class Atom:
    value: str


@dataclass(frozen=True)
class ListExpr:
    items: Tuple["Expr", ...]


Expr = Union[Atom, ListExpr]


def _tokenize_sbpl(text: str) -> List[str]:
    """
    Tokenize SBPL into:
    - "(" and ")"
    - atoms (symbols/numbers/etc)
    - strings (including quotes and escapes)

    Supported comments:
    - ';' to end-of-line
    - '#| ... |#' block comments (best-effort)
    """

    tokens: List[str] = []
    i = 0
    in_line_comment = False
    in_block_comment = False
    n = len(text)

    while i < n:
        ch = text[i]

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
            i += 1
            continue

        if in_block_comment:
            if text.startswith("|#", i):
                in_block_comment = False
                i += 2
                continue
            i += 1
            continue

        if text.startswith("#|", i):
            in_block_comment = True
            i += 2
            continue

        if ch.isspace():
            i += 1
            continue

        if ch == ";":
            in_line_comment = True
            i += 1
            continue

        if ch in ("(", ")"):
            tokens.append(ch)
            i += 1
            continue

        if ch == '"':
            start = i
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            tokens.append(text[start:i])
            continue

        # atom
        start = i
        while i < n:
            ch2 = text[i]
            if ch2.isspace() or ch2 in ("(", ")", ";"):
                break
            if text.startswith("#|", i):
                break
            i += 1
        if start == i:
            # Defensive: avoid infinite loops on unexpected chars.
            i += 1
            continue
        tokens.append(text[start:i])

    return tokens


def _parse_expr(tokens: Sequence[str], idx: int) -> Tuple[Expr, int]:
    if idx >= len(tokens):
        raise ValueError("unexpected EOF while parsing SBPL")
    tok = tokens[idx]
    if tok == "(":
        idx += 1
        items: List[Expr] = []
        while True:
            if idx >= len(tokens):
                raise ValueError("unterminated list")
            if tokens[idx] == ")":
                idx += 1
                break
            child, idx = _parse_expr(tokens, idx)
            items.append(child)
        return ListExpr(tuple(items)), idx
    if tok == ")":
        raise ValueError("unexpected ')'")
    return Atom(tok), idx + 1


def parse_sbpl(text: str) -> List[Expr]:
    tokens = _tokenize_sbpl(text)
    exprs: List[Expr] = []
    idx = 0
    while idx < len(tokens):
        expr, idx = _parse_expr(tokens, idx)
        exprs.append(expr)
    return exprs


def render_sbpl(exprs: Sequence[Expr]) -> str:
    def _render(expr: Expr) -> str:
        if isinstance(expr, Atom):
            return expr.value
        inner = " ".join(_render(item) for item in expr.items)
        return f"({inner})"

    out = "\n".join(_render(e) for e in exprs)
    return out + ("\n" if not out.endswith("\n") else "")


def _list_operator(expr: Expr) -> Optional[str]:
    if not isinstance(expr, ListExpr) or not expr.items:
        return None
    head = expr.items[0]
    return head.value if isinstance(head, Atom) else None


def _is_version_form(expr: Expr) -> bool:
    return _list_operator(expr) == "version"


# --- Harness + contract parsing ------------------------------------------------


@dataclass(frozen=True)
class ApplyProbeOutcome:
    sbpl_sha256: str
    wrapper_rc: int
    failure_stage: Optional[str]
    failure_kind: Optional[str]
    apply_report: Optional[Dict[str, Any]]
    stderr_canonical: str
    raw_stderr: str

    @property
    def is_apply_gate_eperm(self) -> bool:
        if self.failure_stage != "apply":
            return False
        if not isinstance(self.apply_report, dict):
            return False
        return self.apply_report.get("errno") == EPERM

    @property
    def is_apply_success(self) -> bool:
        if not isinstance(self.apply_report, dict):
            return False
        return self.apply_report.get("rc") == 0

    @property
    def failure_errno(self) -> Optional[int]:
        """
        Best-effort errno associated with failure_stage.

        - apply: from apply_report.errno
        - bootstrap: from sbpl-apply exec marker errno
        """

        if self.failure_stage == "apply":
            if isinstance(self.apply_report, dict):
                err = self.apply_report.get("errno")
                return err if isinstance(err, int) else None
            return None
        if self.failure_stage == "bootstrap":
            markers = rt_contract.extract_sbpl_apply_markers(self.raw_stderr)
            for marker in markers:
                if marker.get("stage") == "exec":
                    err = marker.get("errno")
                    return err if isinstance(err, int) else None
            return None
        return None


class CandidateClass(str, enum.Enum):
    """
    Tri-state candidate classification for delta debugging.

    - gate: apply-stage EPERM (the target predicate)
    - not_gate: not an apply-stage failure (no apply gate)
    - invalid: SBPL/tooling candidate cannot be evaluated meaningfully
    """

    GATE = "gate"
    NOT_GATE = "not_gate"
    INVALID = "invalid"


def classify_outcome(outcome: ApplyProbeOutcome) -> CandidateClass:
    if outcome.is_apply_gate_eperm:
        return CandidateClass.GATE
    if outcome.failure_stage == "apply":
        return CandidateClass.INVALID
    return CandidateClass.NOT_GATE


class ApplyProbe:
    def __init__(
        self,
        wrapper_path: Path,
        command: Sequence[str],
        timeout_sec: int,
        trace_path: Optional[Path] = None,
        max_tests: Optional[int] = None,
    ):
        self.wrapper_path = wrapper_path
        self.command = list(command)
        self.timeout_sec = timeout_sec
        self.trace_path = trace_path
        self.max_tests = max_tests
        self._tests_run = 0
        self._cache: Dict[str, ApplyProbeOutcome] = {}
        self._ddmin_calls = 0

    @property
    def tests_run(self) -> int:
        return self._tests_run

    def next_ddmin_call_id(self) -> int:
        self._ddmin_calls += 1
        return self._ddmin_calls

    def _write_trace(self, record: Dict[str, Any]) -> None:
        if not self.trace_path:
            return
        self.trace_path.parent.mkdir(parents=True, exist_ok=True)
        with self.trace_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")

    def trace(self, record: Dict[str, Any]) -> None:
        self._write_trace(record)

    def run(self, sbpl_text: str, *, cache: bool = True) -> ApplyProbeOutcome:
        if self.max_tests is not None and self._tests_run >= self.max_tests:
            raise RuntimeError(f"max_tests exceeded ({self.max_tests})")

        sbpl_bytes = sbpl_text.encode("utf-8")
        sbpl_sha = hashlib.sha256(sbpl_bytes).hexdigest()
        cached = self._cache.get(sbpl_sha) if cache else None
        if cache and cached:
            return cached

        with tempfile.NamedTemporaryFile("w", suffix=".sb", delete=False) as tmp:
            tmp.write(sbpl_text)
            tmp_path = Path(tmp.name)

        full_cmd = [str(self.wrapper_path), "--preflight", "force", "--sbpl", str(tmp_path), "--"] + list(self.command)
        recorded_cmd = [
            path_utils.to_repo_relative(self.wrapper_path, REPO_ROOT),
            "--preflight",
            "force",
            "--sbpl",
            "<tmp_sbpl>",
            "--",
        ] + [str(x) for x in self.command]
        try:
            self._tests_run += 1
            proc = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                env={k: v for k, v in os.environ.items() if not k.startswith("SANDBOX_LORE_SEATBELT_")},
            )
        except subprocess.TimeoutExpired as exc:
            tmp_path.unlink(missing_ok=True)
            outcome = ApplyProbeOutcome(
                sbpl_sha256=sbpl_sha,
                wrapper_rc=124,
                failure_stage="apply",
                failure_kind="timeout",
                apply_report={"api": "sandbox_init", "rc": None, "errno": None, "errbuf": "timeout", "err_class": "unknown", "err_class_source": "tool"},
                stderr_canonical="",
                raw_stderr=str(exc),
            )
            if cache:
                self._cache[sbpl_sha] = outcome
            self._write_trace({"sbpl_sha256": sbpl_sha, "cmd": recorded_cmd, "timeout": True})
            return outcome
        except FileNotFoundError as exc:
            tmp_path.unlink(missing_ok=True)
            outcome = ApplyProbeOutcome(
                sbpl_sha256=sbpl_sha,
                wrapper_rc=127,
                failure_stage="apply",
                failure_kind="tool_missing",
                apply_report={"api": "sandbox_init", "rc": None, "errno": None, "errbuf": str(exc), "err_class": "unknown", "err_class_source": "tool"},
                stderr_canonical="",
                raw_stderr=str(exc),
            )
            if cache:
                self._cache[sbpl_sha] = outcome
            self._write_trace({"sbpl_sha256": sbpl_sha, "cmd": recorded_cmd, "tool_missing": True, "error": str(exc)})
            return outcome
        finally:
            tmp_path.unlink(missing_ok=True)

        stderr_raw = proc.stderr or ""
        upgraded = rt_contract.upgrade_runtime_result({}, stderr_raw)
        failure_stage = upgraded.get("failure_stage")
        failure_kind = upgraded.get("failure_kind")
        apply_report = upgraded.get("apply_report")
        stderr_canonical = rt_contract.strip_tool_markers(stderr_raw) or ""

        outcome = ApplyProbeOutcome(
            sbpl_sha256=sbpl_sha,
            wrapper_rc=proc.returncode,
            failure_stage=failure_stage if isinstance(failure_stage, str) else None,
            failure_kind=failure_kind if isinstance(failure_kind, str) else None,
            apply_report=apply_report if isinstance(apply_report, dict) else None,
            stderr_canonical=stderr_canonical,
            raw_stderr=stderr_raw,
        )

        if cache:
            self._cache[sbpl_sha] = outcome
        self._write_trace(
            {
                "sbpl_sha256": sbpl_sha,
                "cmd": recorded_cmd,
                "wrapper_rc": proc.returncode,
                "failure_stage": outcome.failure_stage,
                "failure_kind": outcome.failure_kind,
                "apply_report": outcome.apply_report,
            }
        )
        return outcome


# --- Delta debugging -----------------------------------------------------------


def _split_chunks(items: Sequence[Any], n: int) -> List[Tuple[int, int]]:
    """
    Split [0..len(items)) into n contiguous ranges, returning [(start,end),...].
    """

    length = len(items)
    if length == 0:
        return []
    n = max(1, min(n, length))
    base, rem = divmod(length, n)
    chunks = []
    start = 0
    for i in range(n):
        size = base + (1 if i < rem else 0)
        end = start + size
        chunks.append((start, end))
        start = end
    return chunks


def ddmin(
    items: List[Any],
    test: Callable[[List[Any]], CandidateClass],
    *,
    trace: Optional[Callable[[Dict[str, Any]], None]] = None,
    trace_context: Optional[Dict[str, Any]] = None,
) -> List[Any]:
    """
    Zeller-style ddmin for ordered lists.
    """

    if test(list(items)) != CandidateClass.GATE:
        raise ValueError("ddmin called with a non-failing starting set")

    n = 2
    current = list(items)
    iteration = 0
    while len(current) >= 2:
        iteration += 1
        reduced = False
        gate_count = 0
        not_gate_count = 0
        invalid_count = 0
        tested = 0
        for start, end in _split_chunks(current, n):
            candidate = current[:start] + current[end:]
            tested += 1
            outcome = test(candidate)
            if outcome == CandidateClass.GATE:
                gate_count += 1
                current = candidate
                n = max(2, n - 1)
                reduced = True
                break
            if outcome == CandidateClass.INVALID:
                invalid_count += 1
            else:
                not_gate_count += 1
        if trace:
            record = {
                "type": "ddmin_iteration",
                "iteration": iteration,
                "n": n,
                "current_len": len(current),
                "tested": tested,
                "gate": gate_count,
                "not_gate": not_gate_count,
                "invalid": invalid_count,
                "reduced": reduced,
            }
            if trace_context:
                record.update(trace_context)
            trace(record)
        if reduced:
            continue
        if n >= len(current):
            break
        n = min(len(current), n * 2)
    return current


# --- Tree editing helpers ------------------------------------------------------


PathT = Tuple[int, ...]  # (form_idx, child_idx, child_idx, ...)


def _iter_list_paths(expr: Expr, prefix: PathT = ()) -> Iterable[PathT]:
    if not isinstance(expr, ListExpr):
        return
    yield prefix
    for idx, child in enumerate(expr.items):
        yield from _iter_list_paths(child, prefix + (idx,))


def iter_profile_list_paths(forms: Sequence[Expr]) -> Iterable[PathT]:
    for i, form in enumerate(forms):
        for path in _iter_list_paths(form, (i,)):
            yield path


def get_at_path(forms: Sequence[Expr], path: PathT) -> Expr:
    if not path:
        raise ValueError("empty path")
    expr: Expr = forms[path[0]]
    for idx in path[1:]:
        if not isinstance(expr, ListExpr):
            raise ValueError("path walked into non-list")
        expr = expr.items[idx]
    return expr


def replace_at_path(forms: Sequence[Expr], path: PathT, replacement: Expr) -> List[Expr]:
    if not path:
        raise ValueError("empty path")

    def _replace(expr: Expr, subpath: Tuple[int, ...], repl: Expr) -> Expr:
        if not subpath:
            return repl
        if not isinstance(expr, ListExpr):
            raise ValueError("cannot descend into non-list")
        idx = subpath[0]
        items = list(expr.items)
        items[idx] = _replace(items[idx], subpath[1:], repl)
        return ListExpr(tuple(items))

    forms_list = list(forms)
    root_idx = path[0]
    forms_list[root_idx] = _replace(forms_list[root_idx], path[1:], replacement)
    return forms_list


def delete_child_at_path(forms: Sequence[Expr], path: PathT, child_index: int) -> List[Expr]:
    expr = get_at_path(forms, path)
    if not isinstance(expr, ListExpr):
        raise ValueError("path is not a list")
    items = list(expr.items)
    if child_index < 0 or child_index >= len(items):
        raise IndexError("child_index out of range")
    del items[child_index]
    return replace_at_path(forms, path, ListExpr(tuple(items)))


# --- Minimization strategy -----------------------------------------------------


def frozen_prefix_len(expr: ListExpr) -> int:
    op = _list_operator(expr)
    if op in {"allow", "deny"}:
        return 2 if len(expr.items) >= 2 else 1
    if op in {"import", "include"}:
        return 2 if len(expr.items) >= 2 else 1
    if op == "version":
        return len(expr.items)
    return 1


def min_arity(expr: ListExpr) -> int:
    op = _list_operator(expr)
    if op in {"allow", "deny", "version", "import", "include", "require-any", "require-all", "require-not", "param"}:
        return 2
    return 1


def minimize_top_level_forms(forms: List[Expr], probe: ApplyProbe) -> List[Expr]:
    version_forms = [f for f in forms if _is_version_form(f)]
    others = [f for f in forms if not _is_version_form(f)]

    ddmin_call_id = probe.next_ddmin_call_id()

    def test_candidate(candidate_others: List[Expr]) -> CandidateClass:
        sbpl = render_sbpl(version_forms + candidate_others)
        return classify_outcome(probe.run(sbpl))

    if test_candidate(list(others)) != CandidateClass.GATE:
        raise RuntimeError("input SBPL does not satisfy apply-gate EPERM predicate (cannot minimize)")

    minimized = ddmin(
        list(others),
        test_candidate,
        trace=probe.trace,
        trace_context={"ddmin_context": "top_level_forms", "ddmin_call_id": ddmin_call_id},
    )
    return version_forms + minimized


def minimize_list_tail_at_path(forms: List[Expr], path: PathT, probe: ApplyProbe) -> List[Expr]:
    expr = get_at_path(forms, path)
    if not isinstance(expr, ListExpr):
        return forms
    if _list_operator(expr) == "version":
        return forms

    frozen = frozen_prefix_len(expr)
    min_len = min_arity(expr)
    if len(expr.items) <= max(frozen, min_len):
        return forms

    prefix = list(expr.items[:frozen])
    tail = list(expr.items[frozen:])

    ddmin_call_id = probe.next_ddmin_call_id()

    def test_tail(candidate_tail: List[Expr]) -> CandidateClass:
        if len(prefix) + len(candidate_tail) < min_len:
            return CandidateClass.INVALID
        new_expr = ListExpr(tuple(prefix + candidate_tail))
        new_forms = replace_at_path(forms, path, new_expr)
        sbpl = render_sbpl(new_forms)
        return classify_outcome(probe.run(sbpl))

    # If removing everything fails arity checks, ddmin will keep some.
    if test_tail(list(tail)) != CandidateClass.GATE:
        return forms

    minimized_tail = ddmin(
        list(tail),
        test_tail,
        trace=probe.trace,
        trace_context={
            "ddmin_context": "list_tail",
            "ddmin_call_id": ddmin_call_id,
            "path": list(path),
            "operator": _list_operator(expr),
        },
    )
    new_expr = ListExpr(tuple(prefix + minimized_tail))
    return replace_at_path(forms, path, new_expr)


def minimize_profile(forms: List[Expr], probe: ApplyProbe) -> List[Expr]:
    """
    Coarse-to-fine minimization:
    1) ddmin top-level forms
    2) repeatedly minimize tails of all list expressions until fixpoint
    """

    reduced = minimize_top_level_forms(forms, probe)

    changed = True
    while changed:
        changed = False
        for path in list(iter_profile_list_paths(reduced)):
            before = reduced
            try:
                reduced = minimize_list_tail_at_path(reduced, path, probe)
            except Exception:
                reduced = before
            if reduced != before:
                changed = True
                break

    # Final sanity
    final_outcome = probe.run(render_sbpl(reduced))
    if not final_outcome.is_apply_gate_eperm:
        raise RuntimeError("internal error: minimized profile no longer apply-gated EPERM")
    return reduced


@dataclass(frozen=True)
class NeighborCandidate:
    sbpl: str
    deletion: Dict[str, Any]
    outcome: ApplyProbeOutcome


def find_passing_neighbor(forms: List[Expr], probe: ApplyProbe) -> Optional[NeighborCandidate]:
    """
    Find a one-deletion neighbor that is not apply-gated.

    The neighbor is chosen by minimal rendered SBPL length (tie-breaker: first found).
    """

    best: Optional[NeighborCandidate] = None

    def consider(candidate_forms: List[Expr], deletion: Dict[str, Any]) -> None:
        nonlocal best
        sbpl = render_sbpl(candidate_forms)
        outcome = probe.run(sbpl)
        if classify_outcome(outcome) != CandidateClass.NOT_GATE:
            return
        cand = NeighborCandidate(sbpl=sbpl, deletion=deletion, outcome=outcome)
        if best is None or len(cand.sbpl) < len(best.sbpl):
            best = cand

    # Top-level deletions
    for i, form in enumerate(forms):
        if _is_version_form(form):
            continue
        candidate = list(forms[:i] + forms[i + 1 :])
        if not candidate:
            continue
        consider(candidate, {"kind": "delete_top_level_form", "form_index": i, "operator": _list_operator(form)})

    # Nested deletions: remove one child from any list expr, respecting basic arity.
    for path in iter_profile_list_paths(forms):
        expr = get_at_path(forms, path)
        if not isinstance(expr, ListExpr):
            continue
        op = _list_operator(expr)
        if op == "version":
            continue
        min_len = min_arity(expr)
        if len(expr.items) <= min_len:
            continue
        frozen = frozen_prefix_len(expr)
        for child_idx in range(frozen, len(expr.items)):
            if len(expr.items) - 1 < min_len:
                continue
            candidate = delete_child_at_path(forms, path, child_idx)
            consider(
                candidate,
                {
                    "kind": "delete_list_child",
                    "path": list(path),
                    "operator": op,
                    "child_index": child_idx,
                },
            )

    return best


# --- CLI ----------------------------------------------------------------------


def _load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _confirm_distribution(probe: ApplyProbe, sbpl_text: str, runs: int) -> Dict[str, Any]:
    dist: Dict[Tuple[Optional[str], Optional[int]], int] = {}
    bootstrap_exec_deny = 0
    apply_gate = 0
    not_gate = 0
    invalid = 0

    for _ in range(runs):
        outcome = probe.run(sbpl_text, cache=False)
        stage = outcome.failure_stage
        err = outcome.failure_errno
        dist[(stage, err)] = dist.get((stage, err), 0) + 1

        cls = classify_outcome(outcome)
        if cls == CandidateClass.GATE:
            apply_gate += 1
        elif cls == CandidateClass.NOT_GATE:
            not_gate += 1
        else:
            invalid += 1

        if outcome.failure_kind == "bootstrap_deny_process_exec":
            bootstrap_exec_deny += 1

    distribution = [
        {"failure_stage": stage, "errno": err, "count": count}
        for (stage, err), count in sorted(dist.items(), key=lambda kv: (str(kv[0][0]), kv[0][1] or -1))
    ]
    return {
        "runs": runs,
        "distribution": distribution,
        "apply_gate_eperm": apply_gate,
        "not_apply_gate": not_gate,
        "invalid": invalid,
        "bootstrap_deny_process_exec": bootstrap_exec_deny,
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Delta-debug SBPL apply gating (EPERM) into minimal failing + passing neighbor.")
    ap.add_argument("--input", required=True, type=Path, help="Path to starting SBPL profile (must be apply-gated EPERM).")
    ap.add_argument("--out-dir", required=True, type=Path, help="Output directory (repo-relative preferred).")
    ap.add_argument("--wrapper", type=Path, default=Path("book/tools/sbpl/wrapper/wrapper"), help="Path to SBPL-wrapper binary.")
    ap.add_argument("--command", nargs="+", default=["/usr/bin/true"], help="Command executed after apply (default: /usr/bin/true).")
    ap.add_argument("--timeout-sec", type=int, default=5, help="Per-run timeout in seconds.")
    ap.add_argument("--max-tests", type=int, default=None, help="Optional cap on apply tests to prevent runaway minimization.")
    ap.add_argument("--confirm", type=int, default=0, help="Rerun minimal failing + neighbor N times to confirm determinism (fresh processes).")
    args = ap.parse_args(argv)
    argv_effective = list(sys.argv[1:] if argv is None else argv)

    repo_root = path_utils.find_repo_root(Path(__file__))
    in_path = path_utils.ensure_absolute(args.input, repo_root)
    out_dir = path_utils.ensure_absolute(args.out_dir, repo_root)
    wrapper_path = path_utils.ensure_absolute(args.wrapper, repo_root)
    out_dir.mkdir(parents=True, exist_ok=True)

    trace_path = out_dir / "trace.jsonl"
    trace_path.write_text("", encoding="utf-8")
    probe = ApplyProbe(
        wrapper_path=wrapper_path,
        command=args.command,
        timeout_sec=args.timeout_sec,
        trace_path=trace_path,
        max_tests=args.max_tests,
    )

    original_text = _load_text(in_path)
    try:
        forms = parse_sbpl(original_text)
    except Exception as exc:
        raise SystemExit(f"failed to parse SBPL input: {exc}")

    initial_outcome = probe.run(render_sbpl(forms))
    if not initial_outcome.is_apply_gate_eperm:
        print(
            json.dumps(
                {
                    "error": "input profile is not apply-gated EPERM (cannot minimize)",
                    "input": path_utils.to_repo_relative(in_path, repo_root),
                    "world_id": runtime_models.WORLD_ID,
                    "outcome": dataclasses.asdict(initial_outcome),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return 2

    minimized_forms = minimize_profile(list(forms), probe)
    minimal_failing = render_sbpl(minimized_forms)
    neighbor = find_passing_neighbor(minimized_forms, probe)

    (out_dir / "minimal_failing.sb").write_text(minimal_failing, encoding="utf-8")
    if neighbor:
        (out_dir / "passing_neighbor.sb").write_text(neighbor.sbpl, encoding="utf-8")

    confirm = None
    if args.confirm and args.confirm > 0:
        confirm = {
            "minimal_failing": _confirm_distribution(probe, minimal_failing, args.confirm),
            "passing_neighbor": None if neighbor is None else _confirm_distribution(probe, neighbor.sbpl, args.confirm),
        }

    run_doc = {
        "world_id": runtime_models.WORLD_ID,
        "argv": argv_effective,
        "runtime_contract": {
            "runtime_result_schema_version": rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION,
            "tool_marker_schema_version": rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION,
            "sbpl_apply_marker_schema_version": rt_contract.CURRENT_SBPL_APPLY_MARKER_SCHEMA_VERSION,
            "seatbelt_callout_marker_schema_version": rt_contract.CURRENT_SEATBELT_CALLOUT_MARKER_SCHEMA_VERSION,
        },
        "tool": {
            "path": path_utils.to_repo_relative(Path(__file__).resolve(), repo_root),
            "sha256": _sha256_path(Path(__file__).resolve()),
        },
        "input": path_utils.to_repo_relative(in_path, repo_root),
        "input_sha256": _sha256_path(in_path) if in_path.exists() else None,
        "wrapper": path_utils.to_repo_relative(wrapper_path, repo_root),
        "wrapper_sha256": _sha256_path(wrapper_path) if wrapper_path.exists() else None,
        "command": args.command,
        "timeout_sec": args.timeout_sec,
        "max_tests": args.max_tests,
        "confirm_runs": args.confirm,
        "tests_run": probe.tests_run,
        "initial_outcome": dataclasses.asdict(initial_outcome),
        "minimal_failing_outcome": dataclasses.asdict(probe.run(minimal_failing)),
        "passing_neighbor": None
        if neighbor is None
        else {
            "deletion": neighbor.deletion,
            "outcome": dataclasses.asdict(neighbor.outcome),
        },
        "confirm": confirm,
    }
    (out_dir / "run.json").write_text(json.dumps(run_doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"[+] wrote {path_utils.to_repo_relative(out_dir / 'minimal_failing.sb', repo_root)}")
    if neighbor:
        print(f"[+] wrote {path_utils.to_repo_relative(out_dir / 'passing_neighbor.sb', repo_root)}")
    print(f"[+] wrote {path_utils.to_repo_relative(out_dir / 'run.json', repo_root)}")
    print(f"[+] wrote {path_utils.to_repo_relative(trace_path, repo_root)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
