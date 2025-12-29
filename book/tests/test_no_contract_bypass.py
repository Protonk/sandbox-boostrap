from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]

SCAN_ROOTS = [
    ROOT / "book" / "api",
    ROOT / "book" / "experiments",
    ROOT / "book" / "graph",
]

CODE_SUFFIXES = {".c", ".h", ".py", ".sh", ".swift"}

FORBIDDEN_PATTERNS = {
    "sandbox_init": re.compile(r"\bsandbox_init\s*\("),
    "sandbox_apply": re.compile(r"\bsandbox_apply\s*\("),
    "sandbox_compile_file": re.compile(r"\bsandbox_compile_file\s*\("),
    "sandbox_compile_string": re.compile(r"\bsandbox_compile_string\s*\("),
    "sandbox_exec": re.compile(r"\bsandbox-exec\b"),
}

ALLOWLIST = {
    "sandbox_init": {Path("book/api/runtime/native/tool_markers.h")},
    "sandbox_apply": set(),
    "sandbox_compile_file": {
        Path("book/api/runtime/native/tool_markers.h"),
        Path("book/api/profile_tools/c/compile_profile.c"),
        Path("book/api/profile_tools/libsandbox.py"),
        Path("book/api/profile_tools/compile/libsandbox.py"),
    },
    "sandbox_compile_string": {
        Path("book/api/runtime/native/tool_markers.h"),
        Path("book/api/profile_tools/libsandbox.py"),
        Path("book/api/profile_tools/compile/libsandbox.py"),
    },
    "sandbox_exec": {
        Path("book/api/profile_tools/libsandbox.py"),
        Path("book/api/profile_tools/compile/libsandbox.py"),
        Path("book/api/runtime/execution/harness/runner.py"),
        Path("book/graph/mappings/runtime/generate_runtime_signatures.py"),
        Path("book/experiments/shrink-trace/scripts/run_workflow.sh"),
        Path("book/experiments/shrink-trace/scripts/shrink_instrumented.sh"),
        Path("book/experiments/shrink-trace/scripts/trace_instrumented.sh"),
        Path("book/experiments/shrink-trace/upstream/shrink.sh"),
        Path("book/experiments/shrink-trace/upstream/trace.sh"),
    },
}


def _iter_code_files() -> list[Path]:
    paths: list[Path] = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.suffix in CODE_SUFFIXES:
                paths.append(path)
    return sorted(paths)


def _first_match_line(text: str, match: re.Match[str]) -> int:
    return text.count("\n", 0, match.start()) + 1


def test_no_contract_bypass_tokens():
    violations: list[str] = []
    for path in _iter_code_files():
        rel = path.relative_to(ROOT)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(errors="ignore")

        for kind, pattern in FORBIDDEN_PATTERNS.items():
            if rel in ALLOWLIST.get(kind, set()):
                continue
            match = pattern.search(text)
            if not match:
                continue
            line = _first_match_line(text, match)
            violations.append(f"{rel}:{line} contains forbidden {kind} token")

    assert not violations, "contract bypass risk:\n" + "\n".join(violations)
