"""
Simple trace annotator for Section 2.5.

Reads a trace file and emits lines with basic SBPL/entitlement reasoning.
Intended for synthetic or lightweight traces stored under profiles/textedit/traces/.
"""
from __future__ import annotations

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
TRACES_DIR = BASE_DIR / "traces"


def annotate_line(line: str) -> str:
    """Add a short reason based on the path."""
    lower = line.lower()
    if "/documents/" in lower and "containers/com.apple.textedit" not in lower:
        reason = "# user-selected file entitlement + sandbox extension"
    elif "containers/com.apple.textedit" in lower:
        reason = "# inside app container (appsandbox-container rules)"
    else:
        reason = "# ancillary access"
    return f"{line.rstrip()}    {reason}"


def annotate_trace(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.strip().startswith("#") or not raw.strip():
            continue
        print(annotate_line(raw))


def main() -> None:
    target = TRACES_DIR / "open-existing-document_fs_usage.log"
    annotate_trace(target)


if __name__ == "__main__":
    main()
