from __future__ import annotations

import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC_DIR = ROOT / "book" / "experiments" / "runtime-adversarial" / "out"
DST_DIR = Path(__file__).resolve().parent / "out"

# Keep local copies of the runtime-adversarial outputs that this suite summarizes.
FILES_TO_COPY = [
    "runtime_results.json",
    "expected_matrix.json",
    "mismatch_summary.json",
    "impact_map.json",
]


def main() -> None:
    DST_DIR.mkdir(exist_ok=True)

    copied = []
    missing = []

    for name in FILES_TO_COPY:
        src = SRC_DIR / name
        dst = DST_DIR / name
        if src.exists():
            shutil.copy2(src, dst)
            copied.append(dst)
        else:
            missing.append(name)

    if copied:
        print("Copied:")
        for path in copied:
            print(f"  {path}")
    else:
        print("No files copied; runtime-adversarial outputs not found.")

    if missing:
        print("Missing from source:")
        for name in missing:
            print(f"  {name}")


if __name__ == "__main__":
    main()
