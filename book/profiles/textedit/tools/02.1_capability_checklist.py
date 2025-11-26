"""
Helper for Section 2.5: turn capability summary JSON into a simple checklist.
"""
from __future__ import annotations

import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_PATH = BASE_DIR / "output" / "02.1_capability_summary.json"


def load_capability_summary(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def print_checklist(summary: dict) -> None:
    ent = summary.get("entitlements", {})
    print("- sandbox enabled:", ent.get("sandbox_enabled"))
    print("- printing entitlement:", ent.get("printing"))
    user_files = ent.get("user_selected_files", {})
    print("- user-selected files: read_write=", user_files.get("read_write"), "executable=", user_files.get("executable"))
    ubiquity = ent.get("ubiquity", {})
    print("- ubiquity/iCloud enabled:", ubiquity.get("enabled"), "containers:", ubiquity.get("containers"))
    private = ent.get("private_entitlements", [])
    print("- private entitlements:", ", ".join(private) if private else "(none)")


def main() -> None:
    summary = load_capability_summary(OUTPUT_PATH)
    print_checklist(summary)


if __name__ == "__main__":
    main()
