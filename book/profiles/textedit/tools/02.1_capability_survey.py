"""
Support tool for Section 2.1 ("What TextEdit is allowed to do").

Minimal analyzer that loads entitlements and specialized SBPL, then emits a
machine-readable capability summary.
"""
from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"


def load_entitlements(path: Path) -> Dict[str, Any]:
    """Load TextEdit's entitlements plist into a plain dict."""
    with path.open("rb") as fh:
        return plistlib.load(fh)


def summarize_entitlements(entitlements: dict) -> dict:
    """
    Group key entitlements into human- and machine-readable capability buckets
    for Section 2.1.
    """
    ubiquity_containers = entitlements.get(
        "com.apple.developer.ubiquity-container-identifiers", []
    )
    recognized_keys = {
        "com.apple.security.app-sandbox",
        "com.apple.security.print",
        "com.apple.security.files.user-selected.read-write",
        "com.apple.security.files.user-selected.executable",
        "com.apple.developer.ubiquity-container-identifiers",
        "com.apple.application-identifier",
    }

    private_entitlements = [
        key for key in entitlements.keys() if key not in recognized_keys
    ]

    return {
        "sandbox_enabled": bool(entitlements.get("com.apple.security.app-sandbox")),
        "printing": bool(entitlements.get("com.apple.security.print")),
        "user_selected_files": {
            "read_write": bool(
                entitlements.get("com.apple.security.files.user-selected.read-write")
            ),
            "executable": bool(
                entitlements.get("com.apple.security.files.user-selected.executable")
            ),
        },
        "ubiquity": {
            "enabled": bool(ubiquity_containers),
            "containers": ubiquity_containers,
        },
        "private_entitlements": sorted(private_entitlements),
    }


def summarize_specialized_sbpl(sb_text: str) -> dict:
    """
    Inspect textedit-specialized.sb to infer coarse-grained capabilities using
    simple pattern matching.
    """
    mach_lookups = re.findall(r"\bmach-lookup\b", sb_text)
    mach_service_names = re.findall(r"\bglobal-name\b", sb_text)
    mach_service_regexes = re.findall(r"\bglobal-name-regex\b", sb_text)
    mach_local_names = re.findall(r"\blocal-name\b", sb_text)
    mach_local_prefixes = re.findall(r"\blocal-name-prefix\b", sb_text)
    return {
        "filesystem": {
            "container_read_write": "appsandbox-container" in sb_text
            or "application_container" in sb_text,
            "system_read_only": "/System" in sb_text or "/usr/bin" in sb_text,
            "downloads_rules_present": "Downloads" in sb_text,
        },
        "network": {
            "has_generic_network_rules": "network" in sb_text
            or "network-outbound" in sb_text,
        },
        "ipc": {
            "mach_lookups_count": len(mach_lookups),
            "mach_services_approx": len(mach_service_names)
            + len(mach_service_regexes)
            + len(mach_local_names)
            + len(mach_local_prefixes),
        },
    }


def build_capability_summary(ent_summary: dict, sb_summary: dict) -> dict:
    """
    Merge entitlement- and SBPL-derived summaries into a single structure.
    """
    return {"entitlements": ent_summary, "sbpl": sb_summary}


def main() -> None:
    entitlements_path = BASE_DIR / "textedit-entitlements.plist"
    sbpl_path = BASE_DIR / "textedit-specialized.sb"

    entitlements = load_entitlements(entitlements_path)
    sbpl_text = sbpl_path.read_text(encoding="utf-8")

    ent_summary = summarize_entitlements(entitlements)
    sb_summary = summarize_specialized_sbpl(sbpl_text)

    capability_summary = build_capability_summary(ent_summary, sb_summary)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "02.1_capability_summary.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(capability_summary, fh, indent=2, sort_keys=True)

    print(json.dumps(capability_summary, indent=2))
    print(f"\nWrote capability summary to {output_path}")


if __name__ == "__main__":
    main()
