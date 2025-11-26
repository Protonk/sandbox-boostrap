"""
Support tool for Section 2.4 ("What TextEdit shows us about the broader system").

Minimal analyzer that extracts coarse patterns and interesting rules from the
specialized SBPL.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"


def extract_common_patterns(sb_text: str) -> Dict[str, object]:
    """
    Identify high-level patterns that are likely common to many sandboxed apps.
    """
    mach_services = re.findall(r'global-name\s+"([^"]+)"', sb_text)
    local_mach_services = re.findall(r'local-name\s+"([^"]+)"', sb_text)
    all_mach_services: List[str] = mach_services + local_mach_services

    return {
        "filesystem_patterns": {
            "has_container_macros": "appsandbox-container" in sb_text
            or "application_container" in sb_text,
            "has_system_read_only": "/System" in sb_text or "/usr/bin" in sb_text,
            "has_home_library_allows": "/Library/" in sb_text,
        },
        "ipc_patterns": {
            "mach_lookups_total": len(re.findall(r"\bmach-lookup\b", sb_text)),
            "mach_services_examples": sorted(set(all_mach_services))[:10],
        },
        "network_patterns": {
            "has_network_star": "network*" in sb_text or "network-outbound" in sb_text,
            "has_specific_denies": "usbmuxd" in sb_text or "localhost:631" in sb_text,
        },
        "tcc_policy_hints": {
            "mentions_tccd": "tccd" in sb_text,
            "mentions_ocspd": "ocspd" in sb_text,
        },
    }


def identify_surprising_or_narrow_rules(sb_text: str) -> Dict[str, object]:
    """
    Heuristically identify interesting or special-case rules.
    """
    lines = sb_text.splitlines()
    carve_out_denies = [ln for ln in lines if "(deny" in ln and ("subpath" in ln or "regex" in ln)]
    keychain_rules = [ln for ln in lines if "/Library/Keychains" in ln]
    mds_rules = [ln for ln in lines if "/private/var/db/mds" in ln]
    appstore_rules = [ln for ln in lines if "/Library/Application Support/AppStore" in ln]

    return {
        "carve_out_denies": carve_out_denies[:10],
        "keychain_rules": keychain_rules[:10],
        "mds_rules": mds_rules[:10],
        "appstore_rules": appstore_rules[:10],
    }


def load_specialized_sbpl() -> str:
    sbpl_path = BASE_DIR / "textedit-specialized.sb"
    return sbpl_path.read_text(encoding="utf-8")


def main() -> None:
    sbpl_text = load_specialized_sbpl()
    patterns = extract_common_patterns(sbpl_text)
    surprises = identify_surprising_or_narrow_rules(sbpl_text)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "02.4_pattern_extraction.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump({"common_patterns": patterns, "surprises": surprises}, fh, indent=2, sort_keys=True)

    summary = {
        "mach_services_examples": patterns["ipc_patterns"]["mach_services_examples"],
        "carve_out_denies_count": len(surprises["carve_out_denies"]),
    }
    print(json.dumps(summary, indent=2))
    print(f"\nWrote pattern extraction output to {output_path}")


if __name__ == "__main__":
    main()
