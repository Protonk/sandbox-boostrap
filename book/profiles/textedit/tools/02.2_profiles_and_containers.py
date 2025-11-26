"""
Support tool for Section 2.2 ("Profiles, containers, and entitlements in practice").

Minimal analyzer that joins SBPL structure, entitlements, and container notes.
"""
from __future__ import annotations

import json
import plistlib
from pathlib import Path
from typing import Any, Dict

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"


def load_entitlements(path: Path) -> Dict[str, Any]:
    """Load TextEdit's entitlements plist into a plain dict."""
    with path.open("rb") as fh:
        return plistlib.load(fh)


def parse_container_notes(path: Path) -> Dict[str, object]:
    """
    Parse container-notes.md to extract container root and subdirectories.

    Expected patterns (lightweight heuristics):
    - Lines starting with 'container_root = <path>'
    - Bulleted lines (leading '-' or '*') listing known subdirectories
    """
    container_root = None
    known_subdirs = []

    if not path.exists():
        return {"container_root": container_root, "known_subdirs": known_subdirs}

    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("container_root"):
            _, _, value = line.partition("=")
            container_root = value.strip()
        elif line.startswith(("-", "*")):
            known_subdirs.append(line.lstrip("-* ").strip())
        elif "subdir" in line.lower():
            known_subdirs.append(line)

    return {"container_root": container_root, "known_subdirs": known_subdirs}


def summarize_profile_structure(sb_text: str) -> Dict[str, bool]:
    """
    Identify major structural elements in textedit-specialized.sb relevant to
    Section 2.2.
    """
    return {
        "has_appsandbox_container_macros": "appsandbox-container" in sb_text,
        "has_dyld_path_rules": "application_dyld_paths" in sb_text,
        "has_bundle_param_rules": "application_bundle" in sb_text
        or "application_bundle_id" in sb_text,
        "has_application_container_rules": "application_container" in sb_text
        or "application_container_id" in sb_text,
    }


def build_join(entitlements: dict, profile_summary: dict, container_info: dict) -> dict:
    """
    Build a high-level joined view for Section 2.2 explanations.
    """
    relevant_entitlements = {
        "app_sandbox": bool(entitlements.get("com.apple.security.app-sandbox")),
        "printing": bool(entitlements.get("com.apple.security.print")),
        "user_selected_files": {
            "read_write": bool(
                entitlements.get("com.apple.security.files.user-selected.read-write")
            ),
            "executable": bool(
                entitlements.get("com.apple.security.files.user-selected.executable")
            ),
        },
        "ubiquity_containers": entitlements.get(
            "com.apple.developer.ubiquity-container-identifiers", []
        ),
    }

    return {
        "bundle_id": entitlements.get("com.apple.application-identifier"),
        "container_root": container_info.get("container_root"),
        "container_subdirs": container_info.get("known_subdirs", []),
        "has_app_sandbox": relevant_entitlements["app_sandbox"],
        "profile": profile_summary,
        "entitlements": relevant_entitlements,
    }


def format_human_shape(joined: dict) -> str:
    """Format a concise sandbox shape for CLI output."""
    container = joined.get("container_root")
    profile_flags = joined.get("profile", {})
    flags = [
        f"container_macros={profile_flags.get('has_appsandbox_container_macros')}",
        f"dyld_rules={profile_flags.get('has_dyld_path_rules')}",
        f"bundle_params={profile_flags.get('has_bundle_param_rules')}",
    ]
    ent = joined.get("entitlements", {})
    caps = [
        f"printing={ent.get('printing')}",
        f"user_selected_rw={ent.get('user_selected_files', {}).get('read_write')}",
        f"ubiquity={bool(ent.get('ubiquity_containers'))}",
    ]
    return (
        f"{joined.get('bundle_id')} -> container={container} | "
        f"flags[{', '.join(flags)}] | caps[{', '.join(caps)}]"
    )


def main() -> None:
    entitlements_path = BASE_DIR / "textedit-entitlements.plist"
    sbpl_path = BASE_DIR / "textedit-specialized.sb"
    container_notes_path = BASE_DIR / "container-notes.md"

    entitlements = load_entitlements(entitlements_path)
    sbpl_text = sbpl_path.read_text(encoding="utf-8")
    container_info = parse_container_notes(container_notes_path)
    profile_summary = summarize_profile_structure(sbpl_text)

    joined = build_join(entitlements, profile_summary, container_info)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT_DIR / "02.2_profiles_and_containers.json"
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(joined, fh, indent=2, sort_keys=True)

    human_summary = {
        "bundle_id": joined["bundle_id"],
        "container_root": joined["container_root"],
        "has_app_sandbox": joined["has_app_sandbox"],
        "container_subdirs_count": len(joined["container_subdirs"]),
        "profile_flags": joined["profile"],
    }
    print(json.dumps(human_summary, indent=2))
    print("\nShape:", format_human_shape(joined))
    print(f"\nWrote profile/container join to {output_path}")


if __name__ == "__main__":
    main()
