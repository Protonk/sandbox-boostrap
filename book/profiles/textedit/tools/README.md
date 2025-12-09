# TextEdit tooling glue

Lightweight helpers used in the TextEdit chapter to turn entitlements, SBPL, and container notes into machine-readable artifacts under `book/profiles/textedit/output/`.

- `02.1_*` scripts derive capability summaries and a human checklist for Section 2.1 using `textedit-entitlements.plist` and `textedit-specialized.sb`.
- `02.2_profiles_and_containers.py` joins SBPL structure with container notes for Section 2.2; expects `container-notes.md` to be present when run.
- `02.3_*` tracing helpers annotate filesystem/mach traces; they read from `traces/` and emit under `output/`.
- `02.4_pattern_extraction.py` distills patterns for broader lessons; uses the same `output/` staging area.

Scripts assume the Sonoma 14.4.1 artifacts already in this directory; they are not wired into the main test runner. Use them to regenerate chapter-local JSON/markdown outputs without touching graph mappings or CARTON.***
