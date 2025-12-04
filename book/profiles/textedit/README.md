# TextEdit sandbox specialization

This directory now holds the scaffolding for “Chapter 2: TextEdit’s Sandbox Profile” plus the specialized profile artifacts.

## How to run the Chapter 2 tools

From the repo root:

- Section 2.1 capability summary:

  ```sh
  python3 profiles/textedit/tools/02.1_capability_survey.py
  ```

  Outputs: `profiles/textedit/output/02.1_capability_summary.json`.

- Section 2.2 profile/container join:

  ```sh
  python3 profiles/textedit/tools/02.2_profiles_and_containers.py
  ```

  Outputs: `profiles/textedit/output/02.2_profiles_and_containers.json`.

- Section 2.4 pattern extraction:

  ```sh
  python3 profiles/textedit/tools/02.4_pattern_extraction.py
  ```

  Outputs: `profiles/textedit/output/02.4_pattern_extraction.json`.

- Section 2.3 tracing scaffold (dry-run):

  ```sh
  profiles/textedit/tools/02.3_trace_operations.sh --dry-run
  ```

## Chapter 2 scaffolding

All `tools/02.x_*` scripts are simple analyzers, not full research pipelines; the `notes/` files capture the plan so future authors can pick up the work mid-stream. Outputs land in `profiles/textedit/output/`.

### 2.1 What TextEdit is allowed to do

- `tools/02.1_capability_survey.py` — loads `textedit-entitlements.plist` and `textedit-specialized.sb`, then emits a JSON summary of visible capabilities (printing, user-selected files, ubiquity, sandbox flag) to `output/02.1_capability_summary.json`.
- `notes/02.1-capability-survey.md` — planning notes and intended outputs for Section 2.1.

### 2.2 Profiles, containers, and entitlements in practice

- `tools/02.2_profiles_and_containers.py` — joins SBPL structure, key entitlements, and container notes; writes `output/02.2_profiles_and_containers.json`.
- `notes/02.2-profiles-containers-entitlements.md` — outline of how these will be explained in the chapter.

### 2.3 Tracing real operations through the sandbox

- `tools/02.3_trace_operations.sh` — dry-run tracing scaffold that maps UI actions to planned fs_usage/opensnoop captures; keeps placeholder traces under `traces/`.
- `notes/02.3-tracing-real-operations.md` — scenarios and trace/analysis plan.

### 2.4 What TextEdit shows us about the broader system

- `tools/02.4_pattern_extraction.py` — extracts coarse SBPL patterns (filesystem, IPC/mach, network, TCC hints) and a few “interesting rule” buckets; writes `output/02.4_pattern_extraction.json`.
- `notes/02.4-broader-system-lessons.md` — notes on general lessons (patterns, limitations, global policy).

## Profile source notes

- `textedit-specialized.sb` is a pedagogical specialization of `profiles/textedit/application.sb` using the checked-in TextEdit entitlements and container notes.
- Parameters are fixed conceptually to `application_bundle_id = "com.apple.TextEdit"` and `application_container_id = "com.apple.TextEdit"`; paths remain parameterized for portability.
- Entitlement guards (`when`/`if`/`unless`) were evaluated: TextEdit’s entitlements inline the active bodies (e.g., printing, user-selected file access) and drop the inactive ones with short comments.
- Array entitlements were expanded: the ubiquity container list produces rules for `com.apple.TextEdit`; all other entitlement arrays were omitted because TextEdit has no values for them.
- Param-guarded forms are assumed true for TextEdit and kept as-is with small “Active” comments rather than substituting concrete system paths.
- The result is meant for documentation, not a bit-for-bit clone of the live sandbox blob.
