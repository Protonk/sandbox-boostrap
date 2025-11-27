# Handoff

- **Plan + clusters:** `book/concepts/CONCEPT_INVENTORY.md` (Process stages 0–6).
- **Example mappings:** `book/concepts/EXAMPLES.md` (examples ↔ clusters).
- **Concept map:** `book/concepts/validation/Concept_map.md` (verbatim definitions + clusters).
- **Validation tasks:** `book/concepts/validation/tasks.py` (per-cluster tasks → examples → expected artifacts); helper `list_tasks()` prints a summary.
- **Harness notes:** `book/concepts/validation/README.md` (intended workflow; keep scripts under `book/concepts/validation/`).
- **Metadata collected:** `book/concepts/validation/out/metadata.json` (OS 14.4.1 build 23E224, arm64, SIP enabled; TCC/variant not collected).
- **Ingestion spine:** `book/concepts/validation/profile_ingestion.py` (minimal, variant-tolerant; recognizes legacy decision-tree headers, otherwise returns “unknown-modern” with full blob available for inspection).
- **Static outputs so far:** `validation/out/static/sample.sb.json` (from `book/examples/sb`) and `validation/out/static/system_profiles.json` (airlock.sb.bin, bsd.sb.bin from `extract_sbs` via ingestion helper); section lengths are placeholder for unknown-modern formats.
- **Semantic outputs so far:** `validation/out/semantic/metafilter.jsonl` (sandbox-exec runs: all cases returned exit 71/denied; expected allows did not succeed on this host), `validation/out/semantic/sbpl_params.jsonl` (both param/no-param runs exited 65; params likely unsupported), `validation/out/semantic/network.jsonl` (AF_INET/AF_UNIX probes all denied with EPERM), `validation/out/semantic/mach_services.jsonl` and write-up `validation/out/semantic/mach_services.md` (bootstrap_not_privileged failures).
- **Lifecycle outputs so far:** `validation/out/lifecycle/entitlements.json` (unsigned run), `validation/out/lifecycle/extensions_dynamic.md` (crash notes).
- **Pending/failed probes:** `extensions-dynamic` still crashes; `mach-services` blocked; vocab tables not generated; entitlements example only run unsigned.

## Blockers and Resolutions (in progress)

- `extensions-dynamic`: `extensions_demo` still crashes with `Sandbox(Signal 11)` even after guarding null tokens. lldb could not attach (process exits immediately); dtruss blocked by SIP. Python/ctypes calls show `sandbox_extension_issue_file` returning `rc=0` with `token=NULL` for both protected (`/private/var/db/ConfigurationProfiles`) and `/tmp`, suggesting libsandbox may return success with null tokens for unentitled callers. Captured notes in `validation/out/lifecycle/extensions_dynamic.md`. Resolution pending (needs debugger with SIP disabled, different target, or mock issuance).
- `entitlements-evolution`: fixed buffer (added limits.h, sane path buffer); now builds and runs, logging unsigned metadata. Output captured in `validation/out/lifecycle/entitlements.json`. For full coverage, rerun with signed builds to see entitlement payloads.
- `mach-services`: compiled after falling back to `bootstrap_register`; registration failed with `kr=0x44c` (BOOTSTRAP_NOT_PRIVILEGED), and client lookups for demo/system services also returned `0x44c`. Logs in `validation/out/semantic/mach_services.jsonl` and notes in `validation/out/semantic/mach_services.md`. Likely blocked by platform/bootstrap policy; would need an allowed service name or different launch context.
- Vocab/lifecycle logs: vocab not generated yet because ingestion of modern blobs is minimal; lifecycle logs captured for entitlements; extensions remain pending due to crash.

## For the next agent

- **Repo state / key files**
  - Plan: `book/concepts/CONCEPT_INVENTORY.md` (Process stages 0–6).
  - Example→cluster map: `book/concepts/EXAMPLES.md`.
  - Concept map: `book/concepts/validation/Concept_map.md`.
  - Task map: `book/concepts/validation/tasks.py`; harness notes in `book/concepts/validation/README.md`.
  - Handoff summary: this file.
  - Ingestion spine: `book/concepts/validation/profile_ingestion.py` (minimal: detects legacy decision-tree, otherwise “unknown-modern”).
  - Ingestion helper: `book/concepts/validation/ingest_blob.py`.

- **Environment**
  - macOS 14.4.1 (23E224), arm64, SIP enabled; TCC state not collected.

- **Outputs so far**
  - Static: `validation/out/static/sample.sb.json` (from `book/examples/sb`), `validation/out/static/system_profiles.json` (airlock/bsd from `extract_sbs`).
  - Semantic: `validation/out/semantic/metafilter.jsonl` (all denied), `sbpl_params.jsonl` (params unsupported), `network.jsonl` (AF_INET/UNIX EPERM), `mach_services.jsonl` and write-up `mach_services.md` (bootstrap_not_privileged failures).
  - Lifecycle: `validation/out/lifecycle/entitlements.json` (unsigned run), `extensions_dynamic.md` (crash notes).
  - Metadata: `validation/out/metadata.json` (OS/build).

- **Known blockers / unresolved**
  - `extensions-dynamic`: crashes with `Sandbox(Signal 11)` even with null-token guards. libsandbox returns `rc=0`, `token=NULL` for issue calls. Could need SIP-disabled debugging, different target, or mocked issuance.
  - `mach-services`: registration and lookups fail with kr=0x44c (BOOTSTRAP_NOT_PRIVILEGED). Likely bootstrap policy; may require a whitelisted service, different launch context, or per-user launchd plist.
  - Vocab tables not generated (ingestion for modern blobs is minimal; no op/node counts). If richer vocab needed, beef up parser.
  - Entitlements probe only run unsigned; rerun signed to capture entitlement payloads.
  - Semantic logs show unexpected denials (metafilter, params) due to host environment/sandbox-exec behavior; may need profiling or alternative harness.

- **Immediate next steps**
  1) Decide whether to enhance `profile_ingestion.py` to parse modern graph-based blobs (headers/op tables/node counts) for better vocab extraction.
  2) Generate vocab tables from ingested blobs and cross-check semantic logs.
  3) Debug `extensions_demo` crash (lldb with SIP off, change target path/extension class, or stub issuance to avoid libsandbox crash).
  4) Retry mach services with allowed service name or launchd context; capture successful registration/lookup if possible.
  5) Rerun entitlements example with signed variants; log outputs.

All supporting notes and logs live under `book/concepts/validation/out/`.
