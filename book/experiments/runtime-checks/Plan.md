# Runtime Checks (bucket-level behavior)

Goal: exercise compiled profiles at runtime to verify that observed allow/deny behavior matches the decoder’s bucket-level expectations (e.g., bucket-4 vs bucket-5 profiles). Publish traces under `book/graph/mappings/runtime/`.

---

## 1) Scope and setup

- [ ] Record host baseline (OS/build, SIP) in `ResearchReport.md`.
- [ ] Identify target profiles: canonical system blobs (`airlock`, `bsd`, `sample`) and representative synthetic profiles from `op-table-operation` (bucket-4 and bucket-5 cases).
- [ ] Choose harness: `sandbox-exec` with SBPL source or compiled blobs; small driver scripts for filesystem, mach, and network probes.

Deliverables: plan/notes/report in this directory; `out/` for raw traces/logs.

## 2) Define probes and expectations

- [x] For each target profile, list the operations to test (e.g., `file-read*` on `/etc/hosts`, `file-write*` to `/tmp`, `mach-lookup` on a known name, `network-outbound` to loopback).
- [ ] Use decoder outputs (bucket assignments, tag signatures) to note expected allow/deny outcomes for each probe.

Deliverables: `out/expected_matrix.json` (profile × probe → expected verdict).

## 3) Run runtime checks

- [ ] Execute probes under each target profile using the chosen harness.
- [ ] Capture logs (success/errno) and summarize verdicts.

Deliverables: `out/runtime_results.json` plus brief Notes.

## 4) Compare and guardrail

- [ ] Compare runtime results to expected matrix; investigate any mismatches.
- [ ] Add a guardrail test/script to rerun a small subset (e.g., one bucket-4 and one bucket-5 profile) to catch regressions.
- [ ] Update `ResearchReport.md` with findings, mismatches, and next steps.

Stop condition: runtime traces collected for bucket-4/bucket-5 and system profiles, with a minimal guardrail and documented alignment (or gaps) with decoder expectations.
