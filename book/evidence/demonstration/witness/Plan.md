# witness demonstration (Plan)

Baseline: `world_id sonoma-14.4.1-23E224-arm64-dyld-a3a840f9`.

## Goal

Produce a clear, stateless demonstration of keepalive + attach capabilities for PolicyWitness,
with explicit prerequisites, commands, and expected outputs. This plan file is temporary and
should be deleted once the demo is settled.

## Plan (to execute now)

1) Draft `DEMO.md` with:
   - Scope and baseline.
   - Prereqs (venv, PolicyWitness app, build + sign helpers).
   - Demonstration runs:
     - hold_open + Frida attach via keepalive (oracle lane).
     - PolicyWitness attach-first (injectable variant).
     - Negative control (base variant).
     - sandbox_check oracle cross-check (sb_api_validator).
     - Repeatability pass.
   - Expected artifacts and how to interpret them.
   - Known failure modes, limits, and an explicit stretch goal not yet achieved.
2) Ensure all paths are repo-relative and runtime statements include stage + lane.
3) Mark this plan complete.

## Completion checklist

- [x] `DEMO.md` written and comprehensive.
- [x] Runtime stage/lane tags included where claims are made.
- [x] Known limits and stretch goal documented.

## Status

Complete. This plan file can be deleted once the demo is accepted.
