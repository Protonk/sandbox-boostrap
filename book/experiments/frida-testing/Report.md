# frida-testing

## Purpose
Explore whether Frida-based instrumentation can provide host-bound runtime witnesses for sandbox behavior on the Sonoma 14.4.1 baseline. This experiment is exploratory; there is no host witness yet, and no claims are promoted beyond substrate theory.

## Baseline & scope
- world_id: sonoma-14.4.1-23E224-arm64-dyld-2c0602c5 (baseline: book/world/sonoma-14.4.1-23E224-arm64/world-baseline.json)
- Scope: Frida tooling, minimal probes, and runtime logs captured under this experiment.
- Out of scope: cross-version behavior, new vocabulary names, and promotion to mappings/CARTON without validation outputs.

## Deliverables / expected outcomes
- Bootstrap assets: target binary, Frida hooks, and a Python runner using the Frida API.
- Runtime logs or traces in `book/experiments/frida-testing/out/`, with repo-relative paths.
- Notes entries documenting runs, including failures or apply-stage gates.

## Plan & execution log
- Planned: verify the Frida CLI and Python bindings used by this repo's venv.
- Planned: define a minimal probe target and capture a first trace/log.
- Planned: map any observations to existing operations/filters or record as "we don't know yet".
- Completed: added a minimal target, hook scripts, and a Python runner (no Frida runs yet).

## Evidence & artifacts
- Bootstrap target: `book/experiments/frida-testing/targets/open_loop.c`.
- Bootstrap binary: `book/experiments/frida-testing/targets/open_loop`.
- Hooks: `book/experiments/frida-testing/hooks/fs_open.js` and `book/experiments/frida-testing/hooks/discover_sandbox_exports.js`.
- Runner: `book/experiments/frida-testing/run_frida.py`.
- No runtime logs yet under `book/experiments/frida-testing/out/`.

## Blockers / risks
- No blockers recorded yet; we do not know the probe shape or target until the first run.

## Next steps
- Await instructions on target process and probe shape.
- Add first-run notes and artifact links once a probe is executed.
