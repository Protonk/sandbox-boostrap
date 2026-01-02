# looking-glass — CARTON_AND_GUARDRAILS (freeze, verify, notice drift)

This bundle describes the repo’s “don’t let it quietly rot” layer: CARTON (the frozen query bundle) and the integration guardrails that enforce invariants across concepts, mappings, and tool wiring.

Scope: integration-time contracts and drift detection. It does **not** explain how to produce new mappings or runtime evidence (see `GRAPH_AND_MAPPINGS.md` and `RUNTIME_AND_WITNESS_TOOLCHAIN.md`).

Baseline anchor: `world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`.

## 1) CARTON in one sentence

CARTON is the integration-time contract for SANDBOX_LORE: a small, reviewable bundle that freezes host-bound facts, their provenance, and “must not drift” invariants as manifest-verified artifacts.

Primary interface: **fix + verify + explain drift**.

## 2) Where CARTON lives

`book/integration/carton/` contains:

- `bundle/CARTON.json`
  - manifest (schema v2): world binding, spec hash, and digest/size pins for frozen artifacts.
- `bundle/relationships/`
  - canonical relationship outputs (coverage, indices, anchor projections, etc.).
- `bundle/views/`
  - derived indices built from relationships (query-friendly projections).
- `bundle/contracts/`
  - derived snapshots intended as a human review surface.
- `spec/`
  - declarative inputs: which artifacts are frozen and how they are hashed.
- `fixers/`
  - relationship + view generators (deterministic transformations).
- `tools/`
  - CLI entrypoints: `update`, `fix`, `check`, `diff`.

Design partner takeaway: when someone wants “a queryable view” of the repo’s host-bound facts, CARTON is the intended surface.

## 3) How CARTON is updated (deliberately)

Front door:
```sh
python -m book.integration.carton.tools.update
```
or:
```sh
make -C book carton-refresh
```

Review drift:
```sh
python -m book.integration.carton.tools.diff
```

Verify invariants:
```sh
python -m book.integration.carton.tools.check
```

Important discipline:
- Do not hand-edit files listed in `bundle/CARTON.json`.
- Update the upstream sources (concept inventory, mappings generators, etc.) and regenerate.

## 4) Integration guardrails (tests as “drift detectors”)

SANDBOX_LORE treats tests as a guardrail suite, not as “unit tests for macOS.”

Single supported runner:
```sh
make -C book test
```

What that runner does (high level):
- Runs a unified CI harness that covers Python wiring and a Swift build of the graph generator.
- Exercises contract surfaces and pinned fixtures so drift fails loudly.

What it is trying to prevent:
- vocabulary drift (ops/filters change unnoticed),
- schema drift (JSON contracts silently change),
- path drift (absolute paths leak into committed artifacts),
- tool wiring drift (CLIs stop matching their documented contracts),
- world mixing (artifacts from different `world_id` get combined).

## 5) Typical drift scenarios (how changes usually fail)

You can often classify failures into one of these buckets:

- **World mismatch**
  - something wrote artifacts keyed to a different `world_id`.
- **Generated outputs out of date**
  - Swift graph outputs, mapping generators, or CARTON bundle not refreshed.
- **Contract break**
  - a tool CLI/JSON shape changed without updating fixtures/contracts.
- **Path normalization regression**
  - absolute paths appear where repo-relative paths are required.
- **Evidence tier/metadata regression**
  - tier/status metadata missing or inconsistent across a mapping surface.

For design conversations, these buckets are useful because they distinguish “the repo is unhealthy” from “the sandbox behavior changed.”

## 6) Why CARTON exists (the co-design partner view)

SANDBOX_LORE’s raw artifacts are wide and evolving: experiments, mappings, runtime bundles, and reverse-engineering outputs.

CARTON exists to give the project a *small, stable slice* that can be:
- validated in CI,
- diffed in code review,
- consumed by downstream tooling and readers without learning every experiment’s output format.

The project treats CARTON as a projection: it should lag the raw evidence only in ways that are explicit and reviewable.

