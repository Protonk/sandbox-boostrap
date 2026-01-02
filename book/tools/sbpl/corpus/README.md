# SBPL corpus

This is a curated, host-bound SBPL specimen set for the Sonoma 14.4.1 baseline
(`world_id sonoma-14.4.1-23E224-arm64-dyld-2c0602c5`). It exists to keep known
inputs in one place and to keep provenance explicit.

## Families

### `baseline/`

Role: minimal allow/deny and tiny example shapes used to sanity-check the
toolchain (compile, decode, preflight classification) without relying on
runtime behavior.

Evidence tier: hypothesis. These inputs are utility probes; they do not
carry runtime witnesses and should not be used to claim policy semantics.

Pointers: `book/experiments/sbpl-graph-runtime/Report.md`.

### `golden-triple/`

Role: SBPL sources corresponding to the golden triple profile set where SBPL
inputs, decoded PolicyGraphs, and runtime results are aligned on this host.
Use when you need stable, host-validated inputs for decoding or runtime harness
work.

Evidence tier: mapped. Scope is narrow and some profiles are known
divergences (for example `bucket5:v11_read_subpath`); check the golden profile
artifacts before treating a profile as runtime-aligned.

Pointers: `book/profiles/golden-triple/README.md`,
`book/experiments/sbpl-graph-runtime/Report.md`.

### `network-matrix/`

Role: libsandbox-encoder network argument matrix. These are controlled SBPL
variants for socket domain/type/proto that produce byte-level diffs in compiled
blobs, used to join encoder-side emission to blob structure (static-only).

Evidence tier: mapped (experiment-local). The witnesses are about userland
emission and compiled-blob structure, not kernel semantics.

Pointers: `book/experiments/field2-final-final/libsandbox-encoder/Report.md`,
`book/experiments/field2-final-final/libsandbox-encoder/out/network_matrix/`.

### `gate-witness/`

Role: minimal failing/passing neighbors for apply-stage EPERM gates. These are
boundary objects for apply-gate detection and preflight guardrails.

Evidence tier: hypothesis. Apply-stage EPERM is a gate signal (profile never
attached); use these to avoid apply-gated shapes, not to interpret policy
decisions.

Pointers: `book/experiments/gate-witnesses/Report.md`,
`book/tools/preflight/README.md`.

## Provenance

`book/tools/sbpl/corpus/PROVENANCE.json` records historical origin pointers
(repo-relative source paths). It is **not** a contract: source paths may move or be deleted as
experiments evolve. The corpus files in this directory are authoritative.

No tests or tooling depend on `PROVENANCE.json`; it exists for human context.

## Reuse

- New experiments should pull inputs from this corpus instead of re-embedding
  specimen SBPL in experiment-local directories.
- Use `book/tools/preflight/preflight.py` to classify corpus entries for
  apply-gate avoidance.
- Use `book/api/profile` to compile, decode, or diff these inputs.
