# Outputs

Emitted by `book/evidence/experiments/node-layout/analyze.py` when compiling the SBPL variants under `sb/`.

- `summary.json` — list of variants with op-table slices, section sizes, stride stats, decoder blocks, and literal samples.

Used by `book/tests/planes/examples/test_experiments.py` to sanity-check presence/shape. Regenerate with `analyze.py` after modifying the SBPL inputs.***
