# Outputs

Emitted by `book/tools/sbpl/node_layout_runner.py` when compiling the SBPL variants under `sb/`.

- `summary.json` — list of variants with op-table slices, section sizes, stride stats, decoder blocks, and literal samples.

Used by `book/integration/tests/examples/test_experiments.py` to sanity-check presence/shape. Regenerate with `python3 book/tools/sbpl/node_layout_runner.py` after modifying the SBPL inputs.
