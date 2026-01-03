# Policy tools

Host-bound utilities for enumerating PolicyGraph node fields on the Sonoma
baseline. This directory is the home for the new `policygraph_node_fields`
enumerator and its supporting inputs.

## Layout

- `policygraph_node_fields.py` — CLI entrypoint (deterministic enumerator).
- `validator/` — local copy of `book/tools/validator` (sb_validator) for
  sandbox_check pairing validation.

## Usage

From repo root:

```sh
python3 book/tools/policy/policygraph_node_fields.py --out book/evidence/syncretic/policygraph/node-fields
python3 book/tools/policy/policygraph_node_fields.py --describe
```

Optional packet annotation:

```sh
python3 book/tools/policy/policygraph_node_fields.py \
  --packet book/tools/policy/runtime_annotation.promotion_packet.json \
  --out book/evidence/syncretic/policygraph/node-fields
```

## Outputs

All outputs are repo-relative and stamped with input provenance:

- `policygraph_node_fields.json` — fixed-width field layout summary.
- `policygraph_node_arg16.json` — arg16 (legacy field2) inventory + anchors.
- `policygraph_node_unknowns.json` — arg16 values with no filter vocab match.
- `policygraph_node_fields_receipt.json` — inputs, digests, and command.
- `policygraph_node_fields.md` — literate, annotated summary for the run.
