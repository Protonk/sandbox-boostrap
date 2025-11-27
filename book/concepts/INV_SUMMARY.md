# Inventory Validation Handoff (in-progress)

- **Plan + clusters:** `book/concepts/CONCEPT_INVENTORY.md` (Process stages 0–6).
- **Example mappings:** `book/concepts/EXAMPLES.md` (examples ↔ clusters).
- **Concept map:** `book/concepts/validation/Concept_map.md` (verbatim definitions + clusters).
- **Validation tasks:** `book/concepts/validation/tasks.py` (per-cluster tasks → examples → expected artifacts); helper `list_tasks()` prints a summary.
- **Harness notes:** `book/concepts/validation/README.md` (intended workflow; keep scripts under `book/concepts/validation/`).
- **Metadata collected:** `book/concepts/validation/out/metadata.json` (OS 14.4.1 build 23E224, arm64, SIP enabled; TCC/variant not collected).
- **Ingestion spine:** `book/concepts/validation/profile_ingestion.py` (minimal, variant-tolerant; recognizes legacy decision-tree headers, otherwise returns “unknown-modern” with full blob available for inspection).
- **Static outputs so far:** `validation/out/static/sample.sb.json` (from `book/examples/sb`) and `validation/out/static/system_profiles.json` (airlock.sb.bin, bsd.sb.bin from `extract_sbs` via ingestion helper); section lengths are placeholder for unknown-modern formats.
- **Outputs pending:** Semantic/vocab/lifecycle JSONL not yet captured; `validation/out/{semantic,vocab,lifecycle}/` are ready for use.
