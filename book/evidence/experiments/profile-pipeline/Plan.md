# Profile Pipeline - Plan

## Goals
- Keep the compile -> layout -> op-table -> vocab -> apply pipeline in one place with clear tiering.
- Preserve track-local tooling while presenting a unified narrative in `Report.md`.
- Avoid hand-editing generated artifacts; refresh via each track's run scripts.

## Current tasks
1) Keep subtrack docs accurate after consolidation (paths, run commands, evidence pointers).
2) Add minimal probes only when they sharpen a specific hypothesis (single-change SBPL or single new handle variant).
3) When evidence stabilizes, propose promotion into shared mappings with guardrails.
