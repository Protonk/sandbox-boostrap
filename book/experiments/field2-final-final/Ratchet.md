# Field2 Ratchet — How the Progress Gate Works

## Purpose
The ratchet is a TDD-style control loop that keeps field2 atlas work advancing in small, checkable steps. It forces a new, finite obligation (the milestone list), requires packet-backed evidence for each claim, and turns green only when every item is decided.

## Core files
- `book/experiments/field2-final-final/out/frontier.json` — ranked candidate queue from userland evidence.
- `book/experiments/field2-final-final/active_milestone.json` — the current finite test list.
- `book/experiments/field2-final-final/decisions.jsonl` — append-only ledger of decided claims.
- `book/integration/tests/graph/test_field2_progress_gate.py` — the progress-gate test (env-gated).
- `book/experiments/field2-final-final/ratchet_driver.py` — widens the milestone and emits the next missing claim.

## Commands (canonical)
```sh
# Refresh frontier ranking (excludes retired by default)
python book/experiments/field2-final-final/frontier_build.py

# Freeze a milestone from the frontier (excluding decided claims)
python book/experiments/field2-final-final/milestone_freeze.py --count 5

# Ratchet driver: widen milestone and emit next missing claim (non-zero exit)
python book/experiments/field2-final-final/ratchet_driver.py --delta 5

# Full test suite (baseline)
make -C book test

# Progress gate enabled
FIELD2_PROGRESS=1 make -C book test
```

## Ratchet loop (operator view)
1. Run `ratchet_driver.py` to widen the milestone; it prints `next_claim=field2=<id>` and exits non-zero.
2. Decide that claim using packet-backed evidence and append one line to `decisions.jsonl`.
3. Run `FIELD2_PROGRESS=1 make -C book test` until green.
4. Repeat step 1 to advance the ratchet.

## Ledger requirements (what the gate enforces)
Each `decisions.jsonl` entry must include:
- `claim_key` matching `active_milestone.json` (e.g., `field2=34`).
- `decision`: `promoted` or `retired`.
- `evidence`: packet identity (`packet_run_id`, `artifact_index_digest`, `packet_relpath`), `suite_id`, `lanes` keys, and `stage_attribution`.
- `consumer`: `atlas_run_id` and `mapping_delta_relpath`.
- `attempt_count` and `last_attempt_packet` (monotonic attempt tracking).
- For `retired`, a `blocker` with `blocker_class` and `retire_reason`.

The test validates packet identity via `book.api.runtime.analysis.packet_utils` and ensures `mapping_delta.json` has non-empty `proposals` or `unresolved`.

## Best practices for a cold start
- Keep `--delta` small (default 5) to avoid large retire batches; widen only after green.
- Use promotion packets as the only authority boundary; do not scrape `out/` trees directly.
- For new claims, add a userland micro-suite in runtime-adversarial before deciding; retire only after two serious attempts.
- Record failures explicitly in the ledger; do not hand-wave “partial” outcomes.
- Keep repo-relative paths in all entries; the gate rejects absolute paths.

## Recovery guide
- If the progress gate fails, read the missing claim list in the error message and add ledger entries for those claim keys.
- If `ratchet_driver.py` reports “no eligible claims,” the frontier is exhausted or fully retired; refresh the frontier or lower constraints.
