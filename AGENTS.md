# Agents start here

SANDBOX_LORE is a host-bound repo; the operational root is `book/`. Read `book/AGENTS.md` before doing any work. Nearest `AGENTS.md` wins.

Non-negotiables (summary)
- Baseline: macOS Sonoma 14.4.1 (23E224), Apple Silicon, SIP enabled; all claims are scoped to this host.
- Be explicit about uncertainty and evidence tiers (bedrock / mapped / hypothesis); cite mapping paths from `book/graph/concepts/BEDROCK_SURFACES.json`.
- Use substrate vocabulary and the canonical ops/filters vocab mappings only.
- Safety: never weaken the baseline, do not copy from `dumps/Sandbox-private/`, do not hand-edit stable mappings/CARTON, and do not hide harness/decoder/apply failures.

Where to work
- Default to `book/` unless directed otherwise.
- `dumps/`, `guidance/`, and `troubles/` have their own narrow AGENTS; follow them if you touch those trees.

Paths
- Emit repo-relative paths using `book.api.path_utils` helpers.

Tests
- Only supported repo-wide test entrypoint: `make -C book test`.
