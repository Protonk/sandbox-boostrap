# Axis 4.1 – Profile Ingestion (skeleton)

This directory is reserved for **Axis 4.1 Profile Ingestion Layer** (see `concepts/CONCEPT_INVENTORY.md` §4.1): shared helpers that take compiled sandbox profile blobs and turn them into typed, section-aware representations. It is anchored to these concepts:
- **Binary Profile Header** (§3.10)
- **Operation Pointer Table** (§3.11)
- **Regex / Literal Table** (§3.14)
- **Profile Format Variant** (§3.15)
- **Compiled Profile Source** (§3.19)

This is a **shared internal layer**:
- No CLI or UX lives here; runnable demos stay under `examples/`.
- Early drafts may temporarily wrap parsing logic already present in `examples/`, but the target state is that examples import ingestion helpers instead of duplicating header parsing.
- It is meant to house the first step of the pipeline: `bytes → header + section slices`, before graph construction or SBPL rendering.

## Scope (initial)
- First implementation covers only the modern graph-based profile format produced by `examples/sb/` and `examples/sbsnarf/`.
- Out of scope for v1: early decision-tree blobs, bundled multi-profile blobs, and other historical formats (can be added later).
- Internal support only: no user-facing commands; `examples/` keep the UX and will call into this layer once it exists.

## API sketch (design only)

Types (illustrative, not final):
- `ProfileBlob`: raw bytes plus `CompiledProfileSource` metadata (e.g., path, origin).
- `ProfileHeader`: parsed header fields (format variant, counts, section offsets/sizes).
- `ProfileSections`: typed slices over the blob for op-pointer table, node array, regex/literal data; may carry a `ProfileFormatVariant` tag if needed.

Core functions (language-agnostic signatures):
- `ProfileBlob::from_path(path) -> Result<ProfileBlob, Error>` — load bytes and tag source.
- `parse_header(blob: &ProfileBlob) -> Result<ProfileHeader, Error>` — parse the supported header format.
- `slice_sections(blob: &ProfileBlob, header: &ProfileHeader) -> Result<ProfileSections, Error>` — derive typed section views from header offsets/counts.
- Optional helper: `detect_format(blob: &ProfileBlob) -> ProfileFormatVariant` — format probe before parsing.

All of the above are **design targets** to guide implementation.

Status: **minimal implementation** exists for both the modern graph-based format (used by `examples/sb/`) and the legacy decision-tree format (used by `examples/sbdis/`); other variants remain unhandled for now.

## Smoke tests
- Modern graph format: `python concepts/cross/profile-ingestion/smoke/test_profile_ingestion.py` (runs `examples/sb` and parses the blob).
- Legacy decision-tree format: same smoke script also builds a tiny synthetic legacy blob and parses it. Real legacy blobs (e.g., for `examples/sbdis/`) should also parse via the ingestion API.
