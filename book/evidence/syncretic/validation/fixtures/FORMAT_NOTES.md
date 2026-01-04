# Modern vs Legacy Format Cues (Quick Notes)

- Legacy decision-tree (early macOS):
  - Heuristic: first two bytes as u16 *8 gives regex table offset; op-table fits in the gap from byte 4 to regex offset.
  - Op-table entries are u16; no separate node array (handlers embedded).
  - Regex table count stored at byte 2.
- Modern graph-based (libsandbox):
  - 16-byte preamble of u16 words; second word often matches operation_count.
  - Op-table appears immediately after preamble, u16 entries pointing into a node array.
  - Node array front often looks like 12-byte records; trailing literal/regex pool contains printable data.
  - Some system blobs may appear as “unknown-modern” to heuristics; op-table length may not be directly derivable without deeper parsing.
- Unknown-modern handling:
  - If preamble does not reveal operation_count, fall back to scanning for a dense u16 region (likely op-table) followed by a less-dense node area and a printable tail.
  - Keep offsets and lengths conservative; prefer capturing slices over failing silently.

Use these cues to branch parsing logic; keep variant detection explicit and carry format tags into outputs.
