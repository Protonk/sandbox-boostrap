"""Block selection helpers for Ghidra scripts.

These utilities pick relevant memory blocks (usually sandbox-related) and
normalize block metadata for JSON outputs. They are intentionally small so
Jython can import them without pulling in heavy dependencies.
"""

from ghidra.program.model.address import AddressSet

try:
    from ghidra_lib import scan_utils
except ImportError:
    from . import scan_utils


# Block name matching is string-based because Ghidra does not expose a richer
# semantic label for kernel collection slices.
DEFAULT_TOKEN = "sandbox"


def sandbox_blocks(program=None, memory=None, token=DEFAULT_TOKEN):
    if memory is None and program is not None:
        memory = program.getMemory()
    if memory is None:
        return []
    blocks = []
    for blk in memory.getBlocks():
        name = blk.getName() or ""
        # Ghidra block names are case-sensitive; normalize to avoid host-specific casing.
        if token in name.lower():
            blocks.append(blk)
    if blocks:
        return blocks
    # Fall back to all blocks so scripts still produce output when names differ.
    return list(memory.getBlocks())


def block_set(blocks):
    aset = AddressSet()
    for blk in blocks:
        # AddressSet expects start/end pairs; use full ranges to keep scans inclusive.
        aset.add(blk.getStart(), blk.getEnd())
    return aset


def block_meta(blocks):
    meta = []
    for blk in blocks:
        meta.append(
            {
                "name": blk.getName(),
                "start": scan_utils.format_address(blk.getStart().getOffset()),
                "end": scan_utils.format_address(blk.getEnd().getOffset()),
            }
        )
    return meta


def block_mode(blocks, token=DEFAULT_TOKEN):
    for blk in blocks:
        name = blk.getName() or ""
        if token in name.lower():
            return "sandbox"
    return "all"
