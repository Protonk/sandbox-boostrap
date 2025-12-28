# Shared scan helpers for Ghidra scripts (pure Python).

import re

try:
    integer_types = (int, long)  # type: ignore[name-defined]
except NameError:  # Python 3
    integer_types = (int,)

_STACK_TOKENS = ("[sp", "[x29", "[fp")


def parse_address(value):
    """Parse a possibly-signed hex address and return a canonical u64 int."""
    if value is None:
        return None
    if isinstance(value, integer_types):
        val = int(value)
    else:
        text = str(value).strip().lower()
        if text.startswith("0x-"):
            text = "-0x" + text[3:]
        val = int(text, 0)
    if val < 0:
        val = (1 << 64) + val
    return val


def format_address(value):
    """Format a value as canonical hex address (u64)."""
    val = parse_address(value)
    if val is None:
        return None
    return "0x%x" % (val & ((1 << 64) - 1))


def normalize_offset(value):
    if value is None:
        return None
    if isinstance(value, integer_types):
        return "0x%x" % int(value)
    text = str(value).strip().lower()
    if not text.startswith("0x"):
        text = "0x" + text
    return text


def exact_offset_match(inst_text, offset):
    """Match #<offset> exactly (avoid prefix hits like #0xc00)."""
    if inst_text is None:
        return False
    needle = normalize_offset(offset)
    if not needle:
        return False
    text = str(inst_text).lower()
    pattern = r"#%s(?![0-9a-f])" % re.escape(needle)
    return re.search(pattern, text) is not None


def is_stack_access(inst_text):
    if not inst_text:
        return False
    text = str(inst_text).lower()
    for token in _STACK_TOKENS:
        if token in text:
            return True
    return False


def classify_mnemonic(mnemonic):
    if not mnemonic:
        return "other"
    text = mnemonic.lower()
    load_prefixes = (
        "ldr",
        "ldp",
        "ldrb",
        "ldrh",
        "ldur",
        "ldrs",
        "ldrsw",
        "ldxr",
        "ldar",
        "ldapr",
    )
    store_prefixes = (
        "str",
        "stp",
        "stur",
        "stxr",
        "stlr",
        "stl",
    )
    for prefix in load_prefixes:
        if text.startswith(prefix):
            return "load"
    for prefix in store_prefixes:
        if text.startswith(prefix):
            return "store"
    return "other"
