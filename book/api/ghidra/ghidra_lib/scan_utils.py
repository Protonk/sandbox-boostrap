"""Shared scan helpers for Ghidra scripts (pure Python).

These helpers normalize addresses and instruction text across Ghidra outputs,
including the signed-address behavior Ghidra uses for 64-bit values. Keep them
pure-Python so they work in Jython without extra dependencies.
"""

import hashlib
import os
import re

try:
    integer_types = (int, long)  # type: ignore[name-defined]
except NameError:  # Python 3
    integer_types = (int,)

MASK64 = (1 << 64) - 1
SIGN_BIT = 1 << 63
# Ghidra uses signed 64-bit offsets; normalize by masking to u64 for stable JSON.

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
    return val & MASK64


def format_address(value):
    """Format a value as canonical hex address (u64)."""
    val = parse_address(value)
    if val is None:
        return None
    # Canonical hex avoids negative prefixes in dumps and keeps comparisons stable.
    return "0x%x" % (val & MASK64)


def to_unsigned(value):
    if value is None:
        return None
    return int(value) & MASK64


def to_signed(value):
    if value is None:
        return None
    val = int(value) & MASK64
    if val & SIGN_BIT:
        return val - (1 << 64)
    return val


def parse_hex(value):
    """Parse a hex string (0x optional) into u64; supports 0x-/ -0x."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text.startswith("0x-"):
        text = "-0x" + text[3:]
    if not text.startswith("0x") and not text.startswith("-0x"):
        text = "0x" + text
    val = int(text, 16)
    return to_unsigned(val)


def parse_signed_hex(value):
    """Parse hex string (0x optional) into signed 64-bit value."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    if text.startswith("0x-"):
        text = "-0x" + text[3:]
    if text.startswith("-0x"):
        val = int(text, 16)
        return val
    if not text.startswith("0x"):
        text = "0x" + text
    val = int(text, 16)
    return to_signed(val)


def format_signed_hex(value):
    if value is None:
        return None
    val = int(value)
    if val < 0:
        return "0x-%x" % abs(val)
    return "0x%x" % val


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


def find_repo_root(start_path=None):
    """Locate the repo root by walking upwards to find book/ and dumps/."""
    if start_path is None:
        start_path = os.path.abspath(os.path.dirname(__file__))
    path = os.path.abspath(start_path)
    if os.path.isfile(path):
        path = os.path.dirname(path)
    # Limit the walk to keep Jython scripts fast even when invoked from temp dirs.
    for _ in range(8):
        if os.path.isdir(os.path.join(path, "book")) and os.path.isdir(os.path.join(path, "dumps")):
            return path
        parent = os.path.dirname(path)
        if parent == path:
            break
        path = parent
    return None


def to_repo_relative(path, repo_root):
    """Return a repo-relative path (with /) when possible."""
    if path is None or repo_root is None:
        return path
    try:
        abs_path = os.path.abspath(path)
        root = os.path.abspath(repo_root)
        if abs_path == root:
            return "."
        prefix = root + os.sep
        if abs_path.startswith(prefix):
            rel = os.path.relpath(abs_path, root)
            return rel.replace(os.sep, "/")
    except Exception:
        return path
    return path


def sha256_path(path):
    if path is None:
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
