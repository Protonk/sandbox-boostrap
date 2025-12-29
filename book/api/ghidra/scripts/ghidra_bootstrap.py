# Shared bootstrap for Ghidra scripts that need ghidra_lib helpers.

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
GHIDRA_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if GHIDRA_ROOT not in sys.path:
    sys.path.insert(0, GHIDRA_ROOT)

from ghidra_lib import node_scan_utils  # noqa: E402
from ghidra_lib import scan_utils  # noqa: E402

