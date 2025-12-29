"""Shared bootstrap for Ghidra scripts that need ghidra_lib helpers.

This module pins the helper import path so Jython scripts can import local
utilities without depending on the user's PYTHONPATH.
"""

import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
# Resolve relative to this file so headless runs do not depend on cwd.
GHIDRA_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
if GHIDRA_ROOT not in sys.path:
    # Prepend to sys.path so our local ghidra_lib wins over any global installs.
    sys.path.insert(0, GHIDRA_ROOT)

from ghidra_lib import block_utils  # noqa: E402
from ghidra_lib import io_utils  # noqa: E402
from ghidra_lib import node_scan_utils  # noqa: E402
from ghidra_lib import provenance  # noqa: E402
from ghidra_lib import scan_utils  # noqa: E402
