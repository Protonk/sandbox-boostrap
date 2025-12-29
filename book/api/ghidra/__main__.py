"""Entry point for ghidra registry CLI.

This module keeps `python -m book.api.ghidra` aligned with the CLI parser in
`book/api/ghidra/cli.py`.
"""

# Import the CLI module directly so this entrypoint stays thin and predictable.
from . import cli


if __name__ == "__main__":
    # Use SystemExit to propagate CLI return codes to calling shells.
    raise SystemExit(cli.main())
