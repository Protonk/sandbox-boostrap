"""
`python -m book.api.profile` entrypoint.

This module intentionally stays tiny: we keep the CLI implementation in
`book/api/profile/cli.py` so that importing `book.api.profile` in library code
does not accidentally pull in argparse / command wiring.

If you're reading this file directly, the "real" surface is:
- Library: `book.api.profile` and its subpackages (compile/decoder/ingestion/…)
- CLI: `python -m book.api.profile ...` (implemented by `book.api.profile.cli`)
"""

from __future__ import annotations

from . import cli


def main() -> int:
    """Delegate to `book.api.profile.cli.main`."""
    return cli.main()


if __name__ == "__main__":
    raise SystemExit(main())
