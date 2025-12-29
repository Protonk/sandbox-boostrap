"""
Runtime package CLI entrypoint shim.

This file exists so `python -m book.api.runtime` works without importing CLI
helpers directly from random scripts. Keeping the entrypoint here makes the
package behave like a tool, not just a library.

In Python, `__main__.py` is executed when a package is invoked with
`-m`. That keeps the command line experience consistent with imports.
"""

from __future__ import annotations

from . import cli


def main() -> int:
    """Dispatch to the runtime CLI entrypoint and return its exit code."""
    return cli.main()


if __name__ == "__main__":
    # Raise SystemExit explicitly so the shell sees the CLI's return code.
    raise SystemExit(main())
