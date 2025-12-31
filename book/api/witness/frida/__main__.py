"""Module entrypoint for `python -m book.api.witness.frida`."""

from book.api.witness.frida.runner import main

if __name__ == "__main__":
    raise SystemExit(main())
