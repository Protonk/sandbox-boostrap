"""Frida API surface for experiment runners."""

from __future__ import annotations


def run(
    *,
    spawn: list[str] | None,
    attach_pid: int | None,
    script: str,
    out_dir: str = "book/api/frida/out",
    duration_s: float | None = None,
) -> int:
    # Import lazily so non-run tooling (schema/normalize/query/export) does not
    # require the Frida Python bindings just to import `book.api.frida`.
    from .runner import run as _run

    return _run(
        spawn=spawn,
        attach_pid=attach_pid,
        script=script,
        out_dir=out_dir,
        duration_s=duration_s,
    )
