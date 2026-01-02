#!/usr/bin/env python3
"""Prepare host-local fixtures for vfs-canonicalization probes."""

from __future__ import annotations

from pathlib import Path

from book.api.runtime.execution.harness.runner import ensure_fixtures


FIXTURE_CONTENT = "vfs-canonicalization {name}\n"


def _write_fixture(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(FIXTURE_CONTENT.format(name=path.name))


def prepare_fixtures() -> None:
    ensure_fixtures()
    fixture_paths = [
        Path("/private/tmp/foo"),
        Path("/private/tmp/bar"),
        Path("/private/tmp/nested/child"),
        Path("/private/var/tmp/canon"),
        Path("/private/var/tmp/vfs_canon_probe"),
        Path("/private/tmp/vfs_firmlink_probe"),
        Path("/private/var/tmp/vfs_link_probe"),
    ]
    for path in fixture_paths:
        _write_fixture(path)

    link_dir = Path("/private/tmp/vfs_linkdir")
    link_dir.mkdir(parents=True, exist_ok=True)
    link_path = link_dir / "to_var_tmp"
    if link_path.exists() or link_path.is_symlink():
        link_path.unlink()
    link_path.symlink_to("/private/var/tmp")


if __name__ == "__main__":
    prepare_fixtures()
