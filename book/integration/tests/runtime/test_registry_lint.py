from __future__ import annotations

from book.api.runtime.plans import registry as runtime_registry


def test_runtime_registry_lint():
    index_doc, errors = runtime_registry.lint_registry()
    assert index_doc is not None, "registry index failed to load"
    assert not errors, "registry lint errors:\n" + "\n".join(sorted(set(errors)))
