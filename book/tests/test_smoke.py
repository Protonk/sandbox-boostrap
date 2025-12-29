def test_imports():
    # Basic import sanity for core modules; fails if paths or package layout break.
    import book.api.profile.decoder  # noqa: F401
    import book.api.profile.ingestion  # noqa: F401
    import book.graph.concepts.validation.fixtures.run_fixture_harness  # noqa: F401
