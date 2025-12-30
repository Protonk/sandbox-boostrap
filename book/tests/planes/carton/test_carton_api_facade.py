from book.api.carton import carton_query as api_carton


def test_facade_exports_expected_symbols():
    for name in api_carton.__all__:
        assert hasattr(api_carton, name)


def test_facade_basic_queries():
    profiles = api_carton.profiles_with_operation("file-read*")
    assert "sys:bsd" in profiles


def test_list_carton_paths_includes_coverage():
    paths = api_carton.list_carton_paths()
    assert "coverage" in paths
    for key in ["vocab_ops", "system_profiles", "coverage"]:
        assert key in paths
