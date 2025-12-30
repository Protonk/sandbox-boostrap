import pytest

from book.api.carton import carton_query


def test_discovery_helpers_shapes():
    ops = carton_query.list_operations()
    profiles = carton_query.list_profiles()
    filters = carton_query.list_filters()
    assert isinstance(ops, list) and ops, "expected non-empty ops list"
    assert isinstance(profiles, list) and profiles, "expected non-empty profiles list"
    assert isinstance(filters, list) and filters, "expected non-empty filters list"
    assert all(isinstance(x, str) for x in ops)
    assert all(isinstance(x, str) for x in profiles)
    assert all(isinstance(x, str) for x in filters)


def test_filter_story_usage_status_enum_and_unknown():
    story = carton_query.filter_story("path")
    assert story["usage_status"] in {
        "present-in-vocab-only",
        "referenced-in-profiles",
        "referenced-in-runtime",
        "unknown",
    }
    with pytest.raises(carton_query.CartonDataError):
        carton_query.filter_story("definitely-not-a-filter")


def test_operation_unknown_error():
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.profiles_and_signatures_for_operation("definitely-not-an-op")
    with pytest.raises(carton_query.UnknownOperationError):
        carton_query.operation_story("definitely-not-an-op")
