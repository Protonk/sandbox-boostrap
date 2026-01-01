from book.tools.inside import inside as inside_mod


def _signal(result_class: str):
    return {"result_class": result_class}


def test_score_harness_strong_true():
    summary = inside_mod._score_harness({"S0": _signal("strong_true")})
    assert summary["harness_constrained"] is True
    assert summary["confidence"] == "high"
    assert summary["triggers"] == ["S0"]


def test_score_harness_two_weak_true():
    summary = inside_mod._score_harness({"S1": _signal("weak_true"), "S3": _signal("weak_true")})
    assert summary["harness_constrained"] is True
    assert summary["confidence"] == "medium"
    assert set(summary["triggers"]) == {"S1", "S3"}


def test_score_harness_all_unknown():
    signals = {sid: _signal("unknown") for sid in ("S0", "S1", "S2", "S3", "S4", "S5")}
    summary = inside_mod._score_harness(signals)
    assert summary["harness_constrained"] is None
    assert summary["confidence"] == "low"


def test_score_harness_false_high():
    summary = inside_mod._score_harness({"S0": _signal("strong_false"), "S2": _signal("weak_false")})
    assert summary["harness_constrained"] is False
    assert summary["confidence"] == "high"
    assert "S0" in summary["triggers"]
    assert "S2" in summary["triggers"]
