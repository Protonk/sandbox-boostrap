import json

import pytest

from book.integration.carton.validation.sbpl_param_value_matrix_job import (
    STATUS_PATH as MATRIX_STATUS_PATH,
    run_sbpl_param_value_matrix_job,
)
from book.integration.carton.validation.sbpl_parameterization_job import STATUS_PATH, run_sbpl_parameterization_job


@pytest.mark.system
def test_sbpl_parameterization_job():
    result = run_sbpl_parameterization_job()
    assert result["status"] == "ok", f"mismatches: {result.get('mismatches')}"

    assert STATUS_PATH.exists()
    status = json.loads(STATUS_PATH.read_text())
    assert status.get("status") == "ok"


@pytest.mark.system
def test_sbpl_param_value_matrix_job():
    result = run_sbpl_param_value_matrix_job()
    assert result["status"] == "ok", f"mismatches: {result.get('mismatches')}"

    assert MATRIX_STATUS_PATH.exists()
    status = json.loads(MATRIX_STATUS_PATH.read_text())
    assert status.get("status") == "ok"
