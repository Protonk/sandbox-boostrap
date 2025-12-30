from book.graph.concepts.validation.sandbox_init_params_job import run_sandbox_init_params_job


def test_sandbox_init_params_guardrail():
    result = run_sandbox_init_params_job()
    assert result["status"] == "ok", f"mismatches: {result.get('mismatches')}"
