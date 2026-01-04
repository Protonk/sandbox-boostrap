import json

from book.api.witness import contracts


def test_witness_help_contract():
    help_path = contracts.POLICY_WITNESS_HELP
    assert help_path.exists(), "missing policy-witness help fixture"
    text = help_path.read_text()
    for flag in [
        "xpc run",
        "xpc session",
        "--profile <id[@variant]>",
        "--service <bundle-id>",
        "--variant <base|injectable>",
        "--plan-id",
        "--row-id",
        "--correlation-id",
        "--signposts",
        "--capture-sandbox-logs",
        "--capture-sandbox-logs-target",
        "--capture-sandbox-logs-pid",
        "--capture-signposts",
        "--wait <fifo:auto|fifo:/abs|exists:/abs>",
        "--wait-timeout-ms",
        "--wait-interval-ms",
        "--xpc-timeout-ms",
    ]:
        assert flag in text, f"missing {flag} in policy-witness help"


def test_witness_observer_help_contract():
    help_path = contracts.SANDBOX_LOG_OBSERVER_HELP
    assert help_path.exists(), "missing sandbox-log-observer help fixture"
    text = help_path.read_text()
    for flag in [
        "--pid",
        "--process-name",
        "--start",
        "--end",
        "--last",
        "--duration",
        "--follow",
        "--predicate",
        "--format",
        "--output",
        "--plan-id",
        "--row-id",
        "--correlation-id",
    ]:
        assert flag in text, f"missing {flag} in observer help"


def test_witness_signpost_observer_help_contract():
    help_path = contracts.SIGNPOST_LOG_OBSERVER_HELP
    assert help_path.exists(), "missing signpost-log-observer help fixture"
    text = help_path.read_text()
    for flag in [
        "--correlation-id",
        "--subsystem",
        "--start",
        "--end",
        "--last",
        "--predicate",
        "--format",
        "--output",
        "--plan-id",
        "--row-id",
    ]:
        assert flag in text, f"missing {flag} in signpost observer help"


def test_witness_quarantine_client_help_contract():
    help_path = contracts.XPC_QUARANTINE_CLIENT_HELP
    assert help_path.exists(), "missing xpc-quarantine-client help fixture"
    text = help_path.read_text()
    for token in [
        "xpc-quarantine-client",
        "shell_script",
        "command_file",
        "text",
        "webarchive_like",
        "--operation",
        "--existing-path",
        "--dir",
        "--name",
        "--selection",
        "--test-case-id",
        "--exec",
        "--no-exec",
    ]:
        assert token in text, f"missing {token} in xpc-quarantine-client help"


def test_witness_observer_sample_contract():
    sample_path = contracts.OBSERVER_SAMPLE
    assert sample_path.exists(), "missing observer sample fixture"
    payload = json.loads(sample_path.read_text())
    assert payload.get("kind") == "sandbox_log_observer_report"
    assert isinstance(payload.get("schema_version"), int)
    data = payload.get("data")
    assert isinstance(data, dict)
    for key in ["pid", "process_name", "observed_deny", "predicate", "plan_id", "row_id", "correlation_id"]:
        assert key in data, f"missing data.{key} in observer sample"
