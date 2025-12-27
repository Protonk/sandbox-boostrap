import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_DIR = ROOT / "book" / "tools" / "entitlement" / "fixtures" / "contract"


def test_entitlementjail_help_contract():
    help_path = CONTRACT_DIR / "entitlement-jail.help.txt"
    assert help_path.exists(), "missing entitlement-jail help fixture"
    text = help_path.read_text()
    for flag in [
        "xpc run",
        "xpc session",
        "--profile <id>",
        "--service <bundle-id>",
        "--ack-risk <id|bundle-id>",
        "--plan-id",
        "--row-id",
        "--correlation-id",
        "--wait <fifo:auto|fifo:/abs|exists:/abs>",
        "--wait-timeout-ms",
        "--wait-interval-ms",
        "--xpc-timeout-ms",
    ]:
        assert flag in text, f"missing {flag} in entitlement-jail help"


def test_entitlementjail_observer_help_contract():
    help_path = CONTRACT_DIR / "sandbox-log-observer.help.txt"
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
        "--format",
        "--output",
        "--plan-id",
        "--row-id",
        "--correlation-id",
    ]:
        assert flag in text, f"missing {flag} in observer help"


def test_entitlementjail_observer_sample_contract():
    sample_path = CONTRACT_DIR / "observer.sample.json"
    assert sample_path.exists(), "missing observer sample fixture"
    payload = json.loads(sample_path.read_text())
    assert payload.get("kind") == "sandbox_log_observer_report"
    assert isinstance(payload.get("schema_version"), int)
    data = payload.get("data")
    assert isinstance(data, dict)
    for key in ["pid", "process_name", "observed_deny", "predicate", "plan_id", "row_id", "correlation_id"]:
        assert key in data, f"missing data.{key} in observer sample"
