from __future__ import annotations

import errno
import json
import socket
from pathlib import Path

import pytest

from book.api.witness import keepalive
from book.api.witness.paths import (
    WITNESS_HOLD_OPEN,
    WITNESS_KEEPALIVE_OUT,
    WITNESS_SB_API_VALIDATOR,
)


def _skip_if_socket_bind_blocked(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
    except PermissionError as exc:
        pytest.skip(f"keepalive socket preflight blocked: {exc}")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.bind(str(path))
    except OSError as exc:
        if exc.errno in {errno.EPERM, errno.EACCES}:
            pytest.skip(f"keepalive socket bind blocked: {exc}")
        raise
    finally:
        sock.close()
        try:
            path.unlink()
        except FileNotFoundError:
            pass


@pytest.mark.system
def test_sb_api_validator_json_contract(run_cmd):
    assert WITNESS_SB_API_VALIDATOR.exists(), "missing sb_api_validator binary"
    assert WITNESS_HOLD_OPEN.exists(), "missing hold_open helper"
    _skip_if_socket_bind_blocked(WITNESS_KEEPALIVE_OUT / "pytest-keepalive.sock")

    try:
        with keepalive.KeepaliveService(stage="operation", lane="oracle") as service:
            result = service.client.start_target(mode="spawn", wait_spec="fifo:auto", ready_timeout_s=5.0)
            target = result.get("target")
            assert isinstance(target, dict)
            pid = target.get("pid")
            assert isinstance(pid, int), "hold_open did not report a pid"

            cmd = [
                str(WITNESS_SB_API_VALIDATOR),
                "--json",
                str(pid),
                "file-read*",
                "PATH",
                "/etc/hosts",
            ]
            res = run_cmd(cmd, check=True, label="sb_api_validator json")
            payload = json.loads(res.stdout)
            target_id = target.get("target_id")
            if isinstance(target_id, str):
                service.client.release(target_id=target_id)
    except keepalive.KeepaliveError as exc:
        if exc.code == "sandbox_restriction":
            pytest.skip(exc.message)
        raise

    assert payload["kind"] == "sb_api_validator_result"
    assert payload["schema_version"] == 1
    assert payload["pid"] == pid
    assert payload["operation"] == "file-read*"
    assert payload["filter_type"] == "PATH"
    assert payload["filter_value"] == "/etc/hosts"
    assert isinstance(payload.get("rc"), int)
    assert isinstance(payload.get("errno"), int)
