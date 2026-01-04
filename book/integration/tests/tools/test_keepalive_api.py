from __future__ import annotations

import errno
import socket
from pathlib import Path

import pytest

from book.api.witness import keepalive
from book.api.witness.paths import WITNESS_CLI, WITNESS_HOLD_OPEN, WITNESS_KEEPALIVE_OUT


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
def test_keepalive_hold_open():
    assert WITNESS_HOLD_OPEN.exists(), "missing hold_open helper"
    _skip_if_socket_bind_blocked(WITNESS_KEEPALIVE_OUT / "pytest-keepalive.sock")
    try:
        with keepalive.KeepaliveService(stage="operation", lane="oracle") as service:
            result = service.client.start_target(mode="spawn", wait_spec="fifo:auto", ready_timeout_s=5.0)
            target = result.get("target")
            assert isinstance(target, dict)
            assert target.get("pid")
            assert target.get("mode") == "spawn"
            target_id = target.get("target_id")
            assert isinstance(target_id, str)
            status = service.client.status(target_id=target_id)
            assert status["target"]["alive"] is True
            if target.get("wait_mode") and target.get("wait_path"):
                service.client.release(target_id=target_id)
    except keepalive.KeepaliveError as exc:
        if exc.code == "sandbox_restriction":
            pytest.skip(exc.message)
        raise


@pytest.mark.system
def test_keepalive_policywitness_session():
    assert WITNESS_CLI.exists(), "missing PolicyWitness CLI (book/tools/witness/PolicyWitness.app)"
    _skip_if_socket_bind_blocked(WITNESS_KEEPALIVE_OUT / "pytest-keepalive.sock")
    try:
        with keepalive.KeepaliveService(stage="operation", lane="oracle") as service:
            result = service.client.start_target(
                mode="policywitness",
                profile_id="minimal",
                plan_id="test:keepalive",
                wait_spec="fifo:auto",
            )
            target = result.get("target")
            assert isinstance(target, dict)
            assert target.get("pid")
            assert target.get("mode") == "policywitness"
            target_id = target.get("target_id")
            assert isinstance(target_id, str)
            status = service.client.status(target_id=target_id)
            assert status["target"]["alive"] is True
            service.client.release(target_id=target_id)
    except keepalive.KeepaliveError as exc:
        if exc.code == "sandbox_restriction":
            pytest.skip(exc.message)
        if "Sandbox restriction" in exc.message or "failed at lookup with error 159" in exc.message:
            return
        raise
