from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest


def _write_stub(path: Path, contents: str) -> None:
    path.write_text(contents)
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def _run_inside(run_cmd, env, extra_args=None):
    cmd = [sys.executable, "book/tools/inside/inside.py", "--json"]
    if extra_args:
        cmd.extend(extra_args)
    res = run_cmd(cmd, env=env, check=True, label="inside tool stubbed")
    return json.loads(res.stdout)


@pytest.mark.system
def test_inside_path_injection_fixtures(run_cmd, tmp_path: Path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()

    policy_stub = bin_dir / "policy-witness"
    policy_stub_contents = """#!/bin/sh
mode="${INSIDE_TEST_PW_MODE:-strong}"
if [ "$mode" = "strong" ]; then
  cat <<'EOF'
{"data":{"normalized_outcome":"xpc_error","layer_attribution":{"other":"xpc:openSession_failed"},"error":"failed at lookup with error 159 - Sandbox restriction."}}
EOF
elif [ "$mode" = "near_miss" ]; then
  cat <<'EOF'
{"data":{"normalized_outcome":"xpc_error","layer_attribution":{"other":"xpc:openSession_failed"},"error":"failed at lookup with error 158 - not sandbox."}}
EOF
else
  cat <<'EOF'
{"data":{"normalized_outcome":"ok","layer_attribution":{},"error":null}}
EOF
fi
"""
    _write_stub(policy_stub, policy_stub_contents)

    log_stub = bin_dir / "log"
    log_stub_contents = """#!/bin/sh
mode="${INSIDE_TEST_LOG_MODE:-match}"
if [ "$mode" = "match" ]; then
  echo "Sandbox: inside.py($PPID) deny(1) mach-lookup com.example.test"
else
  echo "Sandbox: inside.py(99999) deny(1) mach-lookup com.example.test"
fi
"""
    _write_stub(log_stub, log_stub_contents)

    env = dict(os.environ)
    env["PYTHONPATH"] = "."
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"

    env["INSIDE_TEST_PW_MODE"] = "strong"
    env["INSIDE_TEST_LOG_MODE"] = "match"
    payload = _run_inside(
        run_cmd,
        env,
        extra_args=["--policywitness-bin", "policy-witness", "--with-logs", "--log-bin", "log"],
    )
    s3 = payload["signals"]["S3"]
    s5 = payload["signals"]["S5"]
    assert s3["strength"] == "strong"
    assert s3["direction"] is True
    assert s5["strength"] == "weak"
    assert s5["direction"] is True

    env["INSIDE_TEST_PW_MODE"] = "near_miss"
    env["INSIDE_TEST_LOG_MODE"] = "mismatch"
    payload = _run_inside(
        run_cmd,
        env,
        extra_args=["--policywitness-bin", "policy-witness", "--with-logs", "--log-bin", "log"],
    )
    s3 = payload["signals"]["S3"]
    s5 = payload["signals"]["S5"]
    assert s3["strength"] == "unknown"
    assert s3["direction"] is None
    assert s5["strength"] == "unknown"
    assert s5["direction"] is None
