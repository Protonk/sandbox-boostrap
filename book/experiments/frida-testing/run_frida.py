#!/usr/bin/env python3
import argparse
import hashlib
import json
import platform
import subprocess
import sys
import time
import uuid
from pathlib import Path

import frida

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from book.api import path_utils  # noqa: E402
from book.api.runtime_tools.observations import WORLD_ID  # noqa: E402


def sha256_bytes(blob: bytes) -> str:
    h = hashlib.sha256()
    h.update(blob)
    return h.hexdigest()


def now_ns() -> int:
    return time.time_ns()


def try_cmd(*cmd: str) -> str | None:
    try:
        return subprocess.check_output(list(cmd), text=True).strip()
    except Exception:
        return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--spawn",
        nargs="+",
        help=(
            "Spawn argv (preferred for bootstrap), e.g. --spawn ./targets/open_loop /etc/hosts"
        ),
    )
    ap.add_argument("--attach-pid", type=int, help="Attach to an existing pid")
    ap.add_argument("--script", required=True, help="Path to frida agent JS")
    ap.add_argument(
        "--out-dir",
        default="book/experiments/frida-testing/out",
        help="Output directory",
    )
    ap.add_argument(
        "--duration-s",
        type=float,
        default=5.0,
        help="How long to run before detach (spawn mode)",
    )
    args = ap.parse_args()

    if (args.spawn is None) == (args.attach_pid is None):
        raise SystemExit("Specify exactly one of --spawn or --attach-pid")

    repo_root = path_utils.find_repo_root()

    run_id = str(uuid.uuid4())
    out_dir_abs = path_utils.ensure_absolute(args.out_dir, repo_root)
    out_root = out_dir_abs / run_id
    out_root.mkdir(parents=True, exist_ok=True)

    js_path_abs = path_utils.ensure_absolute(args.script, repo_root)
    js_src = js_path_abs.read_bytes()

    spawn_exec_abs: Path | None = None
    spawn_argv: list[str] | None = None
    if args.spawn:
        spawn_exec_abs = path_utils.ensure_absolute(args.spawn[0], repo_root)
        if not spawn_exec_abs.exists():
            raise SystemExit(f"spawn target not found: {spawn_exec_abs}")
        spawn_argv = [str(spawn_exec_abs)] + list(args.spawn[1:])

    meta = {
        "run_id": run_id,
        "world_id": WORLD_ID,
        "t0_ns": now_ns(),
        "out_dir": path_utils.to_repo_relative(out_root, repo_root),
        "host": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "sw_vers": {
                "productVersion": try_cmd("sw_vers", "-productVersion"),
                "buildVersion": try_cmd("sw_vers", "-buildVersion"),
            },
        },
        "frida": {
            "python_pkg_version": getattr(frida, "__version__", None),
        },
        "script": {
            "path": path_utils.to_repo_relative(js_path_abs, repo_root),
            "sha256": sha256_bytes(js_src),
        },
        "mode": "spawn" if args.spawn else "attach",
        "target": {
            "spawn_argv": (
                [path_utils.to_repo_relative(spawn_exec_abs, repo_root)]
                + list(args.spawn[1:])
                if spawn_exec_abs and args.spawn
                else None
            ),
            "attach_pid": args.attach_pid,
        },
    }
    (out_root / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True))

    jsonl = (out_root / "events.jsonl").open("w", encoding="utf-8")

    device = frida.get_local_device()

    if spawn_argv:
        pid = device.spawn(spawn_argv)
        session = device.attach(pid)
    else:
        pid = args.attach_pid
        session = device.attach(pid)

    def on_message(msg, data):
        rec = {
            "t_ns": now_ns(),
            "pid": pid,
            "msg": msg,
        }
        jsonl.write(json.dumps(rec, separators=(",", ":")) + "\n")
        jsonl.flush()

    script = session.create_script(js_src.decode("utf-8"))
    script.on("message", on_message)
    script.load()

    if spawn_argv:
        device.resume(pid)
        time.sleep(args.duration_s)
        session.detach()
    else:
        # attach mode: run until Ctrl-C
        try:
            while True:
                time.sleep(0.25)
        except KeyboardInterrupt:
            session.detach()

    jsonl.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
