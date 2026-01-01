"""
Runtime execution harness for expected matrices.

Consolidated home for the former `golden_runner`.

The harness is intentionally boring. It applies profiles, runs probes,
and records structured results so the evidence can be replayed and audited.
"""

from __future__ import annotations

import fcntl
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from book.api import tooling
from book.api.path_utils import ensure_absolute, find_repo_root, relativize_command, to_repo_relative
from book.api.runtime.contracts import schema as rt_contract

REPO_ROOT = find_repo_root(Path(__file__))
DEFAULT_OUT = REPO_ROOT / "book" / "profiles" / "golden-triple"
DEFAULT_RUNTIME_PROFILE_DIR = DEFAULT_OUT / "runtime_profiles"
SANDBOX_RUNNER_DIR = REPO_ROOT / "book" / "api" / "runtime" / "native" / "sandbox_runner"
RUNNER = SANDBOX_RUNNER_DIR / "sandbox_runner"
READER = SANDBOX_RUNNER_DIR / "sandbox_reader"
WRITER = SANDBOX_RUNNER_DIR / "sandbox_writer"
METADATA_RUNNER_DIR = REPO_ROOT / "book" / "api" / "runtime" / "native" / "metadata_runner"
METADATA_RUNNER = METADATA_RUNNER_DIR / "metadata_runner"
WRAPPER = REPO_ROOT / "book" / "tools" / "sbpl" / "wrapper" / "wrapper"
PROBE_DIR = REPO_ROOT / "book" / "api" / "runtime" / "native" / "probes"
MACH_PROBE = PROBE_DIR / "mach_probe"
SANDBOX_MACH_PROBE = PROBE_DIR / "sandbox_mach_probe"
IOKIT_PROBE = PROBE_DIR / "iokit_probe"
SANDBOX_IOKIT_PROBE = PROBE_DIR / "sandbox_iokit_probe"
FILE_PROBE = REPO_ROOT / "book" / "api" / "runtime" / "native" / "file_probe" / "file_probe"

CAT = "/bin/cat"
SH = "/bin/sh"
NOTIFYUTIL = "/usr/bin/notifyutil"
PYTHON = "/usr/bin/python3"

RUNTIME_SHIM_RULES = [
    "(allow process-exec*)",
    '(allow file-read* (subpath "/System"))',
    '(allow file-read* (subpath "/usr"))',
    '(allow file-read* (subpath "/bin"))',
    '(allow file-read* (subpath "/sbin"))',
    '(allow file-read* (subpath "/dev"))',
    '(allow file-read-metadata (literal "/private"))',
    '(allow file-read-metadata (literal "/private/tmp"))',
    '(allow file-read-metadata (literal "/tmp"))',
]

def _first_marker(markers: List[Dict[str, Any]], stage: str) -> Optional[Dict[str, Any]]:
    for marker in markers:
        if marker.get("stage") == stage:
            return marker
    return None


def _extract_probe_details(stdout: Optional[str]) -> tuple[Optional[Dict[str, Any]], str]:
    if not stdout:
        return None, ""
    details: Optional[Dict[str, Any]] = None
    cleaned_lines: List[str] = []
    for line in stdout.splitlines():
        if line.startswith("SBL_PROBE_DETAILS "):
            payload = line[len("SBL_PROBE_DETAILS ") :].strip()
            if payload:
                try:
                    details = json.loads(payload)
                except Exception:
                    details = {"error": "invalid_probe_details_json"}
            continue
        cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    if stdout.endswith("\n") and cleaned:
        cleaned += "\n"
    return details, cleaned


def ensure_fixtures(fixture_root: Path = Path("/tmp")) -> None:
    """Create small fixture files used by runtime probes."""
    for name in ["foo", "bar"]:
        p = fixture_root / name
        p.write_text(f"runtime-checks {name}\n")
        (p.with_suffix(".txt")).write_text(f"{name}\n")
    nested = fixture_root / "nested" / "child"
    nested.parent.mkdir(parents=True, exist_ok=True)
    nested.write_text("runtime-checks nested child\n")
    nested.chmod(0o640)
    var_tmp = Path("/var/tmp/canon")
    try:
        var_tmp.parent.mkdir(parents=True, exist_ok=True)
        var_tmp.write_text("runtime-checks var tmp canon\n")
        var_tmp.chmod(0o640)
    except OSError:
        # Best-effort: /var/tmp can be sandbox-restricted in CI environments.
        pass
    (fixture_root / "baz.txt").write_text("baz\n")
    (fixture_root / "qux.txt").write_text("qux\n")
    rt = fixture_root / "sbpl_rt"
    rt.mkdir(parents=True, exist_ok=True)
    (rt / "read.txt").write_text("runtime-checks read\n")
    (rt / "write.txt").write_text("runtime-checks write\n")
    (rt / "param_root").mkdir(parents=True, exist_ok=True)
    (rt / "param_root" / "foo").write_text("runtime-checks param_root foo\n")
    # Use /private/tmp for canonicalization-sensitive fixtures.
    strict_dir = Path("/private/tmp/strict_ok")
    strict_dir.mkdir(parents=True, exist_ok=True)
    (strict_dir / "allow.txt").write_text("strict allow\n")
    ok_dir = Path("/private/tmp/ok")
    ok_dir.mkdir(parents=True, exist_ok=True)
    (ok_dir / "allow.txt").write_text("param ok allow\n")


def _is_path_operation(op: Optional[str]) -> bool:
    if not op:
        return False
    return op.startswith("file-") or op in {"file-read*", "file-write*", "file-read-data", "file-write-data"}


def _observe_path_unsandboxed(path: Optional[str]) -> Optional[Dict[str, Any]]:
    if not path or not isinstance(path, str) or not path.startswith("/"):
        return None
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as exc:
        return {
            "observed_path": None,
            "observed_path_source": "unsandboxed_error",
            "observed_path_errno": exc.errno,
            "observed_path_nofirmlink": None,
            "observed_path_nofirmlink_source": "unsandboxed_error",
            "observed_path_nofirmlink_errno": exc.errno,
        }
    try:
        buf = fcntl.fcntl(fd, fcntl.F_GETPATH, b"\0" * 1024)
        observed = buf.split(b"\0", 1)[0].decode("utf-8", errors="replace")
        doc: Dict[str, Any] = {
            "observed_path": observed,
            "observed_path_source": "unsandboxed_fd_path",
            "observed_path_errno": None,
        }
        nofirmlink = getattr(fcntl, "F_GETPATH_NOFIRMLINK", None)
        if nofirmlink is None:
            doc.update(
                {
                    "observed_path_nofirmlink": None,
                    "observed_path_nofirmlink_source": "unsandboxed_unavailable",
                    "observed_path_nofirmlink_errno": None,
                }
            )
            return doc
        try:
            buf = fcntl.fcntl(fd, nofirmlink, b"\0" * 1024)
            observed_nf = buf.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            doc.update(
                {
                    "observed_path_nofirmlink": observed_nf,
                    "observed_path_nofirmlink_source": "unsandboxed_fd_path",
                    "observed_path_nofirmlink_errno": None,
                }
            )
        except OSError as exc:
            doc.update(
                {
                    "observed_path_nofirmlink": None,
                    "observed_path_nofirmlink_source": "unsandboxed_error",
                    "observed_path_nofirmlink_errno": exc.errno,
                }
            )
        return doc
    except OSError as exc:
        return {
            "observed_path": None,
            "observed_path_source": "unsandboxed_error",
            "observed_path_errno": exc.errno,
            "observed_path_nofirmlink": None,
            "observed_path_nofirmlink_source": "unsandboxed_error",
            "observed_path_nofirmlink_errno": exc.errno,
        }
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def _unsandboxed_path_observation(path: Optional[str]) -> Optional[Dict[str, Any]]:
    return _observe_path_unsandboxed(path)


def _sanitize_label(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return cleaned.strip("_") or "probe"


def _should_capture_witness_observer() -> bool:
    return os.environ.get("SANDBOX_LORE_WITNESS_OBSERVER") == "1"


def _extract_witness_identity(probe_details: Optional[Dict[str, Any]]) -> tuple[Optional[str], Optional[str]]:
    if not isinstance(probe_details, dict):
        return None, None
    pid = None
    for key in ("service_pid", "probe_pid", "pid"):
        value = probe_details.get(key)
        if isinstance(value, int):
            pid = str(value)
            break
        if isinstance(value, str) and value:
            pid = value
            break
    process_name = probe_details.get("process_name")
    if not isinstance(process_name, str):
        process_name = probe_details.get("service_name")
    if not isinstance(process_name, str):
        process_name = None
    return pid, process_name


def _capture_witness_observer(
    *,
    probe_details: Optional[Dict[str, Any]],
    out_dir: Path,
    profile_id: str,
    probe_name: str,
    started_at_unix_s: Optional[float],
    finished_at_unix_s: Optional[float],
    plan_id: Optional[str],
    row_id: Optional[str],
) -> Optional[Dict[str, Any]]:
    if not _should_capture_witness_observer():
        return None
    try:
        from book.api.witness import observer as witness_observer
    except Exception as exc:
        return {"skipped": "observer_import_error", "error": f"{type(exc).__name__}: {exc}"}
    if not witness_observer.should_run_observer():
        return {"skipped": "observer_disabled"}
    pid, process_name = _extract_witness_identity(probe_details)
    if pid is None or process_name is None:
        return {"skipped": "missing_pid_or_process_name"}
    label = _sanitize_label(f"{profile_id}.{probe_name}")
    dest_path = out_dir / "observer" / f"{label}.observer.json"
    return witness_observer.run_sandbox_log_observer(
        pid=pid,
        process_name=process_name,
        dest_path=dest_path,
        last=witness_observer.OBSERVER_LAST,
        start_s=started_at_unix_s,
        end_s=finished_at_unix_s,
        plan_id=plan_id,
        row_id=row_id or label,
        correlation_id=None,
    )


def classify_profile_status(probes: List[Dict[str, Any]], skipped_reason: str | None = None) -> tuple[str, str | None]:
    """Summarize probe outcomes into a profile-level status."""
    if skipped_reason:
        return "blocked", skipped_reason
    if not probes:
        return "blocked", "no probes executed"
    if any(p.get("error") for p in probes):
        return "blocked", "probe execution error"
    blocked_stages = {"apply", "bootstrap", "preflight"}
    stages = []
    for probe in probes:
        rr = probe.get("runtime_result") or {}
        stage = rr.get("failure_stage")
        if stage:
            stages.append(stage)
    if stages and all(stage in blocked_stages for stage in stages):
        return "blocked", "all probes blocked before policy evaluation"
    all_match = all(p.get("match") is True for p in probes)
    if all_match:
        return "ok", None
    return "partial", "runtime results diverged from expected allow/deny matrix"


def build_probe_command(probe: Dict[str, Any]) -> List[str]:
    """
    Build an unsandboxed probe command for baseline execution.
    """
    target = probe.get("target")
    op = probe.get("operation")
    cmd: List[str]
    if op == "file-read-metadata":
        if target and Path(PYTHON).exists():
            cmd = [PYTHON, "-c", "import os, sys; os.lstat(sys.argv[1])", target]
        else:
            cmd = ["true"]
    elif op == "file-read*":
        use_file_probe = probe.get("driver") == "file_probe" and FILE_PROBE.exists() and target
        if use_file_probe:
            cmd = [str(FILE_PROBE), "read", target]
        else:
            cmd = [CAT, target] if target else ["true"]
    elif op == "file-write*":
        use_file_probe = probe.get("driver") == "file_probe" and FILE_PROBE.exists() and target
        if use_file_probe:
            cmd = [str(FILE_PROBE), "write", target]
        else:
            cmd = [SH, "-c", f"echo runtime-check >> '{target}'"] if target else ["true"]
    elif op == "mach-lookup":
        if MACH_PROBE.exists() and target:
            cmd = [str(MACH_PROBE), target]
        else:
            cmd = ["true"]
    elif op == "iokit-open-service":
        if IOKIT_PROBE.exists() and target:
            cmd = [str(IOKIT_PROBE), target]
        else:
            cmd = ["true"]
    elif op == "sysctl-read":
        if target:
            cmd = ["/usr/sbin/sysctl", "-n", target]
        else:
            cmd = ["true"]
    elif op == "darwin-notification-post":
        if target and Path(NOTIFYUTIL).exists():
            cmd = [NOTIFYUTIL, "-p", target]
        else:
            cmd = ["true"]
    elif op == "distributed-notification-post":
        if target and Path(PYTHON).exists():
            script = (
                "import ctypes, sys\n"
                "cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')\n"
                "cf.CFNotificationCenterGetDistributedCenter.restype = ctypes.c_void_p\n"
                "center = cf.CFNotificationCenterGetDistributedCenter()\n"
                "cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]\n"
                "cf.CFStringCreateWithCString.restype = ctypes.c_void_p\n"
                "kCFStringEncodingUTF8 = 0x08000100\n"
                "name = sys.argv[1].encode('utf-8')\n"
                "cfname = cf.CFStringCreateWithCString(None, name, kCFStringEncodingUTF8)\n"
                "cf.CFNotificationCenterPostNotification.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]\n"
                "cf.CFNotificationCenterPostNotification(center, cfname, None, None, True)\n"
            )
            cmd = [PYTHON, "-c", script, target]
        else:
            cmd = ["true"]
    elif op == "process-info-pidinfo":
        if target and Path(PYTHON).exists():
            script = (
                "import ctypes, ctypes.util, os, sys\n"
                "lib = ctypes.CDLL(ctypes.util.find_library('proc'))\n"
                "lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]\n"
                "lib.proc_pidinfo.restype = ctypes.c_int\n"
                "PROC_PIDTBSDINFO = 3\n"
                "pid_arg = sys.argv[1]\n"
                "pid = os.getpid() if pid_arg == 'self' else int(pid_arg)\n"
                "buf = ctypes.create_string_buffer(512)\n"
                "rc = lib.proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buf, ctypes.sizeof(buf))\n"
                "sys.exit(0 if rc > 0 else 1)\n"
            )
            cmd = [PYTHON, "-c", script, target]
        else:
            cmd = ["true"]
    elif op == "signal":
        if Path(PYTHON).exists():
            script = (
                "import json, os, signal, subprocess, sys\n"
                "ready_r, ready_w = os.pipe()\n"
                "result_r, result_w = os.pipe()\n"
                "child_env = os.environ.copy()\n"
                "child_env['SBL_READY_FD'] = str(ready_w)\n"
                "child_env['SBL_RESULT_FD'] = str(result_w)\n"
                "child_code = (\n"
                "    \"import os, signal, sys\\n\"\n"
                "    \"ready_fd = int(os.environ.get('SBL_READY_FD', '-1'))\\n\"\n"
                "    \"result_fd = int(os.environ.get('SBL_RESULT_FD', '-1'))\\n\"\n"
                "    \"def handler(signum, frame):\\n\"\n"
                "    \"    try: os.write(result_fd, b'signal')\\n\"\n"
                "    \"    except Exception: pass\\n\"\n"
                "    \"    sys.exit(0)\\n\"\n"
                "    \"signal.signal(signal.SIGUSR1, handler)\\n\"\n"
                "    \"try: os.write(ready_fd, b'ready')\\n\"\n"
                "    \"except Exception: pass\\n\"\n"
                "    \"signal.pause()\\n\"\n"
                "    \"sys.exit(2)\\n\"\n"
                ")\n"
                "child = subprocess.Popen([sys.executable, '-c', child_code], pass_fds=(ready_w, result_w), env=child_env)\n"
                "os.close(ready_w)\n"
                "os.close(result_w)\n"
                "details = {\n"
                "    'probe_schema_version': 'hardened-runtime.signal-probe.v0.2',\n"
                "    'child_pid': child.pid,\n"
                "    'child_spawn_method': 'subprocess.Popen',\n"
                "    'handshake_ok': False,\n"
                "    'signal_sent': False,\n"
                "    'child_received_signal': False,\n"
                "}\n"
                "try:\n"
                "    data = os.read(ready_r, 5)\n"
                "    details['handshake_ok'] = data == b'ready'\n"
                "except Exception as exc:\n"
                "    details['handshake_error'] = str(exc)\n"
                "if details['handshake_ok']:\n"
                "    try:\n"
                "        os.kill(child.pid, signal.SIGUSR1)\n"
                "        details['signal_sent'] = True\n"
                "    except Exception as exc:\n"
                "        details['signal_error'] = str(exc)\n"
                "try:\n"
                "    import select\n"
                "    rlist, _, _ = select.select([result_r], [], [], 1.0)\n"
                "    if rlist:\n"
                "        data = os.read(result_r, 16)\n"
                "        if data.startswith(b'signal'):\n"
                "            details['child_received_signal'] = True\n"
                "except Exception as exc:\n"
                "    details['result_error'] = str(exc)\n"
                "try:\n"
                "    child.wait(timeout=1.0)\n"
                "    details['child_exit_code'] = child.returncode\n"
                "    details['child_status'] = 'exited'\n"
                "except Exception:\n"
                "    child.kill()\n"
                "    child.wait()\n"
                "    details['child_exit_code'] = child.returncode\n"
                "    details['child_status'] = 'killed'\n"
                "print('SBL_PROBE_DETAILS ' + json.dumps(details))\n"
                "sys.exit(0 if details['signal_sent'] and details['child_received_signal'] else 1)\n"
            )
            cmd = [PYTHON, "-c", script]
        else:
            cmd = ["true"]
    elif op == "network-outbound":
        hostport = target or "127.0.0.1"
        if ":" in hostport:
            host, port = hostport.split(":", 1)
        else:
            host, port = hostport, "80"
        nc = Path("/usr/bin/nc")
        cmd = [str(nc), "-z", "-w", "2", host, port]
    elif op == "process-exec":
        cmd = ["true"]
    else:
        cmd = ["true"]
    return cmd


def prepare_profile(
    base: Path,
    key: str,
    key_specific_rules: Dict[str, List[str]],
    runtime_profile_dir: Path,
    shim_rules: List[str] | None = None,
    profile_mode: str | None = None,
) -> Path:
    """Prepare a runtime profile path with shim rules applied."""
    base = ensure_absolute(base, REPO_ROOT)
    runtime_profile_dir.mkdir(parents=True, exist_ok=True)
    if base.suffix == ".bin":
        return base
    text = base.read_text()
    runtime_path = runtime_profile_dir / f"{base.stem}.{key.replace(':', '_')}.runtime.sb"
    shim = "\n".join((shim_rules or RUNTIME_SHIM_RULES) + key_specific_rules.get(key, [])) + "\n"
    patched = text.rstrip() + "\n" + shim
    runtime_path.write_text(patched + ("\n" if not patched.endswith("\n") else ""))
    return runtime_path


def run_probe(profile: Path, probe: Dict[str, Any], profile_mode: str | None, wrapper_preflight: str | None) -> Dict[str, Any]:
    """Run a single probe under a prepared profile and return the result row."""
    target = probe.get("target")
    op = probe.get("operation")
    cmd: List[str]
    blob_mode = (probe.get("mode") == "blob") or (profile_mode == "blob")
    if profile.suffix == ".bin" and WRAPPER.exists():
        blob_mode = True

    reader_mode = False
    writer_mode = False
    self_apply_mode = False
    metadata_driver = False
    if op == "file-read-metadata":
        driver = probe.get("driver")
        if driver != "metadata_runner":
            return {"error": "file-read-metadata probe missing driver (expected metadata_runner)"}
        if not METADATA_RUNNER.exists():
            return {"error": "metadata_runner missing"}
        if not target:
            return {"error": "metadata_runner requires target path"}
        cmd = [str(METADATA_RUNNER)]
        if blob_mode:
            cmd += ["--blob", str(profile)]
        else:
            cmd += ["--sbpl", str(profile)]
        cmd += ["--op", op, "--path", target]
        syscall = probe.get("syscall")
        if syscall:
            cmd += ["--syscall", str(syscall)]
        attr_payload = probe.get("attr_payload")
        if attr_payload:
            cmd += ["--attr-payload", str(attr_payload)]
        metadata_driver = True
        self_apply_mode = True
    elif op == "file-read*":
        use_file_probe = probe.get("driver") == "file_probe" and FILE_PROBE.exists() and target
        if use_file_probe:
            cmd = [str(FILE_PROBE), "read", target]
        # In blob mode, the wrapper applies the compiled profile; use /bin/cat
        # as the in-sandbox probe so we don't re-run sandbox_init on a .sb.bin.
        elif not blob_mode and READER.exists():
            cmd = [str(READER), str(profile), target]
            reader_mode = True
        else:
            cmd = [CAT, target]
    elif op == "file-write*":
        driver = probe.get("driver")
        if driver == "metadata_runner":
            if not METADATA_RUNNER.exists():
                return {"error": "metadata_runner missing"}
            if not target:
                return {"error": "metadata_runner requires target path"}
            cmd = [str(METADATA_RUNNER)]
            if blob_mode:
                cmd += ["--blob", str(profile)]
            else:
                cmd += ["--sbpl", str(profile)]
            cmd += ["--op", op, "--path", target]
            syscall = probe.get("syscall")
            if syscall:
                cmd += ["--syscall", str(syscall)]
            metadata_driver = True
            self_apply_mode = True
        else:
            use_file_probe = driver == "file_probe" and FILE_PROBE.exists() and target
            if use_file_probe:
                cmd = [str(FILE_PROBE), "write", target]
            # Same rule as file-read*: avoid sandbox_init-on-binary by using /bin/sh
            # inside the blob-applied wrapper process.
            elif not blob_mode and WRITER.exists():
                cmd = [str(WRITER), str(profile), target]
                writer_mode = True
            else:
                cmd = [SH, "-c", f"echo runtime-check >> '{target}'"]
    elif op == "mach-lookup":
        driver = probe.get("driver")
        if driver == "sandbox_mach_probe":
            if target and not blob_mode and SANDBOX_MACH_PROBE.exists():
                cmd = [str(SANDBOX_MACH_PROBE), str(profile), target]
                self_apply_mode = True
            else:
                return {"error": "sandbox_mach_probe missing or invalid target"}
        elif driver == "mach_probe":
            cmd = [str(MACH_PROBE), target] if (MACH_PROBE.exists() and target) else ["true"]
        elif driver is None:
            return {"error": "mach-lookup probe missing driver (expected sandbox_mach_probe or mach_probe)"}
        else:
            return {"error": f"unsupported mach-lookup driver: {driver}"}
    elif op == "iokit-open-service":
        driver = probe.get("driver")
        if driver == "sandbox_iokit_probe":
            if target and not blob_mode and SANDBOX_IOKIT_PROBE.exists():
                cmd = [str(SANDBOX_IOKIT_PROBE), str(profile), target]
                self_apply_mode = True
            else:
                return {"error": "sandbox_iokit_probe missing or invalid target"}
        elif driver == "iokit_probe":
            cmd = [str(IOKIT_PROBE), target] if (IOKIT_PROBE.exists() and target) else ["true"]
        elif driver is None:
            return {"error": "iokit-open-service probe missing driver (expected sandbox_iokit_probe or iokit_probe)"}
        else:
            return {"error": f"unsupported iokit-open-service driver: {driver}"}
    elif op == "sysctl-read":
        if target:
            cmd = ["/usr/sbin/sysctl", "-n", target]
        else:
            cmd = ["true"]
    elif op == "darwin-notification-post":
        if target and Path(NOTIFYUTIL).exists():
            cmd = [NOTIFYUTIL, "-p", target]
        else:
            cmd = ["true"]
    elif op == "distributed-notification-post":
        if target and Path(PYTHON).exists():
            script = (
                "import ctypes, sys\n"
                "cf = ctypes.CDLL('/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation')\n"
                "cf.CFNotificationCenterGetDistributedCenter.restype = ctypes.c_void_p\n"
                "center = cf.CFNotificationCenterGetDistributedCenter()\n"
                "cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]\n"
                "cf.CFStringCreateWithCString.restype = ctypes.c_void_p\n"
                "kCFStringEncodingUTF8 = 0x08000100\n"
                "name = sys.argv[1].encode('utf-8')\n"
                "cfname = cf.CFStringCreateWithCString(None, name, kCFStringEncodingUTF8)\n"
                "cf.CFNotificationCenterPostNotification.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]\n"
                "cf.CFNotificationCenterPostNotification(center, cfname, None, None, True)\n"
            )
            cmd = [PYTHON, "-c", script, target]
        else:
            cmd = ["true"]
    elif op == "process-info-pidinfo":
        if target and Path(PYTHON).exists():
            script = (
                "import ctypes, ctypes.util, os, sys\n"
                "lib = ctypes.CDLL(ctypes.util.find_library('proc'))\n"
                "lib.proc_pidinfo.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int]\n"
                "lib.proc_pidinfo.restype = ctypes.c_int\n"
                "PROC_PIDTBSDINFO = 3\n"
                "pid_arg = sys.argv[1]\n"
                "pid = os.getpid() if pid_arg == 'self' else int(pid_arg)\n"
                "buf = ctypes.create_string_buffer(512)\n"
                "rc = lib.proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, buf, ctypes.sizeof(buf))\n"
                "sys.exit(0 if rc > 0 else 1)\n"
            )
            cmd = [PYTHON, "-c", script, target]
        else:
            cmd = ["true"]
    elif op == "signal":
        if Path(PYTHON).exists():
            script = (
                "import json, os, signal, subprocess, sys\n"
                "ready_r, ready_w = os.pipe()\n"
                "result_r, result_w = os.pipe()\n"
                "child_env = os.environ.copy()\n"
                "child_env['SBL_READY_FD'] = str(ready_w)\n"
                "child_env['SBL_RESULT_FD'] = str(result_w)\n"
                "child_code = (\n"
                "    \"import os, signal, sys\\n\"\n"
                "    \"ready_fd = int(os.environ.get('SBL_READY_FD', '-1'))\\n\"\n"
                "    \"result_fd = int(os.environ.get('SBL_RESULT_FD', '-1'))\\n\"\n"
                "    \"def handler(signum, frame):\\n\"\n"
                "    \"    try: os.write(result_fd, b'signal')\\n\"\n"
                "    \"    except Exception: pass\\n\"\n"
                "    \"    sys.exit(0)\\n\"\n"
                "    \"signal.signal(signal.SIGUSR1, handler)\\n\"\n"
                "    \"try: os.write(ready_fd, b'ready')\\n\"\n"
                "    \"except Exception: pass\\n\"\n"
                "    \"signal.pause()\\n\"\n"
                "    \"sys.exit(2)\\n\"\n"
                ")\n"
                "child = subprocess.Popen([sys.executable, '-c', child_code], pass_fds=(ready_w, result_w), env=child_env)\n"
                "os.close(ready_w)\n"
                "os.close(result_w)\n"
                "details = {\n"
                "    'probe_schema_version': 'hardened-runtime.signal-probe.v0.2',\n"
                "    'child_pid': child.pid,\n"
                "    'child_spawn_method': 'subprocess.Popen',\n"
                "    'handshake_ok': False,\n"
                "    'signal_sent': False,\n"
                "    'child_received_signal': False,\n"
                "}\n"
                "try:\n"
                "    data = os.read(ready_r, 5)\n"
                "    details['handshake_ok'] = data == b'ready'\n"
                "except Exception as exc:\n"
                "    details['handshake_error'] = str(exc)\n"
                "if details['handshake_ok']:\n"
                "    try:\n"
                "        os.kill(child.pid, signal.SIGUSR1)\n"
                "        details['signal_sent'] = True\n"
                "    except Exception as exc:\n"
                "        details['signal_error'] = str(exc)\n"
                "try:\n"
                "    import select\n"
                "    rlist, _, _ = select.select([result_r], [], [], 1.0)\n"
                "    if rlist:\n"
                "        data = os.read(result_r, 16)\n"
                "        if data.startswith(b'signal'):\n"
                "            details['child_received_signal'] = True\n"
                "except Exception as exc:\n"
                "    details['result_error'] = str(exc)\n"
                "try:\n"
                "    child.wait(timeout=1.0)\n"
                "    details['child_exit_code'] = child.returncode\n"
                "    details['child_status'] = 'exited'\n"
                "except Exception:\n"
                "    child.kill()\n"
                "    child.wait()\n"
                "    details['child_exit_code'] = child.returncode\n"
                "    details['child_status'] = 'killed'\n"
                "print('SBL_PROBE_DETAILS ' + json.dumps(details))\n"
                "sys.exit(0 if details['signal_sent'] and details['child_received_signal'] else 1)\n"
            )
            cmd = [PYTHON, "-c", script]
        else:
            cmd = ["true"]
    elif op == "network-outbound":
        hostport = target or "127.0.0.1"
        if ":" in hostport:
            host, port = hostport.split(":", 1)
        else:
            host, port = hostport, "80"
        nc = Path("/usr/bin/nc")
        cmd = [str(nc), "-z", "-w", "2", host, port]
    elif op == "process-exec":
        cmd = ["true"]
    else:
        cmd = ["true"]

    if blob_mode and WRAPPER.exists():
        full_cmd = [str(WRAPPER)]
        if wrapper_preflight:
            full_cmd += ["--preflight", wrapper_preflight]
        full_cmd += ["--blob", str(profile), "--"] + cmd
    elif self_apply_mode:
        full_cmd = cmd
    elif reader_mode:
        full_cmd = cmd
    elif writer_mode:
        full_cmd = cmd
    elif RUNNER.exists():
        full_cmd = [str(RUNNER), str(profile), "--"] + cmd
    else:
        return {"error": "sandbox_runner missing; sandbox-exec fallback is unsupported for stable runtime IR"}

    env = None
    if os.environ.get("SANDBOX_LORE_SEATBELT_CALLOUT") == "1":
        filter_type: Optional[int] = None
        callout_arg: Optional[str] = None
        seatbelt_op = op
        if op in {"file-read*", "file-write*", "file-read-metadata"} and target:
            filter_type = 0
            callout_arg = target
            if op == "file-read*":
                seatbelt_op = "file-read-data"
            elif op == "file-write*":
                seatbelt_op = "file-write-data"
        elif op == "mach-lookup" and target:
            filter_type = 5
            callout_arg = target
        elif op == "sysctl-read" and target:
            filter_type = 37
            callout_arg = target
        elif op in {"darwin-notification-post", "distributed-notification-post"} and target:
            filter_type = 34
            callout_arg = target

        if seatbelt_op and filter_type is not None and callout_arg is not None:
            env = dict(os.environ)
            env["SANDBOX_LORE_SEATBELT_OP"] = seatbelt_op
            env["SANDBOX_LORE_SEATBELT_FILTER_TYPE"] = str(filter_type)
            env["SANDBOX_LORE_SEATBELT_ARG"] = callout_arg

    started_at_unix_s = time.time()
    try:
        res = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )
        finished_at_unix_s = time.time()
        exit_code = res.returncode
        probe_details = None
        stdout_clean = res.stdout
        if metadata_driver:
            parsed: Optional[Dict[str, Any]] = None
            stdout_clean = ""
            if res.stdout:
                try:
                    parsed = json.loads(res.stdout)
                except Exception:
                    parsed = {"error": "metadata_runner_stdout_parse_failed"}
                    stdout_clean = res.stdout
            if isinstance(parsed, dict):
                probe_details = parsed
                status = parsed.get("status")
                if status == "ok":
                    exit_code = 0
                elif isinstance(parsed.get("errno"), int):
                    exit_code = int(parsed.get("errno") or 1)
                else:
                    exit_code = 1
        else:
            probe_details, stdout_clean = _extract_probe_details(res.stdout)
        return {
            "command": full_cmd,
            "exit_code": exit_code,
            "stdout": stdout_clean,
            "stderr": res.stderr,
            "probe_details": probe_details,
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }
    except FileNotFoundError as e:
        finished_at_unix_s = time.time()
        return {
            "error": f"sandbox-exec missing: {e}",
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }
    except Exception as e:
        finished_at_unix_s = time.time()
        return {
            "error": str(e),
            "cmd_started_at_unix_s": started_at_unix_s,
            "cmd_finished_at_unix_s": finished_at_unix_s,
            "cmd_duration_s": finished_at_unix_s - started_at_unix_s,
        }


def run_matrix(
    matrix_path: Path | str,
    out_dir: Path | None = None,
    runtime_profile_dir: Path | None = None,
    profile_paths: Dict[str, Path] | None = None,
    key_specific_rules: Dict[str, List[str]] | None = None,
) -> Path:
    """Run an expected-matrix harness and write runtime_results.json."""
    matrix_path = ensure_absolute(matrix_path, REPO_ROOT)
    out_dir = ensure_absolute(out_dir, REPO_ROOT) if out_dir else DEFAULT_OUT
    runtime_profile_dir = ensure_absolute(runtime_profile_dir, REPO_ROOT) if runtime_profile_dir else out_dir / "runtime_profiles"
    ensure_fixtures()
    assert matrix_path.exists(), f"missing expected matrix: {matrix_path}"
    matrix = json.loads(matrix_path.read_text())
    plan_id = matrix.get("plan_id") if isinstance(matrix, dict) else None
    profiles = matrix.get("profiles") or {}
    profile_paths = {k: ensure_absolute(v, REPO_ROOT) for k, v in (profile_paths or {}).items()}
    key_specific_rules = key_specific_rules or {}

    results: Dict[str, Any] = {}
    preflight_enabled = os.environ.get("SANDBOX_LORE_PREFLIGHT") != "0"
    preflight_force = os.environ.get("SANDBOX_LORE_PREFLIGHT_FORCE") == "1"
    for key, rec in profiles.items():
        profile_path = profile_paths.get(key)
        if not profile_path:
            blob = rec.get("blob")
            if blob:
                profile_path = ensure_absolute(blob, REPO_ROOT)
        if not profile_path or not profile_path.exists():
            status, note = classify_profile_status([], skipped_reason="no profile path")
            entry: Dict[str, Any] = {"status": status}
            if note:
                entry["notes"] = note
            results[key] = entry
            continue
        probes = rec.get("probes") or []
        metadata_only = bool(probes) and all(p.get("driver") == "metadata_runner" for p in probes)
        if metadata_only:
            runtime_profile = profile_path
        else:
            runtime_profile = prepare_profile(
                profile_path,
                key,
                key_specific_rules=key_specific_rules,
                runtime_profile_dir=runtime_profile_dir,
                profile_mode=rec.get("mode"),
            )
        profile_mode = rec.get("mode")
        preflight_record: Optional[Dict[str, Any]] = None
        preflight_blocked = False
        profile_preflight_mode = rec.get("preflight")
        if isinstance(profile_preflight_mode, dict):
            profile_preflight_mode = profile_preflight_mode.get("mode")
        if isinstance(profile_preflight_mode, str):
            profile_preflight_mode = profile_preflight_mode.strip().lower()
        else:
            profile_preflight_mode = None

        profile_preflight_enabled = preflight_enabled
        profile_preflight_force = preflight_force
        if profile_preflight_mode == "off":
            profile_preflight_enabled = False
        elif profile_preflight_mode == "force":
            profile_preflight_enabled = True
            profile_preflight_force = True
        elif profile_preflight_mode == "enforce":
            profile_preflight_enabled = True
            profile_preflight_force = False

        supported_preflight_input = runtime_profile.suffix == ".sb" or runtime_profile.suffixes[-2:] == [".sb", ".bin"]
        if profile_preflight_enabled and supported_preflight_input:
            try:
                from book.tools.preflight import preflight as preflight_mod  # type: ignore

                rec_obj = preflight_mod.preflight_path(runtime_profile)
                preflight_record = rec_obj.to_json()
                if (
                    preflight_record.get("classification") == "likely_apply_gated_for_harness_identity"
                    and not profile_preflight_force
                ):
                    preflight_blocked = True
            except Exception:
                preflight_record = None
                preflight_blocked = False
        probe_results = []
        for probe in probes:
            path_observation = None
            if _is_path_operation(probe.get("operation")):
                path_observation = _observe_path_unsandboxed(probe.get("target"))
            if preflight_blocked:
                actual = None
                raw = {"command": [], "exit_code": None, "stdout": "", "stderr": ""}
            else:
                wrapper_preflight = None
                if not profile_preflight_enabled:
                    wrapper_preflight = "off"
                elif profile_preflight_force:
                    wrapper_preflight = "force"
                else:
                    wrapper_preflight = "enforce"
                raw = run_probe(runtime_profile, probe, profile_mode, wrapper_preflight)
                actual = "allow" if raw.get("exit_code") == 0 else "deny"
            if not preflight_blocked and raw.get("error") is None:
                probe_name = probe.get("name") or probe.get("probe_id") or probe.get("operation") or "probe"
                observer_record = _capture_witness_observer(
                    probe_details=raw.get("probe_details"),
                    out_dir=out_dir,
                    profile_id=key,
                    probe_name=str(probe_name),
                    started_at_unix_s=raw.get("cmd_started_at_unix_s"),
                    finished_at_unix_s=raw.get("cmd_finished_at_unix_s"),
                    plan_id=plan_id if isinstance(plan_id, str) else None,
                    row_id=probe.get("expectation_id") if isinstance(probe.get("expectation_id"), str) else None,
                )
                if observer_record is not None:
                    raw["observer"] = observer_record
            expected = probe.get("expected")

            stderr = raw.get("stderr") or ""
            apply_markers = rt_contract.extract_sbpl_apply_markers(stderr)
            apply_marker = _first_marker(apply_markers, "apply")
            applied_marker = _first_marker(apply_markers, "applied")
            exec_marker = _first_marker(apply_markers, "exec")
            seatbelt_callouts = rt_contract.extract_seatbelt_callout_markers(stderr) or None

            failure_stage: Optional[str] = None
            failure_kind: Optional[str] = None
            observed_errno: Optional[int] = None
            apply_report: Optional[Dict[str, Any]] = None

            if preflight_blocked:
                failure_stage = "preflight"
                failure_kind = "preflight_apply_gate_signature"
            apply_rc = apply_marker.get("rc") if apply_marker else None
            if isinstance(apply_rc, int) and apply_rc != 0:
                failure_stage = "apply"
                if apply_marker:
                    api = apply_marker.get("api")
                    errbuf = apply_marker.get("errbuf")
                    err_class = apply_marker.get("err_class")
                    apply_report = {
                        "api": api,
                        "rc": apply_marker.get("rc"),
                        "errno": apply_marker.get("errno"),
                        "errbuf": errbuf,
                        "err_class": err_class,
                        "err_class_source": apply_marker.get("err_class_source"),
                    }
                    if err_class == "already_sandboxed":
                        failure_kind = "apply_already_sandboxed"
                    else:
                        failure_kind = f"{api}_failed" if api else "apply_failed"
                else:
                    failure_kind = "apply_failed"
                observed_errno = apply_marker.get("errno") if apply_marker else None
            else:
                if apply_marker:
                    apply_report = {
                        "api": apply_marker.get("api"),
                        "rc": apply_marker.get("rc"),
                        "errno": apply_marker.get("errno"),
                        "errbuf": apply_marker.get("errbuf"),
                        "err_class": apply_marker.get("err_class"),
                        "err_class_source": apply_marker.get("err_class_source"),
                    }
                exec_rc = exec_marker.get("rc") if exec_marker else None
                if isinstance(exec_rc, int) and exec_rc != 0:
                    failure_stage = "bootstrap"
                    observed_errno = exec_marker.get("errno") if exec_marker else None
                    if applied_marker is not None and observed_errno == 1:
                        failure_kind = "bootstrap_deny_process_exec"
                    else:
                        failure_kind = "bootstrap_exec_failed"
                elif raw.get("exit_code") not in (None, 0):
                    failure_stage = "probe"
                    failure_kind = "probe_nonzero_exit"
                    observed_errno = observed_errno or raw.get("exit_code")

            entrypoint = (raw.get("command") or [None])[0]
            entrypoint_path = Path(entrypoint) if isinstance(entrypoint, str) else None
            runner_info: Optional[Dict[str, Any]]
            if entrypoint == str(WRAPPER):
                runner_info = {"entrypoint": "SBPL-wrapper", "apply_model": "exec_wrapper", "apply_timing": "pre_exec"}
            elif entrypoint == str(RUNNER):
                runner_info = {"entrypoint": "sandbox_runner", "apply_model": "exec_wrapper", "apply_timing": "pre_exec"}
            elif entrypoint == str(SANDBOX_MACH_PROBE):
                runner_info = {"entrypoint": "sandbox_mach_probe", "apply_model": "self_apply", "apply_timing": "pre_syscall"}
            elif entrypoint == str(READER):
                runner_info = {"entrypoint": "sandbox_reader", "apply_model": "self_apply", "apply_timing": "pre_syscall"}
            elif entrypoint == str(WRITER):
                runner_info = {"entrypoint": "sandbox_writer", "apply_model": "self_apply", "apply_timing": "pre_syscall"}
            elif entrypoint == str(METADATA_RUNNER):
                runner_info = {"entrypoint": "metadata_runner", "apply_model": "self_apply", "apply_timing": "pre_syscall"}
            else:
                runner_info = None

            if runner_info is not None:
                preexisting = failure_kind == "apply_already_sandboxed"
                if failure_stage == "apply" and isinstance(apply_report, dict):
                    if apply_report.get("err_class") == "errno_eperm":
                        preexisting = True
                runner_info["preexisting_sandbox_suspected"] = preexisting

            if runner_info is not None and entrypoint_path:
                runner_info.update(
                    tooling.runner_info(
                        entrypoint_path,
                        repo_root=REPO_ROOT,
                        entrypoint=str(runner_info.get("entrypoint") or "runtime"),
                    )
                )

            runtime_result = {
                "status": "blocked" if preflight_blocked else ("success" if raw.get("exit_code") == 0 else "errno"),
                "errno": None if preflight_blocked or raw.get("exit_code") == 0 else observed_errno,
                "runtime_result_schema_version": rt_contract.CURRENT_RUNTIME_RESULT_SCHEMA_VERSION,
                "tool_marker_schema_version": rt_contract.CURRENT_TOOL_MARKER_SCHEMA_VERSION,
                "failure_stage": failure_stage,
                "failure_kind": failure_kind,
                "apply_report": apply_report,
                "runner_info": runner_info,
                "seatbelt_callouts": seatbelt_callouts,
            }

            violation_summary = None
            if observed_errno == 1:
                violation_summary = "EPERM"
            elif (
                failure_stage == "apply"
                and isinstance(apply_report, dict)
                and apply_report.get("err_class") == "errno_eperm"
            ):
                violation_summary = "EPERM"

            probe_results.append(
                {
                    "name": probe.get("name"),
                    "expectation_id": probe.get("expectation_id"),
                    **({"anchor_ctx_id": probe.get("anchor_ctx_id")} if probe.get("anchor_ctx_id") else {}),
                    "operation": probe.get("operation"),
                    "path": probe.get("target"),
                    "expected": expected,
                    "actual": actual,
                    "match": (expected == actual) if actual is not None else None,
                    "runtime_result": runtime_result,
                    "violation_summary": violation_summary,
                    **({"path_observation": path_observation} if path_observation else {}),
                    **{**raw, "command": relativize_command(raw.get("command") or [], REPO_ROOT)},
                    **(
                        {"notes": "preflight blocked: known apply-gate signature"}
                        if preflight_blocked
                        else {}
                    ),
                }
            )
        status, note = classify_profile_status(probe_results)
        entry = {
            "status": status,
            "profile_path": to_repo_relative(runtime_profile, REPO_ROOT),
            "base_profile_path": to_repo_relative(profile_path, REPO_ROOT),
            "preflight": preflight_record,
            "probes": probe_results,
        }
        if note:
            entry["notes"] = note
        results[key] = entry

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "runtime_results.json"
    out_path.write_text(json.dumps(results, indent=2))
    return out_path
