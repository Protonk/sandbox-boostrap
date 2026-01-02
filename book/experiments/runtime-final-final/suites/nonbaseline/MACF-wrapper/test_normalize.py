import importlib.util
import pathlib
import sys

# Ensure repo root is on path for normalize import
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.append(str(REPO_ROOT))


def load_normalize():
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location("macf_wrapper.normalize", here / "normalize.py")
    if spec is None or spec.loader is None:
        raise ImportError("Failed to load normalize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[attr-defined]
    return module


normalize = load_normalize()


def test_correlate_open():
    raw = [
        "EVENT kind=syscall sys=open world=w run_id=test pid=1 tid=2 exec=ls ts=10 path=/tmp flags=0x0",
        "EVENT kind=hook hook=mac_vnode_check_open world=w run_id=test pid=1 tid=2 exec=ls ts=15 ctx=0x1 vp=0x2 acc_mode=1",
    ]
    events = normalize.parse_raw_log(raw)
    output = normalize.build_output(
        events=events,
        runtime_world_id="w",
        run_id="test",
        os_build=None,
        kernel_version=None,
        provider="fbt",
        module="mach_kernel",
        hooks=["mac_vnode_check_open"],
        run_command="/bin/ls",
        target_pid=None,
        static_refs={},
        scenario=None,
        scenario_description=None,
    )
    assert len(output["events"]) == 1
    evt = output["events"][0]
    assert evt["hook"] == "mac_vnode_check_open"
    assert evt["derived_operation"] == "vnode_open"
    assert evt["operation_flags"] == ["read"]
    assert evt["syscall"]["sys"] == "open"
    assert evt["syscall"]["path"] == "/tmp"


def test_correlate_setxattr():
    raw = [
        "EVENT kind=syscall sys=setxattr world=w run_id=test pid=2 tid=3 exec=xattr ts=20 path=/tmp/foo name=com.test size=5",
        "EVENT kind=hook hook=mac_vnop_setxattr world=w run_id=test pid=2 tid=3 exec=xattr ts=25 vp=0x3 name_ptr=0x4 buf_ptr=0x5 len=5",
    ]
    events = normalize.parse_raw_log(raw)
    output = normalize.build_output(
        events=events,
        runtime_world_id="w",
        run_id="test",
        os_build=None,
        kernel_version=None,
        provider="fbt",
        module="mach_kernel",
        hooks=["mac_vnop_setxattr"],
        run_command="/usr/bin/xattr",
        target_pid=None,
        static_refs={},
        scenario=None,
        scenario_description=None,
    )
    assert len(output["events"]) == 1
    evt = output["events"][0]
    assert evt["hook"] == "mac_vnop_setxattr"
    assert evt["derived_operation"] == "vnode_setxattr"
    assert evt["syscall"]["sys"] == "setxattr"
    assert evt["syscall"]["path"] == "/tmp/foo"
    assert evt["syscall"]["xattr_name"] == "com.test"
