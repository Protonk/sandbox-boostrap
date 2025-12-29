import types
import sys
import os


def _install_ghidra_stubs():
    ghidra = types.ModuleType("ghidra")
    program = types.ModuleType("ghidra.program")
    model = types.ModuleType("ghidra.program.model")

    address = types.ModuleType("ghidra.program.model.address")
    class DummyAddressSet:
        pass
    address.AddressSet = DummyAddressSet

    data = types.ModuleType("ghidra.program.model.data")
    class DummyStringDataInstance:
        @staticmethod
        def isString(obj):
            return False
    data.StringDataInstance = DummyStringDataInstance

    model.address = address
    model.data = data
    program.model = model
    ghidra.program = program

    sys.modules["ghidra"] = ghidra
    sys.modules["ghidra.program"] = program
    sys.modules["ghidra.program.model"] = model
    sys.modules["ghidra.program.model.address"] = address
    sys.modules["ghidra.program.model.data"] = data


def _install_ghidra_bootstrap_stub():
    from book.api.ghidra.ghidra_lib import block_utils, io_utils, scan_utils

    bootstrap = types.ModuleType("ghidra_bootstrap")
    bootstrap.block_utils = block_utils
    bootstrap.io_utils = io_utils
    bootstrap.scan_utils = scan_utils
    bootstrap.node_scan_utils = types.ModuleType("node_scan_utils")
    sys.modules["ghidra_bootstrap"] = bootstrap


def test_safe_external_location_handles_missing_method(monkeypatch):
    _install_ghidra_stubs()
    _install_ghidra_bootstrap_stub()
    monkeypatch.setenv("GHIDRA_SKIP_AUTORUN", "1")
    from book.api.ghidra.scripts import kernel_string_refs as mod

    class NoExternal:
        pass

    class WithExternal:
        def __init__(self, value):
            self._value = value

        def getExternalLocation(self):
            return self._value

    assert mod._safe_external_location(NoExternal()) is None
    loc = object()
    assert mod._safe_external_location(WithExternal(loc)) is loc
