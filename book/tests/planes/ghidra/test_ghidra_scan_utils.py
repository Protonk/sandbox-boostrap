import hashlib
import os
import tempfile

from book.api import path_utils
from book.api.ghidra.ghidra_lib import scan_utils


def test_parse_address_handles_negative_hex():
    assert scan_utils.parse_address("0x-1") == (1 << 64) - 1
    assert scan_utils.parse_address("-0x2") == (1 << 64) - 2


def test_parse_address_handles_positive():
    assert scan_utils.parse_address("0x10") == 0x10
    assert scan_utils.parse_address(0x20) == 0x20


def test_format_address():
    assert scan_utils.format_address("0x-1") == "0xffffffffffffffff"
    assert scan_utils.format_address(0x2a) == "0x2a"


def test_parse_hex():
    assert scan_utils.parse_hex("deadbeef") == 0xdeadbeef
    assert scan_utils.parse_hex("0x10") == 0x10
    assert scan_utils.parse_hex("-0x1") == (1 << 64) - 1


def test_parse_signed_hex():
    assert scan_utils.parse_signed_hex("0x-1") == -1
    assert scan_utils.parse_signed_hex("0xffffffffffffffff") == -1
    assert scan_utils.parse_signed_hex("0x2a") == 0x2a


def test_format_signed_hex():
    assert scan_utils.format_signed_hex(-1) == "0x-1"
    assert scan_utils.format_signed_hex(0x2a) == "0x2a"


def test_signed_unsigned_helpers():
    assert scan_utils.to_unsigned(-1) == (1 << 64) - 1
    assert scan_utils.to_signed((1 << 64) - 1) == -1


def test_exact_offset_match():
    assert scan_utils.exact_offset_match("str w8,[x20, #0xc0]", "0xc0")
    assert not scan_utils.exact_offset_match("str w8,[x20, #0xc00]", "0xc0")
    assert scan_utils.exact_offset_match("ldr w9,[x20, #0x74]", 0x74)


def test_is_stack_access():
    assert scan_utils.is_stack_access("str w8,[sp, #0xc0]")
    assert scan_utils.is_stack_access("str w8,[x29, #0x20]")
    assert not scan_utils.is_stack_access("str w8,[x20, #0xc0]")


def test_classify_mnemonic():
    assert scan_utils.classify_mnemonic("ldr") == "load"
    assert scan_utils.classify_mnemonic("ldp") == "load"
    assert scan_utils.classify_mnemonic("str") == "store"
    assert scan_utils.classify_mnemonic("stp") == "store"
    assert scan_utils.classify_mnemonic("add") == "other"


def test_repo_root_helpers():
    repo_root = path_utils.find_repo_root()
    assert scan_utils.find_repo_root() == str(repo_root)
    rel = scan_utils.to_repo_relative(os.path.join(str(repo_root), "book"), str(repo_root))
    assert rel == "book"


def test_sha256_path():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"scan-utils-test")
        tmp_path = tmp.name
    try:
        expected = hashlib.sha256(b"scan-utils-test").hexdigest()
        assert scan_utils.sha256_path(tmp_path) == expected
    finally:
        os.unlink(tmp_path)
