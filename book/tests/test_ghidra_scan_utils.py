import hashlib
import os
import tempfile
import unittest

from book.api import path_utils
from book.api.ghidra.ghidra_lib import scan_utils


class ScanUtilsTests(unittest.TestCase):
    def test_parse_address_handles_negative_hex(self):
        self.assertEqual(scan_utils.parse_address("0x-1"), (1 << 64) - 1)
        self.assertEqual(scan_utils.parse_address("-0x2"), (1 << 64) - 2)

    def test_parse_address_handles_positive(self):
        self.assertEqual(scan_utils.parse_address("0x10"), 0x10)
        self.assertEqual(scan_utils.parse_address(0x20), 0x20)

    def test_format_address(self):
        self.assertEqual(scan_utils.format_address("0x-1"), "0xffffffffffffffff")
        self.assertEqual(scan_utils.format_address(0x2a), "0x2a")

    def test_parse_hex(self):
        self.assertEqual(scan_utils.parse_hex("deadbeef"), 0xdeadbeef)
        self.assertEqual(scan_utils.parse_hex("0x10"), 0x10)
        self.assertEqual(scan_utils.parse_hex("-0x1"), (1 << 64) - 1)

    def test_parse_signed_hex(self):
        self.assertEqual(scan_utils.parse_signed_hex("0x-1"), -1)
        self.assertEqual(scan_utils.parse_signed_hex("0xffffffffffffffff"), -1)
        self.assertEqual(scan_utils.parse_signed_hex("0x2a"), 0x2a)

    def test_format_signed_hex(self):
        self.assertEqual(scan_utils.format_signed_hex(-1), "0x-1")
        self.assertEqual(scan_utils.format_signed_hex(0x2a), "0x2a")

    def test_signed_unsigned_helpers(self):
        self.assertEqual(scan_utils.to_unsigned(-1), (1 << 64) - 1)
        self.assertEqual(scan_utils.to_signed((1 << 64) - 1), -1)

    def test_exact_offset_match(self):
        self.assertTrue(scan_utils.exact_offset_match("str w8,[x20, #0xc0]", "0xc0"))
        self.assertFalse(scan_utils.exact_offset_match("str w8,[x20, #0xc00]", "0xc0"))
        self.assertTrue(scan_utils.exact_offset_match("ldr w9,[x20, #0x74]", 0x74))

    def test_is_stack_access(self):
        self.assertTrue(scan_utils.is_stack_access("str w8,[sp, #0xc0]"))
        self.assertTrue(scan_utils.is_stack_access("str w8,[x29, #0x20]"))
        self.assertFalse(scan_utils.is_stack_access("str w8,[x20, #0xc0]"))

    def test_classify_mnemonic(self):
        self.assertEqual(scan_utils.classify_mnemonic("ldr"), "load")
        self.assertEqual(scan_utils.classify_mnemonic("ldp"), "load")
        self.assertEqual(scan_utils.classify_mnemonic("str"), "store")
        self.assertEqual(scan_utils.classify_mnemonic("stp"), "store")
        self.assertEqual(scan_utils.classify_mnemonic("add"), "other")

    def test_repo_root_helpers(self):
        repo_root = path_utils.find_repo_root()
        self.assertEqual(scan_utils.find_repo_root(), str(repo_root))
        rel = scan_utils.to_repo_relative(os.path.join(str(repo_root), "book"), str(repo_root))
        self.assertEqual(rel, "book")

    def test_sha256_path(self):
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"scan-utils-test")
            tmp_path = tmp.name
        try:
            expected = hashlib.sha256(b"scan-utils-test").hexdigest()
            self.assertEqual(scan_utils.sha256_path(tmp_path), expected)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    unittest.main()
