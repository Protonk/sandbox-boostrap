import unittest

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


if __name__ == "__main__":
    unittest.main()
