"""CodeDirectory 解析与逐页核验的单元测试。"""

from __future__ import annotations

import struct
import unittest

from app.codedir import verify_payload
from tests.fixtures import build_payload


def _patch_u32be(payload: bytes, offset: int, value: int) -> bytes:
    buf = bytearray(payload)
    struct.pack_into(">I", buf, offset, value)
    return bytes(buf)


class ValidPayloadTests(unittest.TestCase):
    def test_valid_payload_passes(self):
        payload, info = build_payload()
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "pass")
        self.assertIsNone(result["reason"])
        self.assertIsNone(result["first_failing_slot"])
        self.assertEqual(len(result["pages"]), info["n_code_slots"])
        self.assertTrue(all(p["match"] for p in result["pages"]))
        # 页证据按槽号升序
        self.assertEqual([p["slot"] for p in result["pages"]],
                         list(range(info["n_code_slots"])))

    def test_summary_and_coverage(self):
        payload, info = build_payload(n_pages=6, page_exp=12)
        result = verify_payload(payload)
        cd = result["code_directory"]
        self.assertEqual(cd["hash_type"], "sha256")
        self.assertEqual(cd["hash_size"], 32)
        self.assertEqual(cd["page_size"], 4096)
        self.assertEqual(cd["page_exponent"], 12)
        self.assertEqual(cd["n_code_slots"], 6)
        self.assertEqual(cd["code_limit"], info["code_limit"])
        self.assertEqual(cd["ident"], "com.vendor.payload.fw")
        cov = result["coverage"]
        self.assertEqual(cov["start"], 0)
        self.assertEqual(cov["end"], info["code_limit"])
        self.assertEqual(cov["n_pages"], 6)
        self.assertEqual(cov["page_size"], 4096)

    def test_partial_last_page(self):
        payload, info = build_payload()
        result = verify_payload(payload)
        last = result["pages"][-1]
        self.assertEqual(last["length"], info["page_size"] - 37)
        self.assertEqual(last["offset"] + last["length"], info["code_limit"])

    def test_min_and_max_page_exponents(self):
        for exp in (9, 16):
            payload, _ = build_payload(n_pages=3, page_exp=exp)
            result = verify_payload(payload)
            self.assertEqual(result["verdict"], "pass", exp)

    def test_special_slots_present(self):
        payload, _ = build_payload(n_special=5)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "pass")
        self.assertEqual(result["code_directory"]["n_special_slots"], 5)

    def test_all_mach_o_flavours(self):
        for bits in (32, 64):
            for endian in ("<", ">"):
                payload, _ = build_payload(bits=bits, endian=endian)
                result = verify_payload(payload)
                self.assertEqual(result["verdict"], "pass", (bits, endian))

    def test_supported_versions(self):
        for version in (0x20000, 0x20100, 0x20200, 0x20300, 0x20400):
            payload, _ = build_payload(version=version)
            result = verify_payload(payload)
            self.assertEqual(result["verdict"], "pass", hex(version))


class PageMismatchTests(unittest.TestCase):
    def test_tampered_middle_page_reports_first_failing_slot(self):
        payload, _ = build_payload(tamper_slot=2)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["first_failing_slot"], 2)
        self.assertIn("2", result["reason"])
        matches = [p["match"] for p in result["pages"]]
        self.assertEqual(matches, [True, True, False, True, True])

    def test_tampered_first_page(self):
        payload, _ = build_payload(tamper_slot=0)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["first_failing_slot"], 0)

    def test_tampered_last_partial_page(self):
        payload, info = build_payload(tamper_slot=4)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertEqual(result["first_failing_slot"], info["n_code_slots"] - 1)


class UnsupportedParameterTests(unittest.TestCase):
    def test_unsupported_hash_type(self):
        payload, _ = build_payload(hash_type=1, hash_size=20)  # SHA-1
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("散列类型", result["reason"])

    def test_hash_size_mismatch(self):
        payload, _ = build_payload(hash_type=2, hash_size=20)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("散列槽长度", result["reason"])

    def test_unsupported_page_exponent(self):
        payload, info = build_payload()
        cd = info["cd_file_offset"]
        for bad_exp in (3, 8, 17, 24):
            buf = bytearray(payload)
            buf[cd + 39] = bad_exp
            result = verify_payload(bytes(buf))
            self.assertEqual(result["verdict"], "fail", bad_exp)
            self.assertIn("页指数", result["reason"])

    def test_zero_code_slots(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 28, 0)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("nCodeSlots", result["reason"])

    def test_excessive_code_slots(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 28, 5000)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("代码槽数", result["reason"])

    def test_slot_count_inconsistent_with_code_limit(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 28,
                               info["n_code_slots"] + 1)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("不一致", result["reason"])

    def test_excessive_special_slots(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 24, 100)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("特殊槽数", result["reason"])

    def test_unsupported_version(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 8, 0x20500)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("版本", result["reason"])


class CodeLimitTests(unittest.TestCase):
    def test_code_limit_zero(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 32, 0)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("codeLimit", result["reason"])

    def test_code_limit_beyond_file(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 32,
                               len(payload) + 4096)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("codeLimit", result["reason"])

    def test_code_limit_overlaps_signature(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 32,
                               info["dataoff"] + 16)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("codeLimit", result["reason"])


class StructuralTests(unittest.TestCase):
    def test_empty_payload(self):
        result = verify_payload(b"")
        self.assertEqual(result["verdict"], "fail")

    def test_oversize_payload(self):
        result = verify_payload(b"\x00" * (2 * 1024 * 1024 + 1))
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("2 MiB", result["reason"])

    def test_not_a_macho(self):
        result = verify_payload(b"\x11\x22\x33\x44" * 64)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("Mach-O", result["reason"])

    def test_truncated_header(self):
        result = verify_payload(b"\xcf\xfa\xed\xfe" + b"\x00" * 10)
        self.assertEqual(result["verdict"], "fail")

    def test_truncated_slice(self):
        payload, _ = build_payload()
        result = verify_payload(payload[:100])
        self.assertEqual(result["verdict"], "fail")

    def test_no_code_signature_command(self):
        payload, info = build_payload()
        # 把唯一的 load command 改成 LC_SYMTAB
        payload = _patch_u32be(payload, info["lc_file_offset"], 0x2)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("LC_CODE_SIGNATURE", result["reason"])

    def test_duplicate_code_signature_commands(self):
        payload, info = build_payload()
        buf = bytearray(payload)
        hdr = info["header_size"]
        lc = bytes(buf[hdr:hdr + 16])
        # 在第一个 LC 之后塞入第二个相同的 LC（覆盖填充字节）
        buf[hdr + 16:hdr + 32] = lc
        struct.pack_into("<I", buf, 16, 2)   # ncmds = 2
        struct.pack_into("<I", buf, 20, 32)  # sizeofcmds = 32
        result = verify_payload(bytes(buf))
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("多个", result["reason"])

    def test_signature_region_past_eof(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["lc_file_offset"] + 12,
                               len(payload) * 2)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")

    def test_not_a_superblob(self):
        payload, info = build_payload()
        # SuperBlob magic 换成裸 CodeDirectory magic
        payload = _patch_u32be(payload, info["sb_file_offset"], 0xFADE0C02)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("SuperBlob", result["reason"])

    def test_superblob_length_exceeds_region(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["sb_file_offset"] + 4,
                               info["sb_length"] + 256)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("SuperBlob", result["reason"])

    def test_superblob_index_offset_out_of_range(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["sb_file_offset"] + 16, 8)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("索引", result["reason"])

    def test_bad_codedirectory_magic(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"], 0xDEADBEEF)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("CodeDirectory", result["reason"])

    def test_codedirectory_length_exceeds_superblob(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 4,
                               info["cd_length"] + 256)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")

    def test_hash_offset_overlaps_header(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 16, 20)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("hashOffset", result["reason"])

    def test_code_slots_overflow_codedirectory(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 16,
                               info["hash_offset"] + 64)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("哈希槽", result["reason"])

    def test_special_slots_overlap_header(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 24, 10)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("重叠", result["reason"])

    def test_ident_offset_out_of_range(self):
        payload, info = build_payload()
        payload = _patch_u32be(payload, info["cd_file_offset"] + 20,
                               info["cd_length"] + 8)
        result = verify_payload(payload)
        self.assertEqual(result["verdict"], "fail")
        self.assertIn("identOffset", result["reason"])


if __name__ == "__main__":
    unittest.main()
