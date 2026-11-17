import argparse
import struct
import unittest

import ntfs_fixture as fx
import util

mft = util.module()


class TimeTests(unittest.TestCase):

    def test_filetime_zero(self):
        self.assertEqual(mft.filetime_to_iso(0), "1601-01-01T00:00:00.0000000Z")

    def test_filetime_none(self):
        self.assertEqual(mft.filetime_to_iso(None), "")

    def test_filetime_unix_epoch(self):
        self.assertEqual(mft.filetime_to_iso(mft.EPOCH_DIFF_100NS), "1970-01-01T00:00:00.0000000Z")

    def test_filetime_keeps_100ns(self):
        self.assertEqual(mft.filetime_to_iso(mft.EPOCH_DIFF_100NS + 1234567), "1970-01-01T00:00:00.1234567Z")

    def test_filetime_out_of_range(self):
        self.assertTrue(mft.filetime_to_iso(0x7FFFFFFFFFFFFFFF).startswith("INVALID("))

    def test_filetime_to_epoch(self):
        self.assertEqual(mft.filetime_to_epoch(mft.EPOCH_DIFF_100NS + 15 * 10000000), 15)
        self.assertEqual(mft.filetime_to_epoch(0), 0)

    def test_user_time_roundtrip(self):
        for text in ("2026-05-01", "2026-05-01T08:00", "2026-05-01 08:00:30", "2026-05-01T08:00:30.5Z"):
            iso = mft.filetime_to_iso(mft.parse_user_time(text))
            self.assertTrue(iso.startswith("2026-05-01T"), iso)

    def test_user_time_rejects_garbage(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            mft.parse_user_time("yesterday")


class DataRunTests(unittest.TestCase):

    def test_roundtrip(self):
        runs = [(1000, 8), (None, 16), (20, 3), (70000, 300), (5, 1)]
        self.assertEqual(mft.parse_data_runs(fx.encode_runs(runs)), runs)

    def test_text(self):
        self.assertEqual(mft.runs_to_text([(10, 2), (None, 4)]), "10:2;SPARSE:4")

    def test_truncated_header(self):
        with self.assertRaises(mft.MftError):
            mft.parse_data_runs(b"\x21\x08")

    def test_zero_length_size(self):
        with self.assertRaises(mft.MftError):
            mft.parse_data_runs(b"\x10\x05\x00")

    def test_negative_lcn(self):
        with self.assertRaises(mft.MftError):
            mft.parse_data_runs(b"\x11\x04\x80\x00")


class RecordTests(unittest.TestCase):

    def record(self, **kwargs):
        attrs = [fx.std_info(fx.filetime(1)), fx.file_name(5, 5, "a.txt", fx.filetime(1)),
                 fx.resident_attr(0x80, b"hello", 4)]
        return fx.make_record(40, attrs, **kwargs)

    def test_parse(self):
        rec = mft.parse_record(self.record(), 40)
        self.assertTrue(rec.valid and rec.in_use and rec.fixup_ok)
        self.assertEqual(rec.stored_number, 40)
        self.assertEqual(rec.best_file_name().name, "a.txt")
        self.assertEqual(rec.get_data_attr("")[0].value, b"hello")
        self.assertEqual(rec.error, "")

    def test_fixup_mismatch_is_flagged(self):
        raw = bytearray(self.record())
        raw[510:512] = b"\xAA\xBB"
        rec = mft.parse_record(bytes(raw), 40)
        self.assertTrue(rec.valid)
        self.assertFalse(rec.fixup_ok)

    def test_empty_slot(self):
        rec = mft.parse_record(b"\x00" * 1024, 7)
        self.assertFalse(rec.valid)
        self.assertIn("empty", rec.error)

    def test_bad_signature(self):
        rec = mft.parse_record(b"JUNK" + b"\x00" * 1020, 7)
        self.assertFalse(rec.valid)

    def test_baad_signature(self):
        rec = mft.parse_record(self.record(signature=b"BAAD"), 40)
        self.assertIn("BAAD", rec.error)

    def test_short_buffer(self):
        self.assertFalse(mft.parse_record(b"FILE", 1).valid)

    def test_truncated_attribute_header(self):
        attrs = [fx.std_info(fx.filetime(1)), fx.file_name(5, 5, "x.txt", fx.filetime(1)),
                 fx.resident_attr(0xD0, b"\x00" * 728, 4)]
        raw = bytearray(fx.make_record(41, attrs))
        struct.pack_into("<II", raw, 1008, 0x80, 16)
        rec = mft.parse_record(bytes(raw), 41)
        self.assertTrue(rec.valid)
        self.assertIn("truncated header", rec.error)
        self.assertEqual(rec.best_file_name().name, "x.txt")

    def test_attribute_length_past_record(self):
        raw = bytearray(self.record())
        struct.pack_into("<I", raw, 0x38 + 4, 5000)
        rec = mft.parse_record(bytes(raw), 40)
        self.assertIn("bad length", rec.error)

    def test_namespace_preference(self):
        attrs = [fx.std_info(fx.filetime(1)),
                 fx.file_name(5, 5, "LONGFI~1.TXT", fx.filetime(1), namespace=2, attr_id=1),
                 fx.file_name(5, 5, "long file name.txt", fx.filetime(1), namespace=1, attr_id=2)]
        rec = mft.parse_record(fx.make_record(42, attrs), 42)
        self.assertEqual(rec.best_file_name().name, "long file name.txt")
        self.assertEqual(rec.extension(), "txt")


class Lznt1Tests(unittest.TestCase):

    def roundtrip(self, data):
        packed = fx.lznt1_compress(data)
        self.assertEqual(mft.lznt1_decompress(packed, len(data)), data)
        return packed

    def test_repetitive(self):
        data = b"abcabcabc" * 3000
        self.assertLess(len(self.roundtrip(data)), len(data) // 4)

    def test_text(self):
        self.roundtrip(b"".join(b"row %d of the table\n" % i for i in range(2500)))

    def test_incompressible(self):
        self.roundtrip(fx.pattern("noise", 20000))

    def test_short_tail(self):
        self.roundtrip(b"x" * 4096 + b"tail")

    def test_zero_fill_after_stream(self):
        data = b"hello hello hello hello"
        packed = fx.lznt1_compress(data) + b"\x00" * 100
        self.assertEqual(mft.lznt1_decompress(packed, 4096), data + b"\x00" * (4096 - len(data)))

    def test_bad_back_reference(self):
        chunk = bytes([0x01]) + struct.pack("<H", 0x0FFF)
        with self.assertRaises(mft.MftError):
            mft.lznt1_decompress(struct.pack("<H", 0xB000 | (len(chunk) - 1)) + chunk, 4096)


class BitmapTests(unittest.TestCase):

    def setUp(self):
        data = bytearray(16)
        for lcn in (8, 9, 10, 40):
            data[lcn >> 3] |= 1 << (lcn & 7)
        self.bitmap = mft.VolumeBitmap(bytes(data), 128)

    def test_states(self):
        self.assertEqual(self.bitmap.runs_state([(0, 8)]), "yes")
        self.assertEqual(self.bitmap.runs_state([(8, 3)]), "no")
        self.assertEqual(self.bitmap.runs_state([(6, 4)]), "partial")
        self.assertEqual(self.bitmap.runs_state([(0, 4), (None, 9), (40, 1)]), "partial")

    def test_outside_bitmap(self):
        self.assertEqual(self.bitmap.runs_state([(120, 20)]), "?")

    def test_only_sparse(self):
        self.assertEqual(self.bitmap.runs_state([(None, 5)]), "")


class SharedRunTests(unittest.TestCase):

    def test_overlap(self):
        shared = mft.shared_run_owners([(100, 110, 1), (105, 120, 2), (300, 310, 3)])
        self.assertEqual(shared, {1: [2], 2: [1]})

    def test_adjacent_runs_do_not_overlap(self):
        self.assertEqual(mft.shared_run_owners([(100, 110, 1), (110, 120, 2)]), {})

    def test_same_owner_is_ignored(self):
        self.assertEqual(mft.shared_run_owners([(100, 110, 1), (105, 108, 1)]), {})

    def test_three_way(self):
        shared = mft.shared_run_owners([(0, 50, 1), (10, 20, 2), (40, 60, 3)])
        self.assertEqual(shared, {1: [2, 3], 2: [1], 3: [1]})


class PathResolverTests(unittest.TestCase):

    def resolver(self, entries):
        res = mft.PathResolver()
        res.index.update(entries)
        return res

    def test_plain(self):
        res = self.resolver({30: (5, 5, "dir", 1, True), 31: (30, 1, "file", 1, True)})
        self.assertEqual(res.resolve(31), "dir/file")

    def test_deleted_parent_keeps_path(self):
        res = self.resolver({30: (5, 5, "dir", 2, False), 31: (30, 1, "file", 2, False)})
        self.assertEqual(res.resolve(31), "dir/file")

    def test_reused_parent_is_orphan(self):
        res = self.resolver({30: (5, 5, "other", 2, True), 31: (30, 1, "file", 2, False)})
        self.assertEqual(res.resolve(31), "$OrphanFiles/<parent-30-seq-mismatch>/file")

    def test_reused_and_deleted_again_is_orphan(self):
        res = self.resolver({30: (5, 5, "other", 3, False), 31: (30, 1, "file", 2, False)})
        self.assertEqual(res.resolve(31), "$OrphanFiles/<parent-30-seq-mismatch>/file")

    def test_sequence_wraps_to_one(self):
        res = self.resolver({30: (5, 5, "dir", 1, False), 31: (30, 0xFFFF, "file", 2, False)})
        self.assertEqual(res.resolve(31), "dir/file")

    def test_missing_parent(self):
        res = self.resolver({31: (99, 1, "file", 1, True)})
        self.assertEqual(res.resolve(31), "$OrphanFiles/<parent-99-missing>/file")

    def test_loop(self):
        res = self.resolver({30: (31, 1, "a", 1, True), 31: (30, 1, "b", 1, True)})
        self.assertIn("<loop>", res.resolve(30))

    def test_unknown_record(self):
        self.assertEqual(mft.PathResolver().resolve(77), "$OrphanFiles/<unknown-77>")


class HelperTests(unittest.TestCase):

    def test_record_numbers(self):
        self.assertEqual(mft._parse_record_numbers(["5", "7,9-11", " 20 "]), [5, 7, 9, 10, 11, 20])

    def test_record_numbers_reject(self):
        for bad in ("abc", "5-", "9-3", "-5", "1,,x"):
            with self.assertRaises(mft.MftError):
                mft._parse_record_numbers([bad])

    def test_safe_name(self):
        self.assertEqual(mft._safe_name('a<b>:"c/d\\e|f?g*h'), "a_b___c_d_e_f_g_h")
        self.assertEqual(mft._safe_name("..."), "unnamed")
        self.assertEqual(mft._safe_name("x\x00\x1fy"), "x__y")

    def test_human_size(self):
        self.assertEqual(mft.human_size(0), "0 B")
        self.assertEqual(mft.human_size(1536), "1.5 KB")
        self.assertEqual(mft.human_size(None), "?")

    def test_flags_text(self):
        self.assertEqual(mft.flags_to_text(0x26), "HIDDEN|SYSTEM|ARCHIVE")

    def test_boot_sector_check(self):
        self.assertTrue(mft.is_ntfs_boot_sector(fx.Volume().boot_sector()))
        self.assertFalse(mft.is_ntfs_boot_sector(b"\x00" * 512))

    def test_attribute_list_rejects_garbage(self):
        with self.assertRaises(mft.MftError):
            mft.parse_attribute_list(struct.pack("<IH", 0x77, 32) + b"\x00" * 26)


if __name__ == "__main__":
    unittest.main()
