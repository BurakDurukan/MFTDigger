import csv
import json
import os
import shutil
import tempfile
import unittest

import ntfs_fixture as fx
import util

mft = util.module()


class HardeningCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mftdigger_hardening_")
        cls.volume, cls.rec = fx.build_standard()
        cls.raw = cls.volume.build()
        cls.image = cls.write("volume.img", cls.raw)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def write(cls, name, data):
        path = os.path.join(cls.tmp, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def out(self, name):
        return os.path.join(self.tmp, name)

    def user_paths(self, image, *extra):
        rc, stdout, stderr = util.run("dump", image, "--format", "jsonl", *extra)
        self.assertEqual(rc, 0, stderr)
        return {r["record"]: r["all_paths"] for r in util.parse_jsonl(stdout) if r["record"] >= 24}

    def names(self, *criteria):
        rc, stdout, stderr = util.run("search", self.image, "--format", "jsonl", *criteria)
        self.assertNotIn("Traceback", stderr)
        by_number = {number: key for key, number in self.rec.items()}
        return {by_number[r["record"]] for r in util.parse_jsonl(stdout) if r["record"] >= 24}


class PartitionTests(HardeningCase):

    def test_logical_partition_in_extended_chain(self):
        image = self.write("extended.img", fx.wrap_mbr_extended(self.raw))
        self.assertEqual(self.user_paths(image), self.user_paths(self.image))
        rc, stdout, _ = util.run("info", image, "--partitions")
        self.assertEqual(rc, 0)
        table = stdout.split("Partition table:")[1]
        self.assertIn("MBR:0x07(logical)", table)
        self.assertIn("MBR:0x83(logical)", table)
        self.assertEqual(table.count("NTFS"), 1)

    def test_extended_table_with_more_than_one_partition(self):
        image = self.write("extended3.img", fx.wrap_mbr_extended_third_entry(self.raw))
        self.assertEqual(self.user_paths(image), self.user_paths(self.image))
        rc, stdout, _ = util.run("info", image, "--partitions")
        self.assertEqual(rc, 0)
        table = stdout.split("Partition table:")[1]
        self.assertEqual(table.count("MBR:0x83(logical)"), 2)
        self.assertEqual(table.count("MBR:0x07(logical)"), 1)

    def test_gpt_with_4096_byte_sectors(self):
        image = self.write("gpt4k.img", fx.wrap_gpt(self.raw, 256, 4096))
        self.assertEqual(self.user_paths(image), self.user_paths(self.image))

    def test_volume_has_no_partition_table(self):
        rc, stdout, _ = util.run("info", self.image, "--partitions")
        self.assertEqual(rc, 0)
        self.assertIn("Partition table: none", stdout)

    def test_foreign_volumes_are_named(self):
        expected = {"bitlocker": "BitLocker-encrypted volume", "exfat": "exFAT volume", "refs": "ReFS volume",
                    "fat32": "FAT volume"}
        for kind, text in expected.items():
            image = self.write(kind + ".img", fx.foreign_boot_sector(kind) + b"\x00" * 8192)
            rc, _, stderr = util.run("info", image)
            self.assertEqual(rc, 1, kind)
            self.assertIn(text, stderr, kind)
            self.assertNotIn("Traceback", stderr)

    def test_bitlocker_partition_inside_a_disk(self):
        volume = fx.foreign_boot_sector("bitlocker") + b"\x00" * (64 * 512 - 512)
        image = self.write("bitlocker_disk.img", fx.wrap_mbr(volume))
        rc, _, stderr = util.run("info", image)
        self.assertEqual(rc, 1)
        self.assertIn("No NTFS partition found", stderr)
        self.assertIn("BitLocker", stderr)
        rc, _, stderr = util.run("info", image, "--partition", "0")
        self.assertIn("it is a BitLocker-encrypted volume", stderr)
        rc, _, stderr = util.run("info", image, "--offset", str(128 * 512))
        self.assertIn("BitLocker", stderr)

    def test_file_that_only_starts_like_an_mft(self):
        rc, _, stderr = util.run("info", self.write("short.mft", b"FILE0\x00\x03\x00"))
        self.assertEqual(rc, 1)
        self.assertIn("too short", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_record0_row_comes_from_the_mirror(self):
        raw = bytearray(self.raw)
        start = self.volume.mft_lcn * fx.CLUSTER
        raw[start:start + fx.RECORD] = b"\x00" * fx.RECORD
        rc, stdout, stderr = util.run("dump", self.write("norecord0.img", raw), "--format", "jsonl")
        self.assertEqual(rc, 0, stderr)
        rows = {r["record"]: r for r in util.parse_jsonl(stdout)}
        self.assertEqual(rows[0]["path"], "$MFT")


class OutputSafetyTests(HardeningCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        v = fx.Volume()
        cls.hostile = {
            "formula": v.add_file("=HYPERLINK.txt", b"a"),
            "at": v.add_file("@SUM.txt", b"b"),
            "escape": v.add_file("red\x1b[31m.txt", fx.pattern("escape", 5000)),
            "bidi": v.add_file("gpj.\u202etxt", b"c"),
            "script": v.add_file("<!--<script>alert(1)</script>.txt", b"d"),
            "tick": v.add_file("a`b.txt", b"e"),
        }
        cls.hostile_image = cls.write("hostile.img", v.build())

    def test_excel_safe_is_opt_in(self):
        plain, safe = self.out("plain.csv"), self.out("safe.csv")
        util.run("dump", self.hostile_image, "-o", plain)
        util.run("dump", self.hostile_image, "-o", safe, "--excel-safe")
        for path, prefix in ((plain, ""), (safe, "'")):
            with open(path, encoding="utf-8", newline="") as fh:
                rows = {int(r["record"]): r for r in csv.DictReader(fh)}
            self.assertEqual(rows[self.hostile["formula"]]["name"], prefix + "=HYPERLINK.txt")
            self.assertEqual(rows[self.hostile["formula"]]["path"], prefix + "=HYPERLINK.txt")
            self.assertEqual(rows[self.hostile["at"]]["name"], prefix + "@SUM.txt")
            self.assertEqual(rows[0]["path"], "$MFT")
            self.assertEqual(rows[self.hostile["formula"]]["size"], "1")

    def test_excel_safe_applies_to_tsv_and_report(self):
        source = self.out("hostile.jsonl")
        util.run("dump", self.hostile_image, "--format", "jsonl", "-o", source)
        rc, stdout, _ = util.run("report", source, "--name", "=*", "--format", "tsv", "--excel-safe")
        self.assertEqual(rc, 0)
        self.assertIn("\t'=HYPERLINK.txt\t", stdout)

    def test_text_output_escapes_control_characters(self):
        for key, shown in (("escape", "red\\x1b[31m.txt"), ("bidi", "gpj.\\u202etxt")):
            rc, stdout, _ = util.run("search", self.hostile_image, "--record", self.hostile[key])
            self.assertEqual(rc, 0)
            self.assertIn(shown, stdout)
            self.assertNotIn("\x1b", stdout)
            self.assertNotIn("\u202e", stdout)

    def test_log_lines_escape_control_characters(self):
        rc, _, stderr = util.run("export", self.hostile_image, "--record", self.hostile["escape"], "-o",
                                 self.out("escape_export"))
        self.assertEqual(rc, 0)
        self.assertNotIn("\x1b", stderr)

    def test_machine_formats_keep_the_real_name(self):
        rc, stdout, _ = util.run("search", self.hostile_image, "--record", self.hostile["escape"], "--format",
                                 "jsonl")
        self.assertEqual(util.parse_jsonl(stdout)[0]["name"], "red\x1b[31m.txt")

    def test_html_cannot_be_broken_by_a_file_name(self):
        path = self.out("hostile.html")
        util.run("dump", self.hostile_image, "--format", "html", "-o", path)
        with open(path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertEqual(html.count("<script"), 2)
        self.assertEqual(html.count("</script>"), 2)
        self.assertNotIn("<!--", html)
        self.assertIn("\\u003c!--\\u003cscript>alert(1)\\u003c/script>.txt", html)

    def test_markdown_path_with_backtick(self):
        rc, stdout, _ = util.run("search", self.hostile_image, "--record", self.hostile["tick"], "--format", "md")
        self.assertIn("`` a`b.txt ``", stdout)

    def test_help_text_shows_single_backslashes(self):
        rc, stdout, _ = util.run(stdin=b"8\n\n9\n")
        self.assertEqual(rc, 0)
        self.assertIn("C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", stdout)
        self.assertNotIn("C:\\\\Windows", stdout)

    def test_empty_report_writes_nothing(self):
        rc, stdout, stderr = util.run("report", self.write("empty.csv", b" \n"), "--format", "csv")
        self.assertEqual(rc, 1)
        self.assertEqual(stdout, "")
        self.assertIn("is empty", stderr)


class ExtensionNameTests(HardeningCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        v = fx.Volume()
        cls.side = v.add_dir("x86_Microsoft.Tools.VisualCPlusPlus.Runtime-Libraries_6.0.0.0_x-ww_ff9986d7",
                             short_name="X86_MI~2.0_X")
        cls.child = v.add_file("mfc42.dll", b"MZ", cls.side)
        cls.nested = v.add_dir("inner", cls.side)
        cls.deep = v.add_file("atl.dll", b"MZ", cls.nested)
        cls.long_image = cls.write("longname.img", v.build())
        rc, stdout, stderr = util.run("dump", cls.long_image, "--format", "jsonl")
        cls.long_rows = {r["record"]: r for r in util.parse_jsonl(stdout)}

    def test_directory_row_uses_the_long_name(self):
        row = self.long_rows[self.side]
        self.assertEqual(row["name"], "x86_Microsoft.Tools.VisualCPlusPlus.Runtime-Libraries_6.0.0.0_x-ww_ff9986d7")
        self.assertEqual(row["has_attr_list"], "yes")

    def test_children_use_the_long_name_of_the_parent(self):
        parent = self.long_rows[self.side]["path"]
        self.assertEqual(self.long_rows[self.child]["path"], parent + "/mfc42.dll")
        self.assertEqual(self.long_rows[self.deep]["path"], parent + "/inner/atl.dll")
        self.assertNotIn("X86_MI~2.0_X", self.long_rows[self.child]["path"])

    def test_search_by_long_path(self):
        rc, stdout, stderr = util.run("search", self.long_image, "--path", "Runtime-Libraries", "--files-only",
                                      "--format", "jsonl")
        self.assertEqual(rc, 0, stderr)
        found = {r["record"] for r in util.parse_jsonl(stdout)}
        self.assertEqual(found, {self.child, self.deep})


class FilterTests(HardeningCase):

    def test_clusters_free_values(self):
        self.assertEqual(self.names("--clusters-free", "yes"), {"del_ok", "payload", "tool", "lost"})
        self.assertEqual(self.names("--clusters-free", "no"), {"del_realloc"})
        self.assertEqual(self.names("--clusters-free", "partial"), {"del_partial"})
        self.assertEqual(self.names("--clusters-free", "contested"), {"contested_old", "contested_new"})

    def test_clusters_free_combines_with_other_filters(self):
        self.assertEqual(self.names("--clusters-free", "yes", "--ext", "exe"), {"payload"})

    def test_clusters_free_in_dump_and_report(self):
        source = self.out("all.jsonl")
        util.run("dump", self.image, "--format", "jsonl", "-o", source)
        rc, stdout, _ = util.run("report", source, "--clusters-free", "contested", "--format", "jsonl")
        self.assertEqual(rc, 0)
        self.assertEqual({r["record"] for r in util.parse_jsonl(stdout)},
                         {self.rec["contested_old"], self.rec["contested_new"]})
        rc, stdout, _ = util.run("dump", self.image, "--deleted-only", "--clusters-free", "yes", "--format",
                                 "jsonl")
        self.assertEqual(len(util.parse_jsonl(stdout)), 4)

    def test_clusters_free_is_recorded_in_the_manifest(self):
        path = self.out("recoverable.csv")
        util.run("search", self.image, "--clusters-free", "yes", "--format", "csv", "-o", path)
        with open(path + ".manifest.json", encoding="utf-8") as fh:
            self.assertIn("--clusters-free yes", json.load(fh)["criteria"])

    def test_invalid_value_is_rejected(self):
        rc, _, stderr = util.run("search", self.image, "--clusters-free", "maybe")
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice", stderr)


class ExportHardeningTests(HardeningCase):

    def export(self, image, name, *args):
        out = self.out(name)
        rc, _, stderr = util.run("export", image, "-o", out, *args)
        self.assertNotIn("Traceback", stderr)
        results = {r["record"]: r for r in util.read_jsonl(os.path.join(out, "export_manifest.jsonl"))}
        return rc, results, out, stderr

    def test_likely_owner_of_contested_clusters(self):
        old, new = self.rec["contested_old"], self.rec["contested_new"]
        rc, results, _, stderr = self.export(self.image, "owner", "--record", "%d,%d" % (old, new))
        self.assertEqual(rc, 1)
        self.assertEqual(results[old]["clusters_likely_owner"], new)
        self.assertEqual(results[new]["clusters_likely_owner"], new)
        self.assertIn("Record %d has the latest $FN creation time" % new, stderr)
        self.assertIn("most likely its own", stderr)

    def test_one_failing_record_does_not_stop_the_others(self):
        note, evil = self.rec["note"], self.rec["evil"]
        out = self.out("blocked")
        os.makedirs(os.path.join(out, "%06d_note.txt" % note))
        rc, results, _, stderr = self.export(self.image, "blocked", "--record", "%d,%d" % (note, evil))
        self.assertEqual(rc, 1)
        self.assertEqual(results[note]["status"], "error")
        self.assertEqual(results[evil]["status"], "ok")

    def test_long_names_are_shortened_on_disk_only(self):
        v = fx.Volume()
        name = "L" * 200 + ".txt"
        number = v.add_file(name, fx.pattern("long", 5000), ads={"S" * 70: b"stream"})
        rc, results, out, _ = self.export(self.write("long.img", v.build()), "long", "--record", number, "--ads")
        self.assertEqual(rc, 0)
        result = results[number]
        self.assertEqual(result["name"], name)
        for stream in result["streams"]:
            self.assertTrue(os.path.exists(os.path.join(out, stream["file"])))
            self.assertLess(len(stream["file"]), 250)
        self.assertEqual(result["streams"][0]["sha256"], util.sha256(fx.pattern("long", 5000)))

    def test_directory_with_an_alternate_data_stream(self):
        v = fx.Volume()
        folder = v.add_dir("tagged")
        v.specs[folder]["streams"]["there"] = {"resident": True, "content": b"hidden in a directory", "size": 21}
        image = self.write("dirads.img", v.build())
        rc, results, out, _ = self.export(image, "dirads", "--record", folder, "--ads")
        self.assertEqual(rc, 0)
        self.assertEqual(results[folder]["status"], "ok")
        self.assertEqual([s["stream"] for s in results[folder]["streams"]], ["there"])
        with open(os.path.join(out, results[folder]["streams"][0]["file"]), "rb") as fh:
            self.assertEqual(fh.read(), b"hidden in a directory")
        rc, results, _, _ = self.export(image, "dirads_plain", "--record", folder)
        self.assertEqual(rc, 0)
        self.assertEqual(results[folder]["status"], "directory")
        rc, results, _, _ = self.export(image, "dirads_stream", "--record", folder, "--stream", "there")
        self.assertEqual(rc, 0)
        self.assertEqual(results[folder]["status"], "ok")

    def test_stream_larger_than_the_volume_is_skipped(self):
        v = fx.Volume()
        number = v.add_file("bomb.bin", fx.pattern("bomb", 5000), fragments=2)
        stream = v.specs[number]["streams"][""]
        stream["runs"].append((None, 50000000))
        stream["size"] = 50000000 * fx.CLUSTER
        stream["flags"] = fx.ATTRF_SPARSE
        rc, results, out, stderr = self.export(self.write("bomb.img", v.build()), "bomb", "--record", number)
        self.assertEqual(rc, 1)
        self.assertEqual(results[number]["status"], "no-data")
        self.assertIn("more than the whole volume", stderr)
        self.assertLess(sum(os.path.getsize(os.path.join(out, f)) for f in os.listdir(out)), 100000)


class UnitTests(unittest.TestCase):

    def test_printable(self):
        self.assertEqual(mft.printable("plain name.txt"), "plain name.txt")
        self.assertEqual(mft.printable("a\x1b[0m"), "a\\x1b[0m")
        self.assertEqual(mft.printable("a\nb\tc"), "a\\x0ab\\x09c")
        self.assertEqual(mft.printable("x\u202ey"), "x\\u202ey")
        self.assertEqual(mft.printable("北京.txt"), "北京.txt")
        self.assertEqual(mft.printable(12), "12")

    def test_foreign_volume_kind(self):
        self.assertIn("BitLocker", mft.foreign_volume_kind(fx.foreign_boot_sector("bitlocker")))
        self.assertIn("exFAT", mft.foreign_volume_kind(fx.foreign_boot_sector("exfat")))
        self.assertIn("FAT", mft.foreign_volume_kind(fx.foreign_boot_sector("fat32")))
        self.assertEqual(mft.foreign_volume_kind(fx.Volume().boot_sector()), "")
        self.assertEqual(mft.foreign_volume_kind(b"\x00" * 512), "")
        self.assertEqual(mft.foreign_volume_kind(b""), "")

    def test_likely_owner_needs_a_unique_latest_time(self):
        engine = mft.Engine(None)
        engine.contested = {10: [11], 11: [10], 20: [21], 21: [20], 30: [31], 31: [30]}
        engine._freed_created = {10: 100, 11: 200, 20: 300, 21: 300, 30: 400}
        self.assertEqual(engine.likely_owner(10), 11)
        self.assertEqual(engine.likely_owner(11), 11)
        self.assertIsNone(engine.likely_owner(20))
        self.assertIsNone(engine.likely_owner(30))
        self.assertIsNone(engine.likely_owner(99))


if __name__ == "__main__":
    unittest.main()
