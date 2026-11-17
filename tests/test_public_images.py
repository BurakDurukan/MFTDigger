import collections
import os
import shutil
import tempfile
import unittest

import util

CATALOGUE = {entry["id"]: entry for entry in util.load_data("images.json")}

DFTT_PATHS = {
    29: "frag1.dat",
    30: "frag2.dat",
    31: "sing1.dat",
    32: "mult1.dat",
    33: "dir1",
    34: "dir1/dir2",
    35: "dir1/dir2/frag3.dat",
    36: "dir1/mult2.dat",
    37: "res1.dat",
    38: "$OrphanFiles/<parent-37-seq-mismatch>/sing2.dat",
}

DFTT_MD5 = {
    (29, "$DATA"): (1584, "7a3bc5b763bef201202108f4ba128149"),
    (30, "$DATA"): (3873, "0e80ab84ef0087e60dfc67b88a1cf13e"),
    (31, "$DATA"): (780, "59b20779f69ff9f0ac5fcd2c38835a79"),
    (32, "$DATA"): (3801, "ffd27bd782bdce67750b6b9ee069d2ef"),
    (32, "ADS"): (1234, "ba1b9eedb1c091ddca253d35dde8f616"),
    (35, "$DATA"): (2027, "21121699487f3fbbdb9a4b3391b6d3e0"),
    (36, "$DATA"): (1715, "59cf0e9cd107bc1e75afb7374f6e05bb"),
    (37, "$DATA"): (101, "9036637712b491904cd0bfbdbe648453"),
    (38, "$DATA"): (1005, "c229626f6a71b167ad7e50c4f2fccdb1"),
}

DFTT3_KEYWORDS = {
    (27, "$DATA"): b"r-alloc",
    (34, "$DATA"): b"r-unalloc",
    (29, "here"): b"r-fads",
    (30, "there"): b"r-dads",
    (33, "$DATA"): b"n-alloc",
    (35, "$DATA"): b"n-frag",
    (37, "here"): b"n-fads",
    (38, "there"): b"n-dads",
}

DFTT8_MD5 = {
    ("alloc/file1.jpg", "$DATA"): "75b8d00568815a36c3809b46fc84ba6d",
    ("alloc/file2.dat", "$DATA"): "de5d83153339931371719f4e5c924eba",
    ("invalid/file3.jpg", "$DATA"): "1ba4e91591f0541eda255ee26f7533bc",
    ("invalid/file4.jpg", "$DATA"): "c8de721102617158e8492121bdad3711",
    ("invalid/file5.rtf", "$DATA"): "86f14fc525648c39d878829f288c0543",
    ("del1/file6.jpg", "$DATA"): "afd55222024a4e22f7f5a3a665320763",
    ("del2/file7.hmm", "$DATA"): "0c452c5800fcfa7c66027ae89c4f068a",
    ("archive/file8.zip", "$DATA"): "d41b56e0a9f84eb2825e73c24cedd963",
    ("archive/file9.boo", "$DATA"): "73c3029066aee9416a5aeb98a5c55321",
    ("archive/file10.tar.gz", "$DATA"): "d4f8cf643141f0c2911c539750e18ef2",
    ("misc/file11.dat", "$DATA"): "f407ab92da959c7ab03292cfe596a99d",
    ("misc/file12.doc", "$DATA"): "61c0b55639e52d1ce82aba834ada2bab",
    ("misc/file13.dll", "here"): "9b787e63e3b64562730c5aecaab1e1f8",
}

HACKING_CASE_PATHS = {
    344: ("Documents and Settings/Mr. Evil", 0),
    3667: ("WINDOWS/system32/config/SAM", 262144),
    5000: ("WINDOWS/system32/winmine.exe", 119808),
    10080: ("Program Files/mIRC/mirc.ini", 5483),
    11692: ("RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/Dc1.exe", 2160043),
    11776: ("Program Files/Look@LAN/irunin.ini", 18197),
    11996: ("RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/Dc2.exe", 1324940),
    12033: ("RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/Dc3.exe", 442417),
    12041: ("RECYCLER/S-1-5-21-2000478354-688789844-1708537768-1003/Dc4.exe", 8460502),
    12264: ("Documents and Settings/Mr. Evil/interception", 173372),
}

DFR04_NAMES = {
    64: "नान.txt", 65: "चपाती.txt", 66: "پکوڑا.txt", 67: "گلاب_جامن.txt", 68: "서울.txt", 69: "한국.txt",
    70: "چلوکباب.txt", 71: "گردو.txt", 72: "פלפל.txt", 73: "חומוס.txt", 74: "كسكس.txt", 75: "طاجين.txt",
    76: "чай.txt", 77: "сыр.txt", 78: "ミツビシ.txt", 79: "みつびし.txt", 80: "Süßigkeiten.txt",
    81: "Gefäß.txt", 82: "北京.txt", 83: "中國.txt", 84: "日本.txt", 85: "東京.txt", 86: "スバル.txt",
    87: "すばる.txt",
}


class ImageCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mftdigger_images_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def image(self, image_id):
        path = util.materialize(CATALOGUE[image_id], self.tmp)
        if path is None:
            self.skipTest("%s not found in %s (run tests/fetch_images.py)" % (CATALOGUE[image_id]["archive"],
                                                                                 util.images_dir()))
        if path.startswith(self.tmp):
            self.addCleanup(lambda: os.path.exists(path) and os.remove(path))
        return path

    def dump(self, image):
        rc, stdout, stderr = util.run("dump", image, "--format", "jsonl")
        self.assertEqual(rc, 0, stderr)
        self.assertNotIn("Traceback", stderr)
        return {row["record"]: row for row in util.parse_jsonl(stdout)}

    def export(self, image, name, *args):
        out = os.path.join(self.tmp, name)
        shutil.rmtree(out, ignore_errors=True)
        rc, _, stderr = util.run("export", image, "-o", out, *args)
        self.assertNotIn("Traceback", stderr)
        results = {row["record"]: row for row in util.read_jsonl(os.path.join(out, "export_manifest.jsonl"))}
        return rc, results, out


class DfttUndeleteTests(ImageCase):

    def test_image_is_the_published_one(self):
        image = self.image("dftt7")
        self.assertEqual(util.file_hash(image, "md5"), "e7dbb96759d9cd62b729463ebfe61dab")

    def test_deleted_paths(self):
        rows = self.dump(self.image("dftt7"))
        for record, path in DFTT_PATHS.items():
            self.assertEqual(rows[record]["path"], path)
            self.assertEqual(rows[record]["in_use"], "no")

    def test_recovered_content_matches_published_md5(self):
        records = sorted({record for record, _ in DFTT_MD5})
        rc, results, _ = self.export(self.image("dftt7"), "dftt7", "--record", ",".join(map(str, records)), "--ads")
        self.assertEqual(rc, 0)
        seen = {}
        for record, result in results.items():
            self.assertEqual(result["status"], "ok")
            for stream in result["streams"]:
                seen[(record, stream["stream"])] = (stream["bytes"], stream["md5"])
        self.assertEqual(seen, DFTT_MD5)

    def test_clusters_free(self):
        rows = self.dump(self.image("dftt7"))
        for record in (29, 30, 31, 32, 35, 36, 38):
            self.assertEqual(rows[record]["clusters_free"], "yes", record)
        self.assertEqual(rows[37]["resident"], "yes")

    def test_leap_day_timestamps(self):
        rows = self.dump(self.image("dftt7"))
        for record in DFTT_PATHS:
            self.assertTrue(rows[record]["si_created"].startswith("2004-02-29T"), record)

    def test_verify(self):
        rc, stdout, _ = util.run("verify", self.image("dftt7"))
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.count("MATCH"), 4)


class NistDfrTests(ImageCase):

    def selected(self):
        only = os.environ.get("MFTDIGGER_DFR")
        ids = [i for i in CATALOGUE if i.startswith("dfr-")]
        if only:
            ids = [i for i in ids if i in only.split(",")]
        return ids

    def test_baseline(self):
        checked = 0
        for image_id in self.selected():
            entry = CATALOGUE[image_id]
            path = util.materialize(entry, self.tmp)
            if path is None:
                continue
            checked += 1
            with self.subTest(image=image_id):
                rows = self.dump(path)
                expected = entry["expected"]
                deleted = [r for r in rows.values() if r["in_use"] == "no" and r["name"]]
                free = collections.Counter(r["clusters_free"] or "n/a" for r in deleted)
                self.assertEqual(len(rows), expected["rows"])
                self.assertEqual(sum(r["in_use"] == "yes" for r in rows.values()), expected["in_use"])
                self.assertEqual(len(deleted), expected["deleted_named"])
                self.assertEqual(dict(free), expected["clusters_free"])
                self.assertEqual(sum(r["is_dir"] == "yes" for r in rows.values()), expected["directories"])
                self.assertEqual(sum(r["ads_count"] > 0 for r in rows.values()), expected["with_ads"])
                self.assertEqual([r["record"] for r in rows.values() if r["error"]], [])
                self.assertEqual([r["record"] for r in rows.values() if r["fixup_ok"] != "yes"], [])
                self.assertEqual([r["record"] for r in rows.values() if r["path"].startswith("$OrphanFiles")], [])
                self.assertEqual(util.run("verify", path)[0], 0)
            if path.startswith(self.tmp):
                os.remove(path)
        if not checked:
            self.skipTest("no NIST DFR image found in %s (run tests/fetch_images.py --all)" % util.images_dir())

    def test_non_ascii_names(self):
        rows = self.dump(self.image("dfr-04-ntfs"))
        self.assertEqual({record: rows[record]["name"] for record in DFR04_NAMES}, DFR04_NAMES)

    def test_overwritten_by_a_deleted_file_is_contested(self):
        image = self.image("dfr-07-one-ntfs")
        rows = self.dump(image)
        self.assertEqual((rows[65]["name"], rows[66]["name"]), ("Eltanin.txt", "Castor.txt"))
        self.assertEqual(rows[65]["clusters_free"], "contested")
        self.assertEqual(rows[66]["clusters_free"], "contested")
        rc, results, out = self.export(image, "dfr07one", "--record", "65,66")
        self.assertEqual(rc, 1)
        self.assertEqual(results[66]["status"], "contested")
        self.assertEqual(results[66]["clusters_shared_with"], [65])
        self.assertEqual(results[65]["clusters_likely_owner"], 65)
        self.assertEqual(results[66]["clusters_likely_owner"], 65)
        with open(os.path.join(out, results[66]["streams"][0]["file"]), "rb") as fh:
            self.assertIn(b"File Eltanin.txt", fh.read(200))

    def test_overwritten_by_a_live_file_is_reallocated(self):
        image = self.image("dfr-07-two-ntfs")
        rows = self.dump(image)
        self.assertEqual(rows[66]["name"], "Castor.txt")
        self.assertEqual(rows[66]["clusters_free"], "no")
        rc, results, _ = self.export(image, "dfr07two", "--record", "66")
        self.assertEqual(rc, 1)
        self.assertEqual(results[66]["status"], "reallocated")

    def test_file_name_stored_in_extension_record(self):
        rows = self.dump(self.image("dfr-10-ntfs"))
        self.assertEqual(rows[847]["path"], "box/FILL.TXT")
        self.assertEqual(rows[847]["ext_records"], "848|849")
        self.assertEqual(rows[847]["has_attr_list"], "yes")

    def content_names_itself(self, image, name, *args):
        rc, results, out = self.export(image, name, *args)
        checked = 0
        for result in results.values():
            if result["is_dir"] or result["name"].upper() == "FILL.TXT" or result["name"].startswith("$"):
                continue
            for stream in result["streams"]:
                if stream["stream"] != "$DATA":
                    continue
                with open(os.path.join(out, stream["file"]), "rb") as fh:
                    head = fh.read(300)
                self.assertIn(("File %s " % result["name"]).encode("utf-8"), head, result["path"])
                checked += 1
        return checked

    def test_deleted_compressed_files(self):
        image = self.image("dfr-11-compress-ntfs")
        rows = self.dump(image)
        for record in (43, 44, 45):
            self.assertEqual(rows[record]["compressed"], "yes")
            self.assertEqual(rows[record]["in_use"], "no")
            self.assertTrue(rows[record]["path"].startswith("Lyra/"))
        self.assertEqual(self.content_names_itself(image, "dfr11c", "--record", "43,44,45"), 3)

    def test_deleted_directory_contents(self):
        image = self.image("dfr-12-ntfs")
        checked = self.content_names_itself(image, "dfr12", "--name", "*.txt", "--include-deleted")
        self.assertEqual(checked, 12)

    def test_many_deleted_files(self):
        image = self.image("dfr-09-ntfs")
        checked = self.content_names_itself(image, "dfr09", "--name", "*.txt", "--include-deleted",
                                            "--max-files", "1000")
        self.assertEqual(checked, 260)

    def test_deep_paths(self):
        rows = self.dump(self.image("dfr-17-ntfs"))
        self.assertEqual(max(row["path"].count("/") for row in rows.values()), 9)


class DfttKeywordTests(ImageCase):

    def test_image_is_the_published_one(self):
        self.assertEqual(util.file_hash(self.image("dftt3"), "md5"), "389e42124eb23c5053ff6596976d6710")

    def test_keywords_are_in_the_exported_streams(self):
        records = sorted({record for record, _ in DFTT3_KEYWORDS})
        rc, results, out = self.export(self.image("dftt3"), "dftt3", "--record", ",".join(map(str, records)), "--ads")
        self.assertEqual(rc, 0)
        found = {}
        for record, result in results.items():
            self.assertEqual(result["status"], "ok", record)
            for stream in result["streams"]:
                with open(os.path.join(out, stream["file"]), "rb") as fh:
                    data = fh.read()
                for keyword in set(DFTT3_KEYWORDS.values()):
                    if keyword in data:
                        found[(record, stream["stream"])] = keyword
        self.assertEqual(found, DFTT3_KEYWORDS)

    def test_published_sectors(self):
        rows = self.dump(self.image("dftt3"))
        self.assertEqual(rows[27]["mft_offset"] // 512, 5409)
        self.assertEqual(rows[34]["mft_offset"] // 512, 5423)
        self.assertEqual(rows[30]["mft_offset"] // 512, 5415)
        self.assertEqual((rows[27]["resident"], rows[34]["resident"]), ("yes", "yes"))
        self.assertEqual(rows[33]["data_runs"], "8048:4")
        self.assertEqual(rows[35]["data_runs"], "8056:3;8072:3")
        self.assertEqual((rows[34]["name"], rows[34]["in_use"]), ("file-r-2.dat", "no"))

    def test_streams_of_directories(self):
        rows = self.dump(self.image("dftt3"))
        self.assertEqual((rows[30]["path"], rows[30]["is_dir"], rows[30]["ads_names"]), ("dir-r-4", "yes", "there"))
        self.assertEqual((rows[38]["path"], rows[38]["is_dir"], rows[38]["ads_names"]), ("dir-n-6", "yes", "there"))


class DfttJpegTests(ImageCase):

    def test_image_is_the_published_one(self):
        self.assertEqual(util.file_hash(self.image("dftt8"), "md5"), "9bdb9c76b80e90d155806a1fc7846db5")

    def test_content_matches_published_md5(self):
        rc, results, _ = self.export(self.image("dftt8"), "dftt8", "--record", "27-44", "--ads")
        self.assertEqual(rc, 0)
        seen = {}
        for result in results.values():
            for stream in result["streams"]:
                seen[(result["path"], stream["stream"])] = stream["md5"]
        for key, md5 in DFTT8_MD5.items():
            self.assertEqual(seen.get(key), md5, key)

    def test_deleted_pictures(self):
        rows = self.dump(self.image("dftt8"))
        self.assertEqual((rows[32]["path"], rows[32]["in_use"], rows[32]["clusters_free"]), ("del1/file6.jpg", "no", "yes"))
        self.assertEqual((rows[31]["path"], rows[31]["in_use"], rows[31]["clusters_free"]), ("del2/file7.hmm", "no", "yes"))


class DfttAutodetectTests(ImageCase):

    def user_rows(self, image, *args):
        rc, stdout, stderr = util.run("dump", image, "--format", "jsonl", *args)
        self.assertEqual(rc, 0, stderr)
        return [(r["record"], r["path"], r["size"], r["si_created"], r["si_modified"])
                for r in util.parse_jsonl(stdout)]

    def test_images_are_the_published_ones(self):
        self.assertEqual(util.file_hash(self.image("dftt10-disk"), "md5"), "9225ff95b92311a28b2224e9dc324231")
        self.assertEqual(util.file_hash(self.image("dftt10-part1"), "md5"), "6bd741152ccedd50e12623af5eeba803")
        self.assertEqual(util.file_hash(self.image("dftt10-part2"), "md5"), "0b768efb1011b047c9831c1e00d1706c")

    def test_ntfs_is_read_from_volumes_that_hold_two_file_systems(self):
        for image_id in ("dftt10-part1", "dftt10-part2"):
            rows = self.dump(self.image(image_id))
            self.assertEqual(len(rows), 23)
            self.assertEqual((rows[29]["path"], rows[29]["size"]), ("NTFS.TXT", 44))

    def test_both_partitions_of_the_disk(self):
        disk = self.image("dftt10-disk")
        rc, stdout, _ = util.run("info", disk, "--partitions")
        self.assertEqual(rc, 0)
        self.assertIn("start=32256", stdout)
        self.assertIn("start=49351680", stdout)
        self.assertEqual(self.user_rows(disk), self.user_rows(self.image("dftt10-part1")))
        self.assertEqual(self.user_rows(disk, "--partition", "1"), self.user_rows(self.image("dftt10-part2")))


class DfttExtendedPartitionTests(ImageCase):

    def test_all_six_published_partitions_are_listed(self):
        image = self.image("dftt1")
        self.assertEqual(util.file_hash(image, "sha256"), CATALOGUE["dftt1"]["image_sha256"])
        rc, _, stderr = util.run("info", image, "--partitions")
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", stderr)
        self.assertIn("No NTFS partition found", stderr)
        for index, (sector, kind) in enumerate(((63, "MBR:0x04"), (52416, "MBR:0x04"), (104832, "MBR:0x04"),
                                                (157311, "MBR:0x04(logical)"), (209727, "MBR:0x04(logical)"),
                                                (262143, "MBR:0x06(logical)"))):
            self.assertIn("%d=%s@%d [a FAT volume]" % (index, kind, sector * 512), stderr)


class HackingCaseTests(ImageCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.path = util.materialize(CATALOGUE["hacking-case"], cls.tmp)
        cls.rows = None

    def setUp(self):
        if self.path is None:
            self.skipTest("SCHARDT.001-008 not found in %s (run tests/fetch_images.py --large)" % util.images_dir())
        if HackingCaseTests.rows is None:
            HackingCaseTests.rows = self.dump(self.path)

    def test_image_is_the_published_one(self):
        self.assertEqual(util.file_hash(self.path, "md5"), "aee4fcd9301c03b3b054623ca261959a")

    def test_baseline(self):
        expected = CATALOGUE["hacking-case"]["expected"]
        rows = self.rows.values()
        self.assertEqual(len(self.rows), expected["rows"])
        self.assertEqual(sum(r["in_use"] == "yes" for r in rows), expected["in_use"])
        self.assertEqual(sum(r["in_use"] == "no" and bool(r["name"]) for r in rows), expected["deleted_named"])
        self.assertEqual(sum(r["is_dir"] == "yes" for r in rows), expected["directories"])
        self.assertEqual(sum(r["compressed"] == "yes" for r in rows), expected["compressed"])
        self.assertEqual(sum(r["has_attr_list"] == "yes" for r in rows), expected["with_attr_list"])
        self.assertEqual(sum(r["ads_count"] > 0 for r in rows), expected["with_ads"])
        self.assertEqual([r["record"] for r in rows if r["error"]], [])
        self.assertEqual([r["record"] for r in rows if r["fixup_ok"] != "yes"], [])
        self.assertEqual([r["record"] for r in rows if r["path"].startswith("$OrphanFiles")], [])

    def test_known_files(self):
        for record, (path, size) in HACKING_CASE_PATHS.items():
            self.assertEqual((self.rows[record]["path"], self.rows[record]["size"]), (path, size))

    def test_long_directory_name_from_an_extension_record(self):
        folder = self.rows[3690]
        self.assertEqual(folder["name"],
                         "x86_Microsoft.Tools.VisualCPlusPlus.Runtime-Libraries_6595b64144ccf1df_6.0.0.0_x-ww_ff9986d7")
        self.assertEqual(self.rows[3692]["path"], folder["path"] + "/mfc42.dll")
        for record in (3691, 3692, 3693, 3694, 3702, 3703):
            self.assertNotIn("~", self.rows[record]["path"])

    def test_mft_hash_and_mirror(self):
        out = os.path.join(self.tmp, "schardt.mft")
        rc, stdout, stderr = util.run("extract-mft", self.path, "-o", out)
        self.assertEqual(rc, 0, stderr)
        self.assertEqual(util.file_hash(out), CATALOGUE["hacking-case"]["expected"]["mft_sha256"])
        self.assertEqual(os.path.getsize(out), CATALOGUE["hacking-case"]["expected"]["slots"] * 1024)
        os.remove(out)
        self.assertEqual(util.run("verify", self.path)[0], 0)

    def test_compressed_system_files(self):
        compressed = [r for r in self.rows.values() if r["compressed"] == "yes" and r["ext"] == "exe"
                      and r["in_use"] == "yes"][:25]
        self.assertEqual(len(compressed), 25)
        rc, results, out = self.export(self.path, "schardt", "--record", ",".join(str(r["record"]) for r in compressed))
        self.assertEqual(rc, 0)
        for row in compressed:
            result = results[row["record"]]
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["streams"][0]["bytes"], row["size"])
            with open(os.path.join(out, result["streams"][0]["file"]), "rb") as fh:
                self.assertEqual(fh.read(2), b"MZ", row["path"])


if __name__ == "__main__":
    unittest.main()
