import os
import shutil
import sys
import tempfile
import unittest

import tool_compare
import util

CATALOGUE = {entry["id"]: entry for entry in util.load_data("images.json")}
VOLUMES = ("dftt7", "dftt3", "dftt8", "dftt10-part1", "dftt10-part2")


class ToolCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mftdigger_tools_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def prepared(self, partitioned=True):
        only = os.environ.get("MFTDIGGER_DFR")
        found = 0
        for image_id, entry in CATALOGUE.items():
            if image_id.startswith("dfr-") and only and image_id not in only.split(","):
                continue
            if not partitioned and image_id not in VOLUMES:
                continue
            if not entry.get("ntfs", True):
                continue
            path = util.materialize(entry, self.tmp)
            if path is None:
                continue
            found += 1
            work = os.path.join(self.tmp, "work")
            rows, mft = tool_compare.prepare(path, work)
            yield image_id, path, rows, mft, work
            shutil.rmtree(work, ignore_errors=True)
            if path.startswith(self.tmp):
                os.remove(path)
        if not found:
            self.skipTest("no public image found in %s (run tests/fetch_images.py --all)" % util.images_dir())


@unittest.skipUnless(tool_compare.have_module("mft"), "the mft package is not installed (pip install mft)")
class RustMftTests(ToolCase):

    def test_records_agree(self):
        for image_id, _, rows, mft, _ in self.prepared():
            with self.subTest(image=image_id):
                result = tool_compare.compare_mft(rows, mft)
                self.assertEqual(result["records"], len(rows))
                for field in ("missing", "seq", "in_use", "is_dir", "si_times", "fn_times", "ads", "path_live"):
                    self.assertEqual(result[field], [], field)
                self.assertLessEqual(len(result["unreadable"]), 1)
                for number, ours, theirs in result["name"]:
                    self.assertEqual(rows[number]["has_attr_list"], "yes", (number, ours, theirs))
                for number, ours, theirs in result["path_deleted"]:
                    self.assertTrue(ours.startswith("$OrphanFiles/"), (number, ours, theirs))
                    self.assertEqual(theirs.rsplit("/", 1)[-1], rows[number]["name"])


@unittest.skipUnless(tool_compare.have_module("dissect.ntfs"),
                     "dissect.ntfs is not installed (pip install dissect.ntfs)")
class DissectTests(ToolCase):

    def test_records_agree(self):
        for image_id, _, rows, mft, _ in self.prepared():
            with self.subTest(image=image_id):
                result = tool_compare.compare_dissect(rows, mft)
                self.assertEqual(result["records"], len(rows))
                for field in ("missing", "seq", "in_use", "is_dir", "si_times", "size"):
                    self.assertEqual(result[field], [], field)
                for number, ours, theirs in result["name"]:
                    row = rows[number]
                    self.assertTrue(row["has_attr_list"] == "yes" or row["link_count"] > 1, (number, ours, theirs))
                for number, ours, theirs in result["path_live"]:
                    self.assertEqual(rows[number]["has_attr_list"], "yes", (number, ours, theirs))
                for number, ours, theirs in result["path_deleted"]:
                    self.assertTrue(theirs and all("<broken_reference" in p for p in theirs), (number, ours, theirs))


@unittest.skipUnless(tool_compare.analyzemft_command(), "analyzeMFT is not installed (pip install analyzeMFT)")
class AnalyzeMftTests(ToolCase):

    def test_records_agree(self):
        for image_id, _, rows, mft, work in self.prepared():
            with self.subTest(image=image_id):
                result = tool_compare.compare_analyzemft(rows, mft, work)
                self.assertGreaterEqual(result["records"], len(rows) - 9)
                for field in ("invalid", "seq", "in_use", "is_dir"):
                    self.assertEqual(result[field], [], field)
                self.assertEqual([n for n in result["missing"] if rows[n]["name"]], [])
                parent = [item for item in result["parent"] if rows[item[0]]["has_attr_list"] == "no"]
                for field, items in (("si_times", result["si_times"]), ("fn_times", result["fn_times"]),
                                     ("parent", parent)):
                    self.assertLessEqual(len(items) * 1000, result["records"], (field, items))


@unittest.skipUnless(tool_compare.mftecmd_command(),
                     "MFTECmd is not installed (put it on PATH or set MFTECMD to its path)")
class MfteCmdTests(ToolCase):

    def test_records_agree(self):
        for image_id, _, rows, mft, work in self.prepared():
            with self.subTest(image=image_id):
                result = tool_compare.compare_mftecmd(rows, mft, work)
                for field in ("seq", "in_use", "is_dir", "si_times", "fn_times", "lsn", "name", "ads", "path_live"):
                    self.assertEqual(result[field], [], field)
                self.assertEqual([n for n in result["missing"] if rows[n]["name"]], [])
                for number, ours, theirs in result["size"]:
                    row = rows[number]
                    self.assertTrue(row["has_attr_list"] == "yes" or (ours == 0 and row["ads_names"]),
                                    (number, ours, theirs))
                for number, ours, theirs in result["path_deleted"]:
                    self.assertTrue(ours.startswith("$OrphanFiles/"), (number, ours, theirs))
                    self.assertTrue(theirs[0].startswith("PathUnknown/"), (number, ours, theirs))


@unittest.skipUnless(sys.platform.startswith("linux") and util.have("ntfsundelete"),
                     "ntfsundelete (ntfs-3g) is only available on Linux")
class NtfsUndeleteTests(ToolCase):

    def test_deleted_records_and_recoverability(self):
        root = os.geteuid() == 0 and util.have("losetup")
        for image_id, path, rows, _, _ in self.prepared(partitioned=root):
            with self.subTest(image=image_id):
                result = tool_compare.compare_ntfsundelete(rows, path)
                self.assertEqual(result["missing"], [])
                self.assertEqual(result["name"], [])
                self.assertEqual(result["recoverable"], [])
                for number, state, percent in result["compressed"]:
                    self.assertEqual((state, percent), ("yes", 0), number)


if __name__ == "__main__":
    unittest.main()
