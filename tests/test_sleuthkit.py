import os
import shutil
import tempfile
import unittest

import tsk_compare
import util

CATALOGUE = {entry["id"]: entry for entry in util.load_data("images.json")}
LARGE = {"dfr-06-ntfs", "dfr-10-ntfs"}


@unittest.skipUnless(util.have("fls", "icat"), "The Sleuth Kit (fls, icat) is not installed")
class SleuthKitTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mftdigger_tsk_")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, image, max_size=64 * 1024 * 1024, stale_names=False):
        result = tsk_compare.compare(image, os.path.join(self.tmp, "work"), max_size)
        self.assertGreater(result["records"], 20)
        self.assertGreater(result["streams"], 10)
        self.assertEqual(result["content"], [])
        if stale_names:
            renamed = {record for record, ours, theirs in result["path"]}
            self.assertTrue({item[0] for item in result["state"]} <= renamed, result["state"])
            self.assertTrue({item[0] for item in result["time"]} <= renamed, result["time"])
            result["state"] = []
            result["time"] = []
        self.assertEqual(result["state"], [])
        self.assertEqual(result["ads"], [])
        self.assertEqual(result["size"], [])
        self.assertEqual(result["bitmap"], [])
        self.assertTrue(result["mft_hash_match"])
        for record, ours, theirs in result["path"]:
            self.assertTrue(set(ours) <= set(theirs), (record, ours, theirs))
        for record, ours, theirs in result["time"]:
            self.assertEqual(ours, (0, 0, 0, 0), (record, ours, theirs))
        return result

    def test_dftt_undelete(self):
        path = util.materialize(CATALOGUE["dftt7"], self.tmp)
        if path is None:
            self.skipTest("DFTT #7 image not found (run tests/fetch_images.py)")
        result = self.check(path)
        self.assertEqual(result["path"], [])
        self.assertEqual(result["time"], [])
        self.assertEqual(result["deleted_streams"], 9)

    def test_dftt_keyword_search(self):
        path = util.materialize(CATALOGUE["dftt3"], self.tmp)
        if path is None:
            self.skipTest("DFTT #3 image not found (run tests/fetch_images.py --all)")
        result = self.check(path)
        self.assertEqual(result["time"], [])
        self.assertEqual(result["streams"], 21)

    def test_dftt_jpeg_search(self):
        path = util.materialize(CATALOGUE["dftt8"], self.tmp)
        if path is None:
            self.skipTest("DFTT #8 image not found (run tests/fetch_images.py --all)")
        result = self.check(path)
        self.assertEqual(result["path"], [])
        self.assertEqual(result["time"], [])
        self.assertEqual(result["deleted_streams"], 2)

    def test_hacking_case(self):
        path = util.materialize(CATALOGUE["hacking-case"], self.tmp)
        if path is None:
            self.skipTest("SCHARDT.001-008 not found (run tests/fetch_images.py --large)")
        result = self.check(path, 4 << 30, stale_names=True)
        self.assertGreater(result["records"], 12000)
        self.assertGreater(result["streams"], 11000)
        self.assertGreater(result["bytes"], 1900000000)

    def test_nist_dfr(self):
        only = os.environ.get("MFTDIGGER_DFR")
        checked = 0
        for image_id, entry in CATALOGUE.items():
            if not image_id.startswith("dfr-") or (only and image_id not in only.split(",")):
                continue
            path = util.materialize(entry, self.tmp)
            if path is None:
                continue
            checked += 1
            with self.subTest(image=image_id):
                self.check(path, 4 << 30 if image_id in LARGE else 64 << 20)
            if path.startswith(self.tmp):
                os.remove(path)
        if not checked:
            self.skipTest("no NIST DFR image found (run tests/fetch_images.py --all)")


if __name__ == "__main__":
    unittest.main()
