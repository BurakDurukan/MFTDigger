import os
import shutil
import sys
import tempfile
import unittest

import ntfs_fixture as fx
import util


def can_build():
    return (sys.platform.startswith("linux") and hasattr(os, "geteuid") and os.geteuid() == 0
            and util.have("mkntfs", "ntfs-3g", "setfattr") and os.path.exists("/dev/fuse"))


@unittest.skipUnless(can_build(), "needs Linux, root, ntfs-3g, mkntfs and setfattr")
class Ntfs3gVolumeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        import ntfs3g_volume
        cls.tmp = tempfile.mkdtemp(prefix="mftdigger_ntfs3g_")
        cls.builder = ntfs3g_volume.Builder(cls.tmp)
        cls.image = cls.builder.build()
        out = os.path.join(cls.tmp, "export")
        cls.rc, _, cls.stderr = util.run("export", cls.image, "--name", "*", "--include-deleted", "--ads",
                                         "--max-files", "100000", "--no-raw-record", "-o", out)
        cls.got = {}
        cls.status = {}
        for item in util.read_jsonl(os.path.join(out, "export_manifest.jsonl")):
            for path in (item.get("all_paths") or item.get("path") or "").split("|"):
                for stream in item.get("streams", []):
                    key = path if stream["stream"] == "$DATA" else "%s:%s" % (path, stream["stream"])
                    cls.got[key] = stream["sha256"]
                    cls.status[key] = item["status"]

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assert_group(self, group):
        self.assertTrue(group)
        wrong = [path for path, digest in group.items() if self.got.get(path) != digest]
        self.assertEqual(wrong, [])

    def test_no_traceback(self):
        self.assertNotIn("Traceback", self.stderr)

    def test_live_files(self):
        self.assert_group(self.builder.live)

    def test_alternate_data_streams(self):
        self.assert_group(self.builder.ads)

    def test_deleted_files(self):
        self.assert_group(self.builder.deleted)
        for path in self.builder.deleted:
            self.assertEqual(self.status[path], "ok", path)

    def test_compressed_layouts(self):
        for name in ("text.txt", "mixed.bin", "small.txt", "random_tail.bin", "text_then_random.bin",
                     "tiny_random.bin", "exact_unit.bin"):
            self.assertEqual(self.got["comp/" + name], self.builder.live["comp/" + name], name)

    def test_verify(self):
        self.assertEqual(util.run("verify", self.image)[0], 0)

    def test_gpt_wrapped_disk(self):
        with open(self.image, "rb") as fh:
            disk = fx.wrap_gpt(fh.read())
        path = os.path.join(self.tmp, "disk.img")
        with open(path, "wb") as fh:
            fh.write(disk)
        plain = {r["record"]: r["all_paths"] for r in util.parse_jsonl(util.run("dump", self.image, "--format",
                                                                                 "jsonl")[1])}
        wrapped = {r["record"]: r["all_paths"] for r in util.parse_jsonl(util.run("dump", path, "--format",
                                                                                   "jsonl")[1])}
        self.assertEqual(plain, wrapped)

    @unittest.skipUnless(util.have("fls", "icat"), "The Sleuth Kit (fls, icat) is not installed")
    def test_against_sleuthkit(self):
        import tsk_compare
        result = tsk_compare.compare(self.image, os.path.join(self.tmp, "tsk"), 4 << 30)
        self.assertEqual(result["content"], [])
        self.assertEqual(result["state"], [])
        self.assertEqual(result["ads"], [])
        self.assertEqual(result["size"], [])
        self.assertEqual(result["bitmap"], [])
        self.assertEqual(result["path"], [])
        self.assertTrue(result["mft_hash_match"])
        self.assertGreater(result["streams"], 500)
        for record, ours, theirs in result["time"]:
            self.assertEqual(ours, (0, 0, 0, 0), record)


if __name__ == "__main__":
    unittest.main()
