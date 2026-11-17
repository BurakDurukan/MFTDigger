import csv
import json
import os
import random
import shutil
import struct
import tempfile
import unittest

import ntfs_fixture as fx
import util

mft = util.module()

DELETED = ("del_ok", "del_res", "del_realloc", "del_partial", "staging", "staging_sub", "payload", "tool",
           "lost", "contested_old", "contested_new")

PATHS = {
    "users": "Users",
    "alice": "Users/alice",
    "note": "Users/alice/note.txt",
    "windows": "Windows",
    "temp": "Windows/Temp",
    "evil": "Windows/Temp/evil.exe",
    "frag": "frag.bin",
    "sparse": "sparse.bin",
    "comp_text": "comp.txt",
    "comp_mixed": "comp_mixed.bin",
    "hard": "Users/alice/orig.txt",
    "unicode": "\u5317\u4eac-\u0447\u0430\u0439-S\u00fc\u00df.txt",
    "stomp": "Windows/Temp/stomped.dll",
    "subsec": "whole_second.zip",
    "wof": "wof.dll",
    "extname": "Users/alice/name_in_extension.vhd",
    "del_ok": "Users/alice/deleted_ok.doc",
    "del_res": "Users/alice/deleted_resident.txt",
    "del_realloc": "deleted_realloc.doc",
    "newer": "newer.bin",
    "del_partial": "deleted_partial.doc",
    "newer2": "newer2.bin",
    "staging": "staging",
    "staging_sub": "staging/sub",
    "payload": "staging/payload.exe",
    "tool": "staging/sub/tool.ps1",
    "old_dir": "replacement_dir",
    "lost": "$OrphanFiles/<parent-%(old_dir)d-seq-mismatch>/lost.txt",
    "contested_old": "contested_old.txt",
    "contested_new": "contested_new.txt",
}


class FixtureCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="mftdigger_test_")
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

    def ok(self, *args):
        rc, stdout, stderr = util.run(*args)
        self.assertNotIn("Traceback", stderr)
        self.assertEqual(rc, 0, stderr)
        return stdout, stderr

    def rows(self, image=None, *extra):
        stdout, _ = self.ok("dump", image or self.image, "--format", "jsonl", *extra)
        return {row["record"]: row for row in util.parse_jsonl(stdout)}

    def hits(self, *criteria):
        rc, stdout, stderr = util.run("search", self.image, "--format", "jsonl", *criteria)
        self.assertNotIn("Traceback", stderr)
        self.assertIn(rc, (0, 2), stderr)
        names = {number: key for key, number in self.rec.items()}
        found = set()
        for row in util.parse_jsonl(stdout):
            if row["record"] >= 24:
                found.add(names[row["record"]])
        return rc, found


class DumpTests(FixtureCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        rc, stdout, stderr = util.run("dump", cls.image, "--format", "jsonl")
        cls.dump = {row["record"]: row for row in util.parse_jsonl(stdout)}

    def row(self, key):
        return self.dump[self.rec[key]]

    def test_paths(self):
        for key, path in PATHS.items():
            self.assertEqual(self.row(key)["path"], path % self.rec if key == "lost" else path, key)

    def test_states(self):
        for key in PATHS:
            self.assertEqual(self.row(key)["in_use"], "no" if key in DELETED else "yes", key)

    def test_sizes(self):
        for key in ("note", "evil", "frag", "sparse", "comp_text", "comp_mixed", "hard", "extname", "del_ok"):
            self.assertEqual(self.row(key)["size"], len(self.volume.content_of(self.rec[key])), key)

    def test_directories(self):
        for key in ("users", "alice", "windows", "temp", "staging", "staging_sub", "old_dir"):
            self.assertEqual(self.row(key)["is_dir"], "yes", key)
        self.assertEqual(self.row("note")["is_dir"], "no")

    def test_system_files(self):
        self.assertEqual(self.dump[0]["path"], "$MFT")
        self.assertEqual(self.dump[6]["path"], "$Bitmap")
        self.assertEqual(self.dump[5]["is_dir"], "yes")

    def test_hard_links(self):
        row = self.row("hard")
        self.assertEqual(row["all_paths"], "Users/alice/orig.txt|Windows/Temp/alias.txt")
        self.assertEqual(row["link_count"], 2)

    def test_ads(self):
        row = self.row("evil")
        self.assertEqual(row["ads_names"], "Zone.Identifier|payload")
        self.assertEqual(row["ads_count"], 2)
        self.assertIn("ADS", row["suspicious"])

    def test_resident_flag(self):
        self.assertEqual(self.row("note")["resident"], "yes")
        self.assertEqual(self.row("frag")["resident"], "no")

    def test_data_runs(self):
        self.assertEqual(self.row("frag")["data_runs"], mft.runs_to_text(self.volume.runs_of(self.rec["frag"])))
        self.assertEqual(len(self.volume.runs_of(self.rec["frag"])), 4)
        self.assertIn("SPARSE:6", self.row("sparse")["data_runs"])

    def test_attribute_flags(self):
        self.assertEqual(self.row("comp_text")["compressed"], "yes")
        self.assertEqual(self.row("sparse")["sparse"], "yes")
        self.assertEqual(self.row("frag")["compressed"], "no")

    def test_timestomp_indicator(self):
        self.assertEqual(self.row("stomp")["si_before_fn"], "yes")
        self.assertIn("SI<FN", self.row("stomp")["suspicious"])
        self.assertEqual(self.row("evil")["si_before_fn"], "no")

    def test_subsecond_indicator(self):
        row = self.row("subsec")
        self.assertEqual(row["si_subsec_zero"], "yes")
        self.assertEqual(row["si_before_fn"], "no")
        self.assertEqual(self.row("evil")["si_subsec_zero"], "no")

    def test_reparse_tag(self):
        self.assertEqual(self.row("wof")["reparse_tag"], "0x80000017(WOF)")

    def test_name_in_extension_record(self):
        row = self.row("extname")
        self.assertEqual(row["has_attr_list"], "yes")
        self.assertNotEqual(row["ext_records"], "")

    def test_clusters_free(self):
        expected = {"del_ok": "yes", "del_res": "", "del_realloc": "no", "del_partial": "partial",
                    "payload": "yes", "tool": "yes", "lost": "yes", "contested_old": "contested",
                    "contested_new": "contested", "evil": "", "frag": ""}
        for key, value in expected.items():
            self.assertEqual(self.row(key)["clusters_free"], value, key)

    def test_deleted_indicator(self):
        self.assertIn("DELETED", self.row("del_ok")["suspicious"])
        self.assertNotIn("DELETED", self.row("evil")["suspicious"])

    def test_no_parse_errors(self):
        for row in self.dump.values():
            self.assertEqual(row["error"], "", row["record"])
            self.assertEqual(row["fixup_ok"], "yes", row["record"])

    def test_mft_offset(self):
        number = self.rec["evil"]
        self.assertEqual(self.row("evil")["mft_offset"], self.volume.mft_lcn * fx.CLUSTER + number * fx.RECORD)

    def test_timestamps(self):
        number = self.rec["evil"]
        self.assertEqual(self.row("evil")["si_created"], mft.filetime_to_iso(fx.filetime(number)))
        self.assertEqual(self.row("evil")["fn_created"], mft.filetime_to_iso(fx.filetime(number)))


class FormatTests(FixtureCase):

    def test_every_format_has_a_manifest(self):
        for fmt in ("csv", "tsv", "jsonl", "body", "html", "md"):
            path = self.out("dump." + fmt)
            self.ok("dump", self.image, "--format", fmt, "-o", path)
            self.assertGreater(os.path.getsize(path), 0, fmt)
            with open(path + ".manifest.json", encoding="utf-8") as fh:
                manifest = json.load(fh)
            self.assertEqual(manifest["output_sha256"], util.file_hash(path), fmt)
            self.assertEqual(manifest["format"], fmt)
            self.assertEqual(manifest["tool"], "MFTDigger %s" % mft.__version__)
            self.assertFalse(manifest["truncated"])

    def test_csv_columns_and_rows(self):
        path = self.out("columns.csv")
        self.ok("dump", self.image, "-o", path)
        with open(path, encoding="utf-8", newline="") as fh:
            reader = csv.DictReader(fh)
            rows = list(reader)
        self.assertEqual(reader.fieldnames, mft.DUMP_FIELDS)
        self.assertEqual(len(rows), len(self.rows()))

    def test_tsv_delimiter(self):
        path = self.out("columns.tsv")
        self.ok("dump", self.image, "--format", "tsv", "-o", path)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(fh.readline().rstrip("\n").split("\t"), mft.DUMP_FIELDS)

    def test_bodyfile(self):
        stdout, _ = self.ok("dump", self.image, "--format", "body")
        lines = stdout.splitlines()
        evil = [line for line in lines if "|/Windows/Temp/evil.exe|" in line]
        self.assertEqual(len(evil), 1)
        fields = evil[0].split("|")
        self.assertEqual(len(fields), 11)
        self.assertEqual(fields[2], "%d-128-1" % self.rec["evil"])
        self.assertEqual(int(fields[6]), 9002)
        self.assertEqual(int(fields[10]), mft.filetime_to_epoch(fx.filetime(self.rec["evil"])))
        self.assertTrue(any("deleted_ok.doc (deleted)|" in line for line in lines))
        self.assertTrue(any("evil.exe ($FILE_NAME)|" in line for line in lines))

    def test_html_embeds_rows(self):
        path = self.out("report.html")
        self.ok("search", self.image, "--deleted-only", "--format", "html", "-o", path)
        with open(path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertIn("<!DOCTYPE html>", html)
        self.assertIn("deleted_ok.doc", html)
        self.assertNotIn("evil.exe", html)

    def test_html_escapes_script_end(self):
        v = fx.Volume()
        v.add_file("x</script><b>.txt", b"data")
        image = self.write("html_escape.img", v.build())
        path = self.out("escape.html")
        self.ok("dump", image, "--format", "html", "-o", path)
        with open(path, encoding="utf-8") as fh:
            html = fh.read()
        self.assertEqual(html.count("</script>"), 2)

    def test_markdown_table(self):
        stdout, _ = self.ok("search", self.image, "--name", "evil.exe", "--format", "md")
        self.assertIn("| Record | State | Path |", stdout)
        self.assertIn("`Windows/Temp/evil.exe`", stdout)

    def test_max_rows_truncates(self):
        path = self.out("capped.md")
        _, stderr = self.ok("dump", self.image, "--format", "md", "--max-rows", "5", "-o", path)
        self.assertIn("truncated", stderr)
        with open(path + ".manifest.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertTrue(manifest["truncated"])
        self.assertEqual(manifest["rows_written"], 5)

    def test_no_runs(self):
        rows = self.rows(None, "--no-runs")
        self.assertEqual(rows[self.rec["frag"]]["data_runs"], "")

    def test_non_ascii_names_survive_redirected_output(self):
        rc, stdout, stderr = util.run("search", self.image, "--record", self.rec["unicode"])
        self.assertEqual(rc, 0, stderr)
        self.assertIn(PATHS["unicode"], stdout)

    def test_report_from_jsonl_and_csv(self):
        for fmt in ("jsonl", "csv"):
            source = self.out("full." + fmt)
            self.ok("dump", self.image, "--format", fmt, "-o", source)
            rc, stdout, stderr = util.run("report", source, "--deleted-only", "--format", "jsonl")
            self.assertEqual(rc, 0, stderr)
            found = {row["record"] for row in util.parse_jsonl(stdout)}
            self.assertEqual(found, {self.rec[key] for key in DELETED}, fmt)

    def test_report_no_match(self):
        source = self.out("nomatch.jsonl")
        self.ok("dump", self.image, "--format", "jsonl", "-o", source)
        rc, _, _ = util.run("report", source, "--name", "does-not-exist", "--format", "csv")
        self.assertEqual(rc, 2)


class SearchTests(FixtureCase):

    def test_name_glob(self):
        self.assertEqual(self.hits("--name", "*.EXE")[1], {"evil", "payload"})

    def test_path_substring(self):
        self.assertEqual(self.hits("--path", "Users\\alice", "--in-use-only")[1],
                         {"alice", "note", "hard", "extname"})

    def test_path_matches_second_hard_link(self):
        self.assertEqual(self.hits("--path", "Temp/alias")[1], {"hard"})

    def test_regex(self):
        self.assertEqual(self.hits("--regex", r"\.ps1$")[1], {"tool"})

    def test_extension(self):
        self.assertEqual(self.hits("--ext", "dll,.ZIP")[1], {"stomp", "wof", "subsec"})

    def test_deleted_only(self):
        self.assertEqual(self.hits("--deleted-only")[1], set(DELETED))

    def test_in_use_only_alone(self):
        rc, found = self.hits("--in-use-only")
        self.assertEqual(rc, 0)
        self.assertEqual(found, set(PATHS) - set(DELETED))

    def test_dirs_and_files(self):
        dirs = {"users", "alice", "windows", "temp", "staging", "staging_sub", "old_dir"}
        self.assertEqual(self.hits("--dirs-only")[1], dirs)
        self.assertEqual(self.hits("--files-only")[1], set(PATHS) - dirs)

    def test_ads_only(self):
        self.assertEqual(self.hits("--ads-only")[1], {"evil"})

    def test_timestomp(self):
        self.assertEqual(self.hits("--timestomp")[1], {"stomp"})
        self.assertEqual(self.hits("--timestomp", "--include-subsec")[1], {"stomp", "subsec"})

    def test_size_window(self):
        self.assertEqual(self.hits("--min-size", "200000")[1], {"comp_text", "comp_mixed"})
        self.assertEqual(self.hits("--min-size", "39000", "--max-size", "41000")[1], {"frag"})

    def test_record_list_and_range(self):
        spec = "%d-%d,%d" % (self.rec["frag"], self.rec["comp_text"], self.rec["unicode"])
        self.assertEqual(self.hits("--record", spec)[1], {"frag", "sparse", "comp_text", "unicode"})

    def test_time_window(self):
        start = mft.filetime_to_iso(fx.filetime(self.rec["frag"]))[:19]
        end = mft.filetime_to_iso(fx.filetime(self.rec["frag"] + 1))[:19]
        found = self.hits("--after", start, "--before", end, "--time-field", "si_created")[1]
        self.assertEqual(found, {"frag"})

    def test_combined_filters(self):
        self.assertEqual(self.hits("--deleted-only", "--ext", "exe,ps1", "--path", "staging")[1],
                         {"payload", "tool"})

    def test_limit(self):
        rc, stdout, _ = util.run("search", self.image, "--in-use-only", "--limit", "3", "--format", "jsonl")
        self.assertEqual(rc, 0)
        self.assertEqual(len(util.parse_jsonl(stdout)), 3)

    def test_no_match_exit_code(self):
        rc, found = self.hits("--name", "nothing-like-this")
        self.assertEqual(rc, 2)
        self.assertEqual(found, set())

    def test_text_output_shows_location(self):
        stdout, _ = self.ok("search", self.image, "--name", "evil.exe")
        first_lcn = self.volume.runs_of(self.rec["evil"])[0][0]
        self.assertIn("[FILE] IN USE  record %d" % self.rec["evil"], stdout)
        self.assertIn("run 0: LCN %d" % first_lcn, stdout)
        self.assertIn("volume offset %d" % (first_lcn * fx.CLUSTER), stdout)
        self.assertIn("ADS ':Zone.Identifier'", stdout)

    def test_text_output_explains_contested(self):
        stdout, _ = self.ok("search", self.image, "--name", "contested_old.txt")
        self.assertIn("also claimed by deleted record(s) %d" % self.rec["contested_new"], stdout)

    def test_record_command(self):
        stdout, _ = self.ok("record", self.image, self.rec["extname"], "--hex")
        self.assertIn("$ATTRIBUTE_LIST", stdout)
        self.assertIn("extension records:", stdout)
        self.assertIn("00000000  46 49 4c 45", stdout)


class ExportTests(FixtureCase):

    def export(self, name, *args):
        out = self.out(name)
        rc, stdout, stderr = util.run("export", self.image, "-o", out, *args)
        self.assertNotIn("Traceback", stderr)
        manifest = os.path.join(out, "export_manifest.jsonl")
        results = {}
        if os.path.exists(manifest):
            results = {row["record"]: row for row in util.read_jsonl(manifest)}
        return rc, results, out, stderr

    def stream(self, result, name="$DATA"):
        return [s for s in result["streams"] if s["stream"] == name][0]

    def test_live_content(self):
        keys = ("note", "evil", "frag", "sparse", "comp_text", "comp_mixed", "hard", "unicode", "extname",
                "newer", "newer2", "stomp")
        rc, results, out, stderr = self.export("live", "--record", ",".join(str(self.rec[k]) for k in keys))
        self.assertEqual(rc, 0, stderr)
        for key in keys:
            result = results[self.rec[key]]
            content = self.volume.content_of(self.rec[key])
            data = self.stream(result)
            self.assertEqual(result["status"], "ok", key)
            self.assertTrue(data["complete"], key)
            self.assertEqual(data["bytes"], len(content), key)
            self.assertEqual(data["sha256"], util.sha256(content), key)
            self.assertEqual(util.file_hash(os.path.join(out, data["file"])), util.sha256(content), key)

    def test_hashes_and_sidecar(self):
        rc, results, out, _ = self.export("hashes", "--record", self.rec["evil"])
        result = results[self.rec["evil"]]
        data = self.stream(result)
        path = os.path.join(out, data["file"])
        self.assertEqual(data["md5"], util.file_hash(path, "md5"))
        self.assertEqual(data["sha1"], util.file_hash(path, "sha1"))
        self.assertEqual(data["magic"][:4], "4d5a")
        self.assertEqual(result["raw_record_sha256"], util.file_hash(os.path.join(out, result["raw_record_file"])))
        with open(os.path.join(out, result["sidecar"]), encoding="utf-8") as fh:
            sidecar = json.load(fh)
        self.assertEqual(sidecar["path"], "Windows/Temp/evil.exe")
        self.assertEqual(sidecar["mft_sha256"], util.sha256(self.volume.mft_bytes()))

    def test_ads(self):
        rc, results, out, _ = self.export("ads", "--record", self.rec["evil"], "--ads")
        self.assertEqual(rc, 0)
        result = results[self.rec["evil"]]
        for name in ("Zone.Identifier", "payload"):
            content = self.volume.content_of(self.rec["evil"], name)
            self.assertEqual(self.stream(result, name)["sha256"], util.sha256(content), name)

    def test_single_stream(self):
        rc, results, out, _ = self.export("stream", "--path", "Windows/Temp/evil.exe", "--stream",
                                          "Zone.Identifier")
        self.assertEqual(rc, 0)
        result = results[self.rec["evil"]]
        self.assertEqual([s["stream"] for s in result["streams"]], ["Zone.Identifier"])

    def test_missing_stream(self):
        rc, results, _, _ = self.export("nostream", "--record", self.rec["note"], "--stream", "nope")
        self.assertEqual(rc, 1)
        self.assertEqual(results[self.rec["note"]]["status"], "no-data")

    def test_by_windows_style_path(self):
        rc, results, _, _ = self.export("winpath", "--path", "C:\\Users\\alice\\note.txt")
        self.assertEqual(rc, 0)
        self.assertEqual(list(results), [self.rec["note"]])

    def test_by_name_skips_deleted_by_default(self):
        rc, results, _, _ = self.export("byname", "--name", "*.doc")
        self.assertEqual(rc, 2)
        rc, results, _, _ = self.export("byname_deleted", "--name", "deleted_ok.doc", "--include-deleted")
        self.assertEqual(rc, 0)
        self.assertEqual(list(results), [self.rec["del_ok"]])

    def test_deleted_intact(self):
        keys = ("del_ok", "del_res", "payload", "tool", "lost")
        rc, results, _, stderr = self.export("deleted", "--record", ",".join(str(self.rec[k]) for k in keys))
        self.assertEqual(rc, 0, stderr)
        for key in keys:
            result = results[self.rec[key]]
            self.assertEqual(result["status"], "ok", key)
            self.assertFalse(result["in_use"], key)
            self.assertTrue(result["warnings"], key)
            self.assertEqual(self.stream(result)["sha256"], util.sha256(self.volume.content_of(self.rec[key])), key)

    def test_deleted_reallocated(self):
        rc, results, _, _ = self.export("realloc", "--record", self.rec["del_realloc"])
        result = results[self.rec["del_realloc"]]
        self.assertEqual(rc, 1)
        self.assertEqual(result["status"], "reallocated")
        self.assertEqual(self.stream(result)["sha256"], util.sha256(self.volume.content_of(self.rec["newer"])))

    def test_deleted_partially_reallocated(self):
        rc, results, _, _ = self.export("partial", "--record", self.rec["del_partial"])
        self.assertEqual(rc, 1)
        self.assertEqual(results[self.rec["del_partial"]]["status"], "partially-reallocated")

    def test_deleted_contested(self):
        old, new = self.rec["contested_old"], self.rec["contested_new"]
        rc, results, _, stderr = self.export("contested", "--record", "%d,%d" % (old, new))
        self.assertEqual(rc, 1)
        self.assertEqual(results[old]["status"], "contested")
        self.assertEqual(results[new]["status"], "contested")
        self.assertEqual(results[old]["clusters_shared_with"], [new])
        self.assertEqual(results[new]["clusters_shared_with"], [old])
        newer = util.sha256(self.volume.content_of(new))
        self.assertEqual(self.stream(results[old])["sha256"], newer)
        self.assertEqual(self.stream(results[new])["sha256"], newer)
        self.assertIn("also claimed by deleted record", stderr)

    def test_wof_placeholder_is_incomplete(self):
        rc, results, _, _ = self.export("wof", "--record", self.rec["wof"])
        self.assertEqual(rc, 1)
        self.assertEqual(results[self.rec["wof"]]["status"], "incomplete")

    def test_directory(self):
        rc, results, _, _ = self.export("dir", "--record", self.rec["users"])
        self.assertEqual(rc, 0)
        self.assertEqual(results[self.rec["users"]]["status"], "directory")

    def test_max_size_skips(self):
        rc, results, _, _ = self.export("maxsize", "--record", self.rec["frag"], "--max-size", "1000")
        self.assertEqual(rc, 1)
        self.assertEqual(results[self.rec["frag"]]["status"], "no-data")

    def test_max_files(self):
        rc, _, stderr = util.run("export", self.image, "--name", "*", "--max-files", "3", "-o", self.out("cap"))
        self.assertEqual(rc, 1)
        self.assertIn("--max-files", stderr)

    def test_invalid_record(self):
        rc, results, _, _ = self.export("invalid", "--record", "90")
        self.assertEqual(rc, 1)
        self.assertEqual(results[90]["status"], "error")

    def test_truncated_image_reports_incomplete(self):
        last = max(lcn + length for lcn, length in self.volume.runs_of(self.rec["frag"]))
        image = self.write("truncated.img", self.raw[:(last - 1) * fx.CLUSTER])
        out = self.out("truncated")
        rc, _, stderr = util.run("export", image, "--record", self.rec["frag"], "-o", out)
        self.assertEqual(rc, 1)
        result = util.read_jsonl(os.path.join(out, "export_manifest.jsonl"))[0]
        data = result["streams"][0]
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(data["complete"])
        self.assertTrue(data["file"].endswith(".partial"))

    def test_preserve_times(self):
        rc, results, out, _ = self.export("times", "--record", self.rec["evil"], "--preserve-times")
        path = os.path.join(out, self.stream(results[self.rec["evil"]])["file"])
        self.assertEqual(int(os.path.getmtime(path)), mft.filetime_to_epoch(fx.filetime(self.rec["evil"])))


class VolumeTests(FixtureCase):

    def user_paths(self, rows):
        return {number: row["all_paths"] for number, row in rows.items() if number >= 24}

    def test_info(self):
        stdout, _ = self.ok("info", self.image, "--stats")
        self.assertIn("Volume label   : FIXTURE", stdout)
        self.assertIn("NTFS version   : 3.1", stdout)
        self.assertIn("Cluster size   : 4096 bytes", stdout)
        self.assertIn("deleted/free   : %d" % len(DELETED), stdout)
        self.assertIn("parse errors   : 0", stdout)
        self.assertIn(util.sha256(self.volume.mft_bytes()), stdout)

    def test_verify_clean(self):
        stdout, _ = self.ok("verify", self.image)
        self.assertEqual(stdout.count("MATCH"), 4)

    def test_verify_detects_mirror_tampering(self):
        raw = bytearray(self.raw)
        raw[self.volume.mirr_lcn * fx.CLUSTER + 2 * fx.RECORD + 0x60] ^= 0xFF
        rc, stdout, _ = util.run("verify", self.write("tampered.img", raw))
        self.assertEqual(rc, 3)
        self.assertIn("record 2 $LogFile  DIFFERENT", stdout)

    def test_record0_falls_back_to_mirror(self):
        raw = bytearray(self.raw)
        start = self.volume.mft_lcn * fx.CLUSTER
        raw[start:start + fx.RECORD] = b"\x00" * fx.RECORD
        image = self.write("norecord0.img", raw)
        out = self.out("norecord0.jsonl")
        _, stderr = self.ok("dump", image, "--format", "jsonl", "-o", out)
        self.assertIn("using the $MFTMirr copy", stderr)
        rows = {row["record"]: row for row in util.read_jsonl(out)}
        self.assertEqual(self.user_paths(rows), self.user_paths(self.rows()))
        with open(out + ".manifest.json", encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["mirror_records_used"], [0])
        self.assertEqual(util.run("verify", image)[0], 3)

    def test_both_copies_of_record0_destroyed(self):
        raw = bytearray(self.raw)
        for lcn in (self.volume.mft_lcn, self.volume.mirr_lcn):
            raw[lcn * fx.CLUSTER:lcn * fx.CLUSTER + fx.RECORD] = b"\x00" * fx.RECORD
        rc, _, stderr = util.run("info", self.write("dead.img", raw))
        self.assertEqual(rc, 1)
        self.assertIn("also unusable", stderr)

    def test_mbr_and_gpt_wrappers(self):
        plain = self.user_paths(self.rows())
        for name, disk in (("mbr.img", fx.wrap_mbr(self.raw)), ("gpt.img", fx.wrap_gpt(self.raw))):
            image = self.write(name, disk)
            self.assertEqual(self.user_paths(self.rows(image)), plain, name)
            stdout, _ = self.ok("info", image, "--partitions")
            self.assertIn("NTFS", stdout.split("Partition table:")[1], name)

    def test_explicit_offset_and_partition(self):
        image = self.write("offset.img", fx.wrap_mbr(self.raw, 128))
        plain = self.user_paths(self.rows())
        self.assertEqual(self.user_paths(self.rows(image, "--offset", str(128 * 512))), plain)
        self.assertEqual(self.user_paths(self.rows(image, "--partition", "0")), plain)
        rc, _, stderr = util.run("info", image, "--partition", "3")
        self.assertEqual(rc, 1)
        self.assertIn("out of range", stderr)

    def test_extract_mft_and_standalone(self):
        out = self.out("extracted.mft")
        self.ok("extract-mft", self.image, "-o", out)
        with open(out, "rb") as fh:
            self.assertEqual(fh.read(), self.volume.mft_bytes())
        digest = util.sha256(self.volume.mft_bytes())
        with open(out + ".sha256") as fh:
            self.assertEqual(fh.read().split()[0], digest)
        dump = self.out("standalone.jsonl")
        self.ok("dump", out, "--format", "jsonl", "-o", dump)
        rows = {row["record"]: row for row in util.read_jsonl(dump)}
        self.assertEqual(self.user_paths(rows), self.user_paths(self.rows()))
        with open(dump + ".manifest.json", encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["mft_sha256"], digest)
        self.assertEqual(rows[self.rec["contested_old"]]["clusters_free"], "contested")
        self.assertEqual(rows[self.rec["del_ok"]]["clusters_free"], "")

    def test_standalone_export(self):
        out = self.out("standalone_src.mft")
        self.ok("extract-mft", self.image, "-o", out)
        dest = self.out("standalone_export")
        rc, _, _ = util.run("export", out, "--record", self.rec["note"], "-o", dest)
        self.assertEqual(rc, 0)
        rc, _, stderr = util.run("export", out, "--record", self.rec["frag"], "-o", dest)
        self.assertEqual(rc, 1)
        self.assertIn("non-resident", stderr)
        rc, _, stderr = util.run("verify", out)
        self.assertEqual(rc, 1)

    def test_manifest_hash_matches_extract(self):
        dump = self.out("hash.jsonl")
        self.ok("dump", self.image, "--format", "jsonl", "-o", dump)
        with open(dump + ".manifest.json", encoding="utf-8") as fh:
            manifest = json.load(fh)
        self.assertEqual(manifest["mft_sha256"], util.sha256(self.volume.mft_bytes()))
        self.assertIn("NOT a hash of the disk image", manifest["mft_sha256_scope"])

    def test_hash_withheld_on_truncated_mft(self):
        cut = (self.volume.mft_lcn + 8) * fx.CLUSTER
        image = self.write("short_mft.img", self.raw[:cut])
        dump = self.out("short.jsonl")
        rc, _, stderr = util.run("dump", image, "--format", "jsonl", "-o", dump)
        self.assertNotIn("Traceback", stderr)
        self.assertIn("hash withheld", stderr)
        with open(dump + ".manifest.json", encoding="utf-8") as fh:
            self.assertIsNone(json.load(fh)["mft_sha256"])


class RobustnessTests(FixtureCase):

    def test_bad_record_values(self):
        for value in ("abc", "5-", "9-3"):
            rc, _, stderr = util.run("search", self.image, "--record", value)
            self.assertEqual(rc, 1, value)
            self.assertIn("Bad --record value", stderr)
            self.assertNotIn("Traceback", stderr)
        rc, _, stderr = util.run("export", self.image, "--record", "x", "-o", self.out("badrec"))
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", stderr)

    def test_search_needs_a_criterion(self):
        rc, _, stderr = util.run("search", self.image)
        self.assertEqual(rc, 1)
        self.assertIn("at least one criterion", stderr)

    def test_bad_regex(self):
        rc, _, stderr = util.run("search", self.image, "--regex", "(")
        self.assertEqual(rc, 1)
        self.assertIn("Bad regex", stderr)

    def test_missing_source(self):
        rc, _, stderr = util.run("info", self.out("missing.img"))
        self.assertEqual(rc, 1)
        self.assertIn("Not found", stderr)

    def test_not_ntfs(self):
        rc, _, stderr = util.run("info", self.write("random.bin", fx.pattern("random", 8192)))
        self.assertEqual(rc, 1)
        self.assertNotIn("Traceback", stderr)

    def test_empty_report_input(self):
        rc, _, stderr = util.run("report", self.write("empty.csv", b""), "--format", "csv")
        self.assertEqual(rc, 1)
        self.assertIn("is empty", stderr)
        self.assertNotIn("Traceback", stderr)

    def test_truncated_attribute_header_does_not_stop_the_dump(self):
        v, rec = fx.build_standard()
        attrs = [fx.std_info(fx.filetime(1)), fx.file_name(5, 5, "x.txt", fx.filetime(1)),
                 fx.resident_attr(0xD0, b"\x00" * 728, 4)]
        raw = bytearray(fx.make_record(80, attrs))
        struct.pack_into("<II", raw, 1008, 0x80, 16)
        v.raw_records[80] = bytes(raw)
        rows = self.rows(self.write("crafted.img", v.build()))
        self.assertIn("PARSE_ERROR", rows[80]["suspicious"])
        self.assertIn("truncated header", rows[80]["error"])
        self.assertEqual(rows[80]["path"], "x.txt")
        self.assertEqual(rows[rec["evil"]]["path"], "Windows/Temp/evil.exe")

    def test_record_number_mismatch_is_flagged(self):
        v, rec = fx.build_standard()
        v.raw_records[81] = fx.make_record(4242, [fx.std_info(fx.filetime(1)),
                                                 fx.file_name(5, 5, "moved.txt", fx.filetime(1))])
        rows = self.rows(self.write("recnum.img", v.build()))
        self.assertIn("RECNUM_MISMATCH", rows[81]["suspicious"])

    def test_fuzzed_records_never_raise(self):
        rng = random.Random(20261114)
        blob = self.volume.mft_bytes()
        count = int(os.environ.get("MFTDIGGER_FUZZ_RECORDS", "4000"))
        for _ in range(count):
            number = rng.randrange(self.volume.mft_records)
            raw = bytearray(blob[number * fx.RECORD:(number + 1) * fx.RECORD])
            for _ in range(rng.randint(1, 12)):
                raw[rng.randrange(len(raw))] = rng.randrange(256)
            rec = mft.parse_record(bytes(raw), number)
            if rec.valid:
                rec.best_file_name()
                rec.ads_names()

    def test_fuzzed_images_never_crash(self):
        rng = random.Random(1337)
        start = self.volume.mft_lcn * fx.CLUSTER
        size = self.volume.mft_records * fx.RECORD
        count = int(os.environ.get("MFTDIGGER_FUZZ_IMAGES", "30"))
        path = self.out("fuzz.img")
        for i in range(count):
            raw = bytearray(self.raw)
            for _ in range(rng.randint(5, 80)):
                raw[start + rng.randrange(size)] = rng.randrange(256)
            with open(path, "wb") as fh:
                fh.write(raw)
            for command in (("dump", path, "--format", "jsonl", "-o", self.out("fuzz.jsonl")),
                            ("export", path, "--name", "*", "--include-deleted", "--ads", "-o",
                             self.out("fuzz_export"))):
                rc, _, stderr = util.run(*command)
                self.assertNotIn("Traceback", stderr, "iteration %d: %s" % (i, command[0]))
                self.assertIn(rc, (0, 1, 2), "iteration %d" % i)


class EntryPointTests(FixtureCase):

    def test_version(self):
        rc, stdout, _ = util.run("--version")
        self.assertEqual(rc, 0)
        self.assertEqual(stdout.strip(), "MFTDigger %s" % mft.__version__)

    def test_help(self):
        rc, stdout, _ = util.run("--help")
        self.assertEqual(rc, 0)
        for command in mft.COMMANDS:
            self.assertIn(command, stdout)

    def test_menu_exit(self):
        rc, stdout, _ = util.run(stdin=b"9\n")
        self.assertEqual(rc, 0)
        self.assertIn("MAIN MENU", stdout)

    def test_menu_runs_info(self):
        script = "1\n%s\n1\n6\n9\n" % self.image
        rc, stdout, stderr = util.run(stdin=script.encode())
        self.assertEqual(rc, 0, stderr)
        self.assertIn("Cluster size   : 4096 bytes", stdout)

    def test_menu_handles_end_of_input(self):
        rc, _, stderr = util.run(stdin=b"")
        self.assertEqual(rc, 0)
        self.assertNotIn("Traceback", stderr)


if __name__ == "__main__":
    unittest.main()
