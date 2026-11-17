import csv
import datetime
import importlib.util
import os
import re
import shutil
import subprocess
import sys

import util

UNIX = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
SI = ("si_created", "si_modified", "si_mft_modified", "si_accessed")
FN = ("fn_created", "fn_modified", "fn_mft_modified", "fn_accessed")
UNDELETE_LINE = re.compile(r"^(\d+)\s+(\S{4})\s+(\d+)%\s+\S+\s+\S+\s+(\d+)\s+(.*)$")


def have_module(name):
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def analyzemft_command():
    beside = os.path.join(os.path.dirname(sys.executable), "analyzemft")
    for candidate in (beside, beside + ".exe"):
        if os.path.exists(candidate):
            return candidate
    return shutil.which("analyzemft")


def prepare(image, work, *args):
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    dump = os.path.join(work, "rows.jsonl")
    mft = os.path.join(work, "mft.bin")
    rc, _, stderr = util.run("dump", image, "--format", "jsonl", "-o", dump, *args)
    if rc != 0:
        raise RuntimeError(stderr)
    rc, _, stderr = util.run("extract-mft", image, "-o", mft, *args)
    if rc != 0:
        raise RuntimeError(stderr)
    rows = {row["record"]: row for row in util.read_jsonl(dump) if not row["error"]}
    return rows, mft


def _micro(text):
    return text[:26] if text else None


def _from_datetime(value):
    return value.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")


def _from_unix_ns(value):
    return (UNIX + datetime.timedelta(microseconds=value // 1000)).strftime("%Y-%m-%dT%H:%M:%S.%f")


def _path(text):
    text = (text or "").replace("\\", "/").strip("/")
    return "" if text == "." else text


def _our_paths(row):
    return {_path(p) for p in (row["all_paths"] or row["path"]).split("|")} | {_path(row["path"])}


def _ads(row):
    return sorted(name for name in row["ads_names"].split("|") if name)


def _result(fields):
    out = {field: [] for field in fields}
    out["records"] = 0
    return out


def compare_mft(rows, mft_path):
    from mft import PyMftParser

    theirs = {}
    unreadable = set()
    for entry in PyMftParser(mft_path).entries():
        if isinstance(entry, RuntimeError):
            continue
        item = {"seq": entry.sequence, "in_use": entry.is_allocated, "is_dir": entry.is_dir,
                "path": _path(entry.full_path), "names": [], "ads": [], "si": None}
        try:
            attributes = list(entry.attributes())
        except (OSError, RuntimeError):
            unreadable.add(entry.entry_id)
            attributes = []
        for attribute in attributes:
            if isinstance(attribute, RuntimeError):
                continue
            content = attribute.attribute_content
            if attribute.type_name == "StandardInformation" and content is not None and item["si"] is None:
                item["si"] = [_from_datetime(content.created), _from_datetime(content.modified),
                              _from_datetime(content.mft_modified), _from_datetime(content.accessed)]
            elif attribute.type_name == "FileName" and content is not None:
                item["names"].append((content.name, content.parent_entry_id,
                                      [_from_datetime(content.created), _from_datetime(content.modified),
                                       _from_datetime(content.mft_modified), _from_datetime(content.accessed)]))
            elif attribute.type_name == "DATA" and attribute.name:
                item["ads"].append(attribute.name)
        theirs[entry.entry_id] = item

    out = _result(("missing", "unreadable", "seq", "in_use", "is_dir", "si_times", "fn_times", "name", "ads",
                   "path_live", "path_deleted"))
    for number, row in rows.items():
        item = theirs.get(number)
        if item is None:
            out["missing"].append(number)
            continue
        out["records"] += 1
        in_use = row["in_use"] == "yes"
        si = [_micro(row[key]) for key in SI]
        fn = [_micro(row[key]) for key in FN]
        if item["seq"] != row["seq"]:
            out["seq"].append((number, row["seq"], item["seq"]))
        if item["in_use"] != in_use:
            out["in_use"].append((number, in_use, item["in_use"]))
        if item["is_dir"] != (row["is_dir"] == "yes"):
            out["is_dir"].append((number, row["is_dir"], item["is_dir"]))
        if number in unreadable:
            out["unreadable"].append(number)
            continue
        if item["si"] is not None and si[0] and item["si"] != si:
            out["si_times"].append((number, si, item["si"]))
        if sorted(item["ads"]) != _ads(row):
            out["ads"].append((number, _ads(row), sorted(item["ads"])))
        if not row["name"]:
            continue
        match = [name for name in item["names"] if name[0] == row["name"] and name[1] == row["parent_record"]]
        if item["names"] and not match:
            out["name"].append((number, row["name"], [name[0] for name in item["names"]]))
        if match and fn[0] and not any(name[2] == fn for name in match):
            out["fn_times"].append((number, fn, match[0][2]))
        if item["path"] not in _our_paths(row):
            out["path_live" if in_use else "path_deleted"].append((number, row["path"], item["path"]))
    return out


def compare_dissect(rows, mft_path):
    from dissect.ntfs import NTFS

    out = _result(("missing", "seq", "in_use", "is_dir", "si_times", "name", "path_live", "path_deleted", "size"))
    with open(mft_path, "rb") as fh:
        fs = NTFS(mft=fh)
        for number, row in rows.items():
            try:
                record = fs.mft.get(number)
            except Exception:
                out["missing"].append(number)
                continue
            out["records"] += 1
            in_use = row["in_use"] == "yes"
            flags = int(record.header.Flags)
            if record.header.SequenceNumber != row["seq"]:
                out["seq"].append((number, row["seq"], record.header.SequenceNumber))
            if bool(flags & 1) != in_use:
                out["in_use"].append((number, in_use, flags))
            if bool(flags & 2) != (row["is_dir"] == "yes"):
                out["is_dir"].append((number, row["is_dir"], flags))
            si = [_micro(row[key]) for key in SI]
            try:
                info = record.attributes.STANDARD_INFORMATION[0].attribute
                theirs = [_from_unix_ns(info.creation_time_ns), _from_unix_ns(info.last_modification_time_ns),
                          _from_unix_ns(info.last_change_time_ns), _from_unix_ns(info.last_access_time_ns)]
            except Exception:
                theirs = None
            if theirs is not None and si[0] and theirs != si:
                out["si_times"].append((number, si, theirs))
            if row["is_dir"] == "no" and row["has_attr_list"] == "no":
                try:
                    size = record.size()
                except Exception:
                    size = None
                if size is not None and size != row["size"]:
                    out["size"].append((number, row["size"], size))
            if not row["name"]:
                continue
            try:
                name = record.filename
            except Exception:
                name = None
            if name != row["name"]:
                out["name"].append((number, row["name"], name))
            try:
                paths = {_path(p) for p in record.full_paths()}
            except Exception:
                paths = set()
            if not paths & _our_paths(row):
                out["path_live" if in_use else "path_deleted"].append((number, row["path"], sorted(paths)))
    return out


def _milliseconds(text):
    stamp = datetime.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    fraction = text[20:].rstrip("Z")
    return int((stamp - UNIX).total_seconds()) * 1000 + int((fraction + "000")[:3] or 0)


def _close(ours, theirs):
    for a, b in zip(ours, theirs):
        if a.startswith("1601-01-01T00:00:00"):
            a = ""
        if not a and b in ("", "Not defined"):
            continue
        if not a or b in ("", "Not defined") or not b[:4].isdigit():
            return False
        if abs(_milliseconds(a) - _milliseconds(b)) > 1:
            return False
    return True


def compare_analyzemft(rows, mft_path, work):
    target = os.path.join(work, "analyzemft.csv")
    subprocess.run([analyzemft_command(), "-f", mft_path, "-o", target], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=True)
    theirs = {}
    csv.field_size_limit(1 << 30)
    with open(target, encoding="utf-8", newline="") as fh:
        for item in csv.DictReader(fh):
            theirs.setdefault(int(item["Record Number"]), item)
    out = _result(("missing", "invalid", "seq", "in_use", "is_dir", "si_times", "fn_times", "name", "parent"))
    for number, row in rows.items():
        if number == 0:
            continue
        item = theirs.get(number)
        if item is None:
            out["missing"].append(number)
            continue
        if item["Record Status"] != "Valid":
            out["invalid"].append(number)
            continue
        out["records"] += 1
        in_use = row["in_use"] == "yes"
        if int(item["Sequence Number"]) != row["seq"]:
            out["seq"].append((number, row["seq"], item["Sequence Number"]))
        if (item["Record Type"] == "In Use") != in_use:
            out["in_use"].append((number, in_use, item["Record Type"]))
        if (item["File Type"] == "Directory") != (row["is_dir"] == "yes"):
            out["is_dir"].append((number, row["is_dir"], item["File Type"]))
        if row["si_created"]:
            times = [item[key] for key in ("SI Creation Time", "SI Modification Time", "SI Entry Time",
                                           "SI Access Time")]
            if not _close([row[key] for key in SI], times):
                out["si_times"].append((number, [row[key] for key in SI], times))
        if not row["name"]:
            continue
        if row["fn_created"] and item["Filename"] == row["name"]:
            times = [item[key] for key in ("FN Creation Time", "FN Modification Time", "FN Entry Time",
                                           "FN Access Time")]
            if not _close([row[key] for key in FN], times):
                out["fn_times"].append((number, [row[key] for key in FN], times))
        if item["Filename"] != row["name"]:
            out["name"].append((number, row["name"], item["Filename"]))
        if int(item["Parent Record Number"]) != row["parent_record"]:
            out["parent"].append((number, row["parent_record"], item["Parent Record Number"]))
    return out


def mftecmd_command():
    return os.environ.get("MFTECMD") or shutil.which("MFTECmd") or shutil.which("MFTECmd.exe")


def _stamp(text):
    return text.replace(" ", "T") + "Z" if text else ""


def _zero(text):
    return "" if text.startswith("1601-01-01T00:00:00.0000000") else text


def compare_mftecmd(rows, mft_path, work):
    target = os.path.join(work, "mftecmd")
    os.makedirs(target, exist_ok=True)
    subprocess.run([mftecmd_command(), "-f", mft_path, "--csv", target, "--csvf", "mftecmd.csv", "--at", "--sn",
                    "--co", "false"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    theirs = {}
    csv.field_size_limit(1 << 30)
    with open(os.path.join(target, "mftecmd.csv"), encoding="utf-8-sig", newline="") as fh:
        for item in csv.DictReader(fh):
            theirs.setdefault(int(item["EntryNumber"]), []).append(item)
    out = _result(("missing", "seq", "in_use", "is_dir", "si_times", "fn_times", "name", "ads", "size", "lsn",
                   "path_live", "path_deleted"))
    for number, row in rows.items():
        items = theirs.get(number)
        if not items:
            out["missing"].append(number)
            continue
        out["records"] += 1
        first = items[0]
        in_use = row["in_use"] == "yes"
        names = [item for item in items if item["IsAds"] != "True"]
        streams = sorted({item["FileName"].split(":", 1)[1] for item in items if item["IsAds"] == "True"})
        if int(first["SequenceNumber"]) != row["seq"]:
            out["seq"].append((number, row["seq"], first["SequenceNumber"]))
        if (first["InUse"] == "True") != in_use:
            out["in_use"].append((number, in_use, first["InUse"]))
        if (first["IsDirectory"] == "True") != (row["is_dir"] == "yes"):
            out["is_dir"].append((number, row["is_dir"], first["IsDirectory"]))
        if row["si_created"]:
            si = [_stamp(first[key]) for key in ("Created0x10", "LastModified0x10", "LastRecordChange0x10",
                                                 "LastAccess0x10")]
            if si != [_zero(row[key]) for key in SI]:
                out["si_times"].append((number, [row[key] for key in SI], si))
        if int(first["LogfileSequenceNumber"]) != row["lsn"]:
            out["lsn"].append((number, row["lsn"], first["LogfileSequenceNumber"]))
        if streams != _ads(row):
            out["ads"].append((number, _ads(row), streams))
        if not row["name"]:
            continue
        match = [item for item in names if item["FileName"] == row["name"]
                 and int(item["ParentEntryNumber"]) == row["parent_record"]]
        if not match:
            out["name"].append((number, row["name"], [item["FileName"] for item in names]))
            continue
        if row["is_dir"] == "no" and int(match[0]["FileSize"]) != row["size"]:
            out["size"].append((number, row["size"], match[0]["FileSize"]))
        if row["fn_created"]:
            fn = [_zero(row[key]) for key in FN]
            if not any([_stamp(item[key]) for key in ("Created0x30", "LastModified0x30", "LastRecordChange0x30",
                                                      "LastAccess0x30")] == fn for item in match):
                out["fn_times"].append((number, fn, match[0]["Created0x30"]))
        paths = {_path(item["ParentPath"] + "/" + item["FileName"]) for item in match}
        paths = {_path(p[2:]) if p.startswith("./") else p for p in paths}
        if not paths & _our_paths(row):
            out["path_live" if in_use else "path_deleted"].append((number, row["path"], sorted(paths)))
    return out


def partition_offset(image):
    info = util.run("info", image)[1]
    return int(re.search(r"Partition off\. : (\d+) bytes", info).group(1))


def compare_ntfsundelete(rows, image):
    offset = partition_offset(image)
    device = image
    if offset:
        device = subprocess.check_output(["losetup", "-f", "--show", "-r", "-o", str(offset), image],
                                         text=True).strip()
    try:
        listing = subprocess.run(["ntfsundelete", "-s", device], capture_output=True, text=True,
                                 errors="replace").stdout
    finally:
        if offset:
            subprocess.run(["losetup", "-d", device])
    theirs = {}
    for line in listing.splitlines():
        match = UNDELETE_LINE.match(line)
        if match:
            theirs[int(match.group(1))] = (int(match.group(3)), match.group(5).strip())
    out = _result(("missing", "name", "recoverable"))
    out["contested"] = []
    out["compressed"] = []
    out["listed"] = len(theirs)
    for number, row in rows.items():
        if row["in_use"] != "no":
            continue
        if number not in theirs:
            out["missing"].append(number)
            continue
        out["records"] += 1
        percent, name = theirs[number]
        if not row["name"]:
            continue
        if name != row["name"]:
            out["name"].append((number, row["name"], name))
        if row["is_dir"] == "yes":
            continue
        state = "yes" if row["resident"] == "yes" or row["size"] == 0 else row["clusters_free"]
        if state == "contested":
            out["contested"].append((number, percent))
        elif row["compressed"] == "yes":
            out["compressed"].append((number, state, percent))
        elif (state == "yes") != (percent == 100) or (state == "no") != (percent == 0):
            out["recoverable"].append((number, state, percent))
    return out
