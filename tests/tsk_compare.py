import datetime
import hashlib
import json
import os
import re
import shutil
import subprocess

import util


def _epoch(iso):
    if not iso or iso.startswith(("INVALID", "1601")):
        return 0
    stamp = datetime.datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
    return int((stamp - datetime.datetime(1970, 1, 1)).total_seconds())


def _normalise(path):
    return re.sub(r"^\$OrphanFiles/<[^/]*>/", "$OrphanFiles/", path)


def _icat(image, offset, inode):
    digest = hashlib.sha256()
    size = 0
    with subprocess.Popen(["icat", "-o", str(offset), image, inode], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL) as proc:
        for block in iter(lambda: proc.stdout.read(1 << 20), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def compare(image, work, max_size=64 * 1024 * 1024):
    shutil.rmtree(work, ignore_errors=True)
    os.makedirs(work)
    info = util.run("info", image)[1]
    offset = int(re.search(r"Partition off\. : (\d+) bytes", info).group(1)) // 512

    dump = os.path.join(work, "dump.jsonl")
    rc, _, stderr = util.run("dump", image, "--format", "jsonl", "-o", dump)
    if rc:
        raise RuntimeError(stderr)
    rows = {row["record"]: row for row in util.read_jsonl(dump)}
    with open(dump + ".manifest.json", encoding="utf-8") as fh:
        manifest = json.load(fh)
    last = max(rows)

    body = subprocess.run(["fls", "-r", "-m", "/", "-o", str(offset), image], capture_output=True)
    tsk = {}
    index_only = 0
    for line in body.stdout.decode("utf-8", "replace").splitlines():
        fields = line.split("|")
        if len(fields) < 11:
            continue
        name, inode, mode = "|".join(fields[1:-9]), fields[-9], fields[-8]
        size, atime, mtime, ctime, crtime = (int(x) for x in fields[-5:])
        if "($FILE_NAME)" in name or mode.startswith("V/"):
            continue
        realloc = name.endswith(" (deleted-realloc)")
        deleted = realloc or name.endswith(" (deleted)")
        name = re.sub(r" \(deleted(-realloc)?\)$", "", name).lstrip("/")
        parts = inode.split("-")
        record = int(parts[0])
        if record > last or realloc:
            continue
        if record == 0 and name != "$MFT":
            index_only += 1
            continue
        if name.startswith("$OrphanFiles/OrphanFile-") and not rows.get(record, {}).get("name"):
            continue
        stream = ""
        leaf = name.rsplit("/", 1)[-1]
        if ":" in leaf:
            stream = leaf.split(":", 1)[1]
            name = name[:len(name) - len(stream) - 1]
        entry = tsk.setdefault(record, {"paths": set(), "streams": {}, "deleted": deleted})
        entry["paths"].add(name)
        entry["deleted"] = deleted
        if stream == "":
            entry.update(size=size, times=(atime, mtime, ctime, crtime), is_dir=mode[2:3] == "d")
        if len(parts) == 3 and parts[1] == "128":
            entry["streams"][stream] = inode

    result = {"records": 0, "index_only_names": index_only, "path": [], "state": [], "time": [], "size": [],
              "ads": [], "content": [], "bitmap": [], "streams": 0, "deleted_streams": 0, "bytes": 0,
              "bitmap_checked": 0}
    for record in sorted(set(tsk) & set(rows)):
        entry, row = tsk[record], rows[record]
        result["records"] += 1
        ours = {_normalise(p) for p in (row["all_paths"] or row["path"]).split("|")} if record != 5 else {""}
        theirs = entry["paths"] if record != 5 else {""}
        if ours != theirs:
            result["path"].append((record, sorted(ours), sorted(theirs)))
        if (row["in_use"] == "no") != entry["deleted"]:
            result["state"].append((record, row["in_use"], entry["deleted"]))
        if "times" in entry:
            mine = (_epoch(row["si_accessed"]), _epoch(row["si_modified"]), _epoch(row["si_mft_modified"]),
                    _epoch(row["si_created"]))
            if mine != entry["times"]:
                result["time"].append((record, mine, entry["times"]))
            if not entry["is_dir"] and row["is_dir"] != "yes" and row["size"] != entry["size"]:
                result["size"].append((record, row["size"], entry["size"]))
        if set(filter(None, row["ads_names"].split("|"))) != {s for s in entry["streams"] if s}:
            result["ads"].append((record, row["ads_names"], sorted(entry["streams"])))

    export = os.path.join(work, "export")
    util.run("export", image, "--name", "*", "--include-deleted", "--ads", "--max-files", "100000",
             "--max-size", str(max_size), "--no-raw-record", "-o", export)
    exported = {}
    manifest_path = os.path.join(export, "export_manifest.jsonl")
    if os.path.exists(manifest_path):
        for item in util.read_jsonl(manifest_path):
            for stream in item.get("streams", []):
                exported[(item["record"], "" if stream["stream"] == "$DATA" else stream["stream"])] = stream
    for record, entry in sorted(tsk.items()):
        if record == 8 or record not in rows:
            continue
        for stream, inode in entry["streams"].items():
            ours = exported.get((record, stream))
            if ours is None or not ours.get("complete"):
                continue
            digest, size = _icat(image, offset, inode)
            result["streams"] += 1
            result["bytes"] += size
            result["deleted_streams"] += rows[record]["in_use"] == "no"
            if digest != ours["sha256"] or size != ours["bytes"]:
                result["content"].append((record, stream, ours["bytes"], size))
    shutil.rmtree(export, ignore_errors=True)

    result["mft_hash_match"] = _icat(image, offset, "0")[0] == manifest["mft_sha256"]

    bitmap = subprocess.run(["icat", "-o", str(offset), image, "6"], capture_output=True).stdout
    for record, row in rows.items():
        state = row["clusters_free"]
        if row["in_use"] != "no" or not row["data_runs"] or state in ("", "?"):
            continue
        total = allocated = 0
        for run in row["data_runs"].split(";"):
            if not run or run.startswith("SPARSE"):
                continue
            lcn, length = (int(x) for x in run.split(":"))
            for cluster in range(lcn, lcn + length):
                total += 1
                allocated += (bitmap[cluster >> 3] >> (cluster & 7)) & 1
        want = "yes" if allocated == 0 else "no" if allocated == total else "partial"
        result["bitmap_checked"] += 1
        if want != ("yes" if state == "contested" else state):
            result["bitmap"].append((record, state, want))
    return result
