import bz2
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TOOL = os.path.join(ROOT, "MFTDigger.py")
DATA = os.path.join(HERE, "data")


def run(*args, **kwargs):
    proc = subprocess.run([sys.executable, TOOL] + [str(a) for a in args], capture_output=True,
                          input=kwargs.get("stdin"))
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def module():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    import MFTDigger
    return MFTDigger


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def parse_jsonl(text):
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def file_hash(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def images_dir():
    return os.environ.get("MFTDIGGER_IMAGES") or os.path.join(HERE, "images")


def load_data(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as fh:
        return json.load(fh)


def materialize(entry, dest):
    base = images_dir()
    ready = os.path.join(base, entry["image"])
    if os.path.exists(ready):
        return ready
    if "parts" in entry:
        parts = [os.path.join(base, part["name"]) for part in entry["parts"]]
        if not all(os.path.exists(part) for part in parts):
            return None
        out = os.path.join(dest, entry["image"])
        with open(out, "wb") as dst:
            for part in parts:
                with open(part, "rb") as src:
                    shutil.copyfileobj(src, dst, 1 << 22)
        return out
    archive = os.path.join(base, entry["archive"])
    if not os.path.exists(archive):
        return None
    out = os.path.join(dest, entry["image"])
    if archive.endswith(".bz2"):
        with bz2.open(archive, "rb") as src, open(out, "wb") as dst:
            shutil.copyfileobj(src, dst, 1 << 22)
    else:
        with zipfile.ZipFile(archive) as zf:
            member = [m for m in zf.namelist() if m.endswith("/" + entry["image"]) or m == entry["image"]][0]
            with zf.open(member) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst, 1 << 22)
    return out


def have(*programs):
    return all(shutil.which(p) for p in programs)
