import argparse
import os
import sys
import urllib.request

import util


def fetch(entry, dest):
    if "parts" in entry:
        return all([fetch_file(part["name"], part["url"], part["bytes"], part["sha256"], dest)
                    for part in entry["parts"]])
    return fetch_file(entry["archive"], entry["url"], entry["archive_bytes"], entry["archive_sha256"], dest)


def fetch_file(name, url, size, sha256, dest):
    target = os.path.join(dest, name)
    if os.path.exists(target) and util.file_hash(target) == sha256:
        print("ok       %s" % name)
        return True
    print("download %s (%d bytes)" % (name, size))
    request = urllib.request.Request(url, headers={"User-Agent": "MFTDigger-tests"})
    with urllib.request.urlopen(request, timeout=120) as response, open(target + ".part", "wb") as out:
        while True:
            block = response.read(1 << 20)
            if not block:
                break
            out.write(block)
    digest = util.file_hash(target + ".part")
    if digest != sha256:
        os.remove(target + ".part")
        print("FAILED   %s: sha256 %s, expected %s" % (name, digest, sha256))
        return False
    os.replace(target + ".part", target)
    print("verified %s" % name)
    return True


def download_size(entry):
    if "parts" in entry:
        return sum(part["bytes"] for part in entry["parts"])
    return entry["archive_bytes"]


def main():
    catalogue = util.load_data("images.json")
    parser = argparse.ArgumentParser(description="Download the public test images listed in tests/data/images.json")
    parser.add_argument("ids", nargs="*", help="image ids (default: dftt7)")
    parser.add_argument("--all", action="store_true", help="download every image except the large ones (about 64 MB)")
    parser.add_argument("--large", action="store_true", help="also download the large images (4.5 GB)")
    parser.add_argument("--list", action="store_true", help="list the known images and exit")
    parser.add_argument("--dest", default=util.images_dir(), help="target directory")
    args = parser.parse_args()
    if args.list:
        for entry in catalogue:
            print("%-22s %10d  %s" % (entry["id"], download_size(entry), entry["description"]))
        return 0
    wanted = list(args.ids)
    if args.all:
        wanted += [e["id"] for e in catalogue if not e.get("large")]
    if args.large:
        wanted += [e["id"] for e in catalogue if e.get("large")]
    wanted = list(dict.fromkeys(wanted)) or ["dftt7"]
    known = {e["id"]: e for e in catalogue}
    unknown = [i for i in wanted if i not in known]
    if unknown:
        print("unknown image id: %s" % ", ".join(unknown))
        return 1
    os.makedirs(args.dest, exist_ok=True)
    results = [fetch(known[i], args.dest) for i in wanted]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
