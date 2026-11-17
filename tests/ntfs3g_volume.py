import hashlib
import os
import subprocess

import ntfs_fixture as fx


def _sh(command):
    subprocess.run(command, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class Builder:

    def __init__(self, work, size_mb=256):
        self.volume = os.path.join(work, "ntfs3g.img")
        self.mount_point = os.path.join(work, "mnt")
        os.makedirs(self.mount_point, exist_ok=True)
        self.live = {}
        self.ads = {}
        self.deleted = {}
        _sh("truncate -s %dM '%s' && mkntfs -F -Q -c 4096 -L MFTDIGGER '%s'" % (size_mb, self.volume, self.volume))

    def mount(self):
        _sh("ntfs-3g -o compression,streams_interface=windows '%s' '%s'" % (self.volume, self.mount_point))

    def unmount(self):
        _sh("sync && umount '%s'" % self.mount_point)

    def put(self, rel, data, group=None):
        path = os.path.join(self.mount_point, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        (self.live if group is None else group)[rel] = hashlib.sha256(data).hexdigest()

    def digest(self, rel):
        h = hashlib.sha256()
        with open(os.path.join(self.mount_point, rel), "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h.update(block)
        self.live[rel] = h.hexdigest()

    def populate(self):
        sizes = [0, 17, 300, 700, 5000, 70000]
        for d in range(12):
            for f in range(40):
                rel = "tree/d%02d/sub%d/f%04d.txt" % (d, f % 4, f)
                self.put(rel, fx.pattern(rel, sizes[(d + f) % len(sizes)]))
        for name in ("नान.txt", "北京.bin", "Süßigkeiten.dat", "чай.log", "name with spaces.txt"):
            self.put("names/" + name, fx.pattern(name, 9000))

        os.makedirs(os.path.join(self.mount_point, "frag"))
        first, second = os.path.join(self.mount_point, "frag/a.bin"), os.path.join(self.mount_point, "frag/b.bin")
        with open(first, "wb") as a, open(second, "wb") as b:
            for i in range(600):
                a.write(fx.pattern("a%d" % i, 4096))
                a.flush()
                os.fsync(a.fileno())
                b.write(fx.pattern("b%d" % i, 8192))
                b.flush()
                os.fsync(b.fileno())
        self.digest("frag/a.bin")
        self.digest("frag/b.bin")

        os.makedirs(os.path.join(self.mount_point, "sparse"))
        with open(os.path.join(self.mount_point, "sparse/holes.bin"), "wb") as fh:
            fh.truncate(40 * 1024 * 1024)
            for offset in (0, 7 * 1024 * 1024 + 123, 39 * 1024 * 1024):
                fh.seek(offset)
                fh.write(fx.pattern("hole%d" % offset, 50000))
        self.digest("sparse/holes.bin")

        os.makedirs(os.path.join(self.mount_point, "comp"))
        _sh("setfattr -h -n system.ntfs_attrib_be -v 0x00000810 '%s'" % os.path.join(self.mount_point, "comp"))
        text = b"".join(b"the quick brown fox jumps over the lazy dog %d\n" % i for i in range(40000))
        self.put("comp/text.txt", text)
        self.put("comp/mixed.bin", b"A" * 300000 + fx.pattern("mixed", 200000) + b"\x00" * 150000 + b"B" * 70001)
        self.put("comp/small.txt", b"z" * 5000)
        self.put("comp/random_tail.bin", fx.pattern("random_tail", 100000))
        self.put("comp/text_then_random.bin", b"A" * 70000 + fx.pattern("ttr", 30000))
        self.put("comp/tiny_random.bin", fx.pattern("tiny", 3000))
        self.put("comp/exact_unit.bin", fx.pattern("exact", 65536))

        self.put("links/orig.txt", fx.pattern("orig", 12345))
        os.makedirs(os.path.join(self.mount_point, "links/other"))
        os.link(os.path.join(self.mount_point, "links/orig.txt"),
                os.path.join(self.mount_point, "links/other/alias.txt"))
        self.live["links/other/alias.txt"] = self.live["links/orig.txt"]

        self.put("ads/host.txt", b"host data")
        for stream, data in (("Zone.Identifier", b"[ZoneTransfer]\r\nZoneId=3\r\n"),
                             ("big", fx.pattern("bigads", 150000))):
            with open(os.path.join(self.mount_point, "ads/host.txt:" + stream), "wb") as fh:
                fh.write(data)
            self.ads["ads/host.txt:" + stream] = hashlib.sha256(data).hexdigest()

        for i in range(30):
            self.put("gone/keep%02d.bin" % i, fx.pattern("keep%d" % i, 20000 + i * 4096), self.deleted)
        for i in range(10):
            self.put("gone/deep/a/b/file%02d.doc" % i, fx.pattern("deep%d" % i, 30000), self.deleted)
        self.put("gone/tiny.txt", b"resident and deleted", self.deleted)

    def build(self):
        self.mount()
        try:
            self.populate()
        finally:
            self.unmount()
        self.mount()
        try:
            _sh("rm -rf '%s'" % os.path.join(self.mount_point, "gone"))
        finally:
            self.unmount()
        return self.volume
