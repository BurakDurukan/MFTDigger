import hashlib
import struct

SECTOR = 512
CLUSTER = 4096
RECORD = 1024
UNIT = 16
FT_BASE = 133500000000000000
RESIDENT_LIMIT = 400

ATTRF_COMPRESSED = 0x0001
ATTRF_SPARSE = 0x8000
FLAG_DIRECTORY = 0x10000000
FLAG_ARCHIVE = 0x20
TAG_WOF = 0x80000017


def pattern(seed, size):
    out = bytearray()
    counter = 0
    while len(out) < size:
        out += hashlib.sha256(("%s:%d" % (seed, counter)).encode()).digest()
        counter += 1
    return bytes(out[:size])


def filetime(seconds=0, ticks=1234567):
    return FT_BASE + seconds * 10000000 + ticks


def _int_bytes(value, signed):
    size = 1
    while True:
        try:
            return value.to_bytes(size, "little", signed=signed)
        except OverflowError:
            size += 1


def encode_runs(runs):
    out = bytearray()
    prev = 0
    for lcn, length in runs:
        lb = _int_bytes(length, False)
        if lcn is None:
            out.append(len(lb))
            out += lb
        else:
            ob = _int_bytes(lcn - prev, True)
            prev = lcn
            out.append((len(ob) << 4) | len(lb))
            out += lb + ob
    out.append(0)
    return bytes(out)


def resident_attr(atype, value, attr_id=0, name=""):
    nm = name.encode("utf-16le")
    voff = 24 + len(nm)
    voff += -voff % 8
    body = bytearray(voff) + value
    body += b"\x00" * (-len(body) % 8)
    struct.pack_into("<IIBBHHH", body, 0, atype, len(body), 0, len(name), 24, 0, attr_id)
    struct.pack_into("<IH", body, 16, len(value), voff)
    body[24:24 + len(nm)] = nm
    return bytes(body)


def nonresident_attr(atype, runs, real_size, attr_id=0, name="", flags=0, start_vcn=0, sizes=True):
    nm = name.encode("utf-16le")
    header = 72 if flags & ATTRF_COMPRESSED else 64
    runs_off = header + len(nm)
    runs_off += -runs_off % 8
    body = bytearray(runs_off) + encode_runs(runs)
    body += b"\x00" * (-len(body) % 8)
    clusters = sum(length for _lcn, length in runs)
    struct.pack_into("<IIBBHHH", body, 0, atype, len(body), 1, len(name), header, flags, attr_id)
    struct.pack_into("<QQHH", body, 16, start_vcn, start_vcn + clusters - 1, runs_off,
                     4 if flags & ATTRF_COMPRESSED else 0)
    if sizes:
        struct.pack_into("<QQQ", body, 40, clusters * CLUSTER, real_size, real_size)
        if flags & ATTRF_COMPRESSED:
            stored = sum(length for lcn, length in runs if lcn is not None)
            struct.pack_into("<Q", body, 64, stored * CLUSTER)
    body[header:header + len(nm)] = nm
    return bytes(body)


def std_info(created, modified=None, flags=FLAG_ARCHIVE):
    modified = created if modified is None else modified
    value = struct.pack("<QQQQI", created, modified, modified, modified, flags) + b"\x00" * 36
    return resident_attr(0x10, value, 0)


def file_name(parent, parent_seq, name, created, namespace=3, flags=FLAG_ARCHIVE, size=0, attr_id=1):
    ref = parent | (parent_seq << 48)
    value = struct.pack("<QQQQQQQII", ref, created, created, created, created, size, size, flags, 0)
    value += struct.pack("<BB", len(name), namespace) + name.encode("utf-16le")
    return resident_attr(0x30, value, attr_id)


def index_root():
    value = struct.pack("<IIIB3x", 0x30, 1, CLUSTER, 1)
    value += struct.pack("<IIIB3x", 16, 32, 32, 0)
    value += struct.pack("<QHHI", 0, 16, 0, 2)
    return resident_attr(0x90, value, 9, "$I30")


def attribute_list(entries):
    out = bytearray()
    for atype, ref, seq, attr_id in entries:
        out += struct.pack("<IHBBQQH", atype, 32, 0, 26, 0, ref | (seq << 48), attr_id) + b"\x00" * 6
    return resident_attr(0x20, bytes(out), 8)


def make_record(number, attrs, seq=1, flags=1, base=0, base_seq=0, links=1, signature=b"FILE"):
    buf = bytearray(RECORD)
    buf[0:4] = signature
    struct.pack_into("<HH", buf, 4, 0x30, 3)
    pos = 0x38
    for attr in attrs:
        buf[pos:pos + len(attr)] = attr
        pos += len(attr)
    if pos + 8 > RECORD:
        raise ValueError("record %d does not fit (%d bytes)" % (number, pos + 8))
    struct.pack_into("<I", buf, pos, 0xFFFFFFFF)
    struct.pack_into("<HHHHIIQH", buf, 16, seq, links, 0x38, flags, pos + 8, RECORD,
                     base | (base_seq << 48), 16)
    struct.pack_into("<I", buf, 0x2C, number)
    usn = b"\x07\x00"
    struct.pack_into("<2s2s2s", buf, 0x30, usn, bytes(buf[510:512]), bytes(buf[1022:1024]))
    buf[510:512] = usn
    buf[1022:1024] = usn
    return bytes(buf)


def lznt1_chunk(data):
    out = bytearray()
    table = {}
    i = 0
    n = len(data)
    while i < n:
        flag_pos = len(out)
        out.append(0)
        flags = 0
        for bit in range(8):
            if i >= n:
                break
            best = 0
            if i + 3 <= n:
                cand = table.get(data[i:i + 3])
                if cand is not None:
                    l_mask = 0xFFF
                    o_shift = 12
                    q = i - 1
                    while q >= 0x10:
                        l_mask >>= 1
                        o_shift -= 1
                        q >>= 1
                    disp = i - cand
                    if disp <= 1 << (16 - o_shift):
                        length = 0
                        while length < l_mask + 3 and i + length < n and data[cand + length] == data[i + length]:
                            length += 1
                        if length >= 3:
                            best = length
            if best:
                out += struct.pack("<H", ((disp - 1) << o_shift) | (best - 3))
                flags |= 1 << bit
                for k in range(best):
                    if i + k + 3 <= n:
                        table[data[i + k:i + k + 3]] = i + k
                i += best
            else:
                if i + 3 <= n:
                    table[data[i:i + 3]] = i
                out.append(data[i])
                i += 1
        out[flag_pos] = flags
    return bytes(out)


def lznt1_compress(data):
    out = bytearray()
    for pos in range(0, len(data), 4096):
        chunk = data[pos:pos + 4096]
        packed = lznt1_chunk(chunk)
        if len(packed) < len(chunk):
            out += struct.pack("<H", 0xB000 | (len(packed) - 1)) + packed
        else:
            out += struct.pack("<H", 0x3000 | (len(chunk) - 1)) + chunk
    return bytes(out)


class Volume:

    def __init__(self, clusters=2048, mft_records=96, label="FIXTURE"):
        self.clusters = clusters
        self.mft_records = mft_records
        self.label = label
        self.mft_lcn = 4
        self.mft_clusters = mft_records * RECORD // CLUSTER
        self.mirr_lcn = clusters // 2
        self.bitmap_lcn = self.mirr_lcn + 1
        self.data = bytearray(clusters * CLUSTER)
        self.used = set([0, self.mirr_lcn, self.bitmap_lcn])
        self.used.update(range(self.mft_lcn, self.mft_lcn + self.mft_clusters))
        self.next_lcn = 64
        self.next_record = 24
        self.specs = {}
        self.raw_records = {}

    def _alloc(self, count):
        if self.next_lcn < self.bitmap_lcn + 1 and self.next_lcn + count > self.mirr_lcn:
            self.next_lcn = self.bitmap_lcn + 1
        lcn = self.next_lcn
        self.next_lcn += count
        if self.next_lcn > self.clusters:
            raise ValueError("fixture volume is full")
        return lcn

    def _write(self, lcn, data):
        self.data[lcn * CLUSTER:lcn * CLUSTER + len(data)] = data

    def _write_runs(self, runs, data):
        pos = 0
        for lcn, length in runs:
            if lcn is not None:
                self._write(lcn, data[pos:pos + length * CLUSTER])
                self.used.update(range(lcn, lcn + length))
            pos += length * CLUSTER

    def _store(self, content, fragments=1, layout=None, compressed=False, runs=None):
        if runs is not None:
            self._write_runs(runs, content)
            return {"runs": list(runs), "size": len(content), "flags": 0, "content": content}
        if compressed:
            out = []
            for pos in range(0, len(content), UNIT * CLUSTER):
                unit = content[pos:pos + UNIT * CLUSTER]
                if not unit.strip(b"\x00"):
                    out.append((None, UNIT))
                    continue
                packed = lznt1_compress(unit)
                need = -(-len(packed) // CLUSTER)
                if need < UNIT:
                    lcn = self._alloc(need)
                    self._write_runs([(lcn, need)], packed)
                    out += [(lcn, need), (None, UNIT - need)]
                else:
                    lcn = self._alloc(UNIT)
                    self._write_runs([(lcn, UNIT)], unit)
                    out.append((lcn, UNIT))
            return {"runs": out, "size": len(content), "flags": ATTRF_COMPRESSED, "content": content}
        if layout is not None:
            out = []
            full = bytearray()
            for part in layout:
                if isinstance(part, int):
                    out.append((None, part))
                    full += b"\x00" * (part * CLUSTER)
                else:
                    need = -(-len(part) // CLUSTER)
                    lcn = self._alloc(need)
                    self._write_runs([(lcn, need)], part)
                    out.append((lcn, need))
                    full += part + b"\x00" * (need * CLUSTER - len(part))
            size = len(content) if content else len(full)
            return {"runs": out, "size": size, "flags": ATTRF_SPARSE, "content": bytes(full[:size])}
        total = max(1, -(-len(content) // CLUSTER))
        fragments = min(fragments, total)
        per = -(-total // fragments)
        out = []
        done = 0
        while done < total:
            take = min(per, total - done)
            lcn = self._alloc(take)
            self._write_runs([(lcn, take)], content[done * CLUSTER:(done + take) * CLUSTER])
            out.append((lcn, take))
            done += take
            self.next_lcn += 1
        return {"runs": out, "size": len(content), "flags": 0, "content": content}

    def _new_spec(self, name, parent, is_dir, number=None):
        if number is None:
            number = self.next_record
            self.next_record += 1
        pseq = 5 if parent == 5 else self.specs[parent]["seq"]
        spec = {"number": number, "seq": 1, "in_use": True, "is_dir": is_dir,
                "names": [(parent, pseq, name, 3)], "streams": {}, "reparse": None,
                "si_created": filetime(number), "fn_created": filetime(number), "si_modified": None,
                "name_in_extension": False}
        self.specs[number] = spec
        return spec

    def add_dir(self, name, parent=5, short_name=None):
        spec = self._new_spec(name, parent, True)
        if short_name is not None:
            parent_ref, pseq, long_name, _ = spec["names"][0]
            spec["names"] = [(parent_ref, pseq, short_name, 2)]
            spec["extension_names"] = [(parent_ref, pseq, long_name, 1)]
            spec["ext_number"] = self.next_record
            self.next_record += 1
        return spec["number"]

    def add_file(self, name, content=b"", parent=5, fragments=1, layout=None, compressed=False, runs=None,
                 ads=None, resident=None, si_created=None, fn_created=None, si_modified=None, reparse=None,
                 name_in_extension=False):
        spec = self._new_spec(name, parent, False)
        plain = layout is None and not compressed and runs is None and fragments == 1
        if resident is None:
            resident = plain and len(content) <= RESIDENT_LIMIT
        if resident:
            spec["streams"][""] = {"resident": True, "content": content, "size": len(content)}
        else:
            spec["streams"][""] = self._store(content, fragments, layout, compressed, runs)
        for stream, data in (ads or {}).items():
            if len(data) <= RESIDENT_LIMIT // 2:
                spec["streams"][stream] = {"resident": True, "content": data, "size": len(data)}
            else:
                spec["streams"][stream] = self._store(data)
        if si_created is not None:
            spec["si_created"] = si_created
        if fn_created is not None:
            spec["fn_created"] = fn_created
        spec["si_modified"] = si_modified
        spec["reparse"] = reparse
        spec["name_in_extension"] = name_in_extension
        if name_in_extension:
            spec["ext_number"] = self.next_record
            self.next_record += 1
        return spec["number"]

    def add_link(self, number, name, parent):
        pseq = 5 if parent == 5 else self.specs[parent]["seq"]
        self.specs[number]["names"].append((parent, pseq, name, 3))

    def runs_of(self, number, stream=""):
        return list(self.specs[number]["streams"][stream]["runs"])

    def content_of(self, number, stream=""):
        return self.specs[number]["streams"][stream]["content"]

    def delete(self, number):
        spec = self.specs[number]
        spec["in_use"] = False
        spec["seq"] += 1
        for stream in spec["streams"].values():
            for lcn, length in stream.get("runs", []):
                if lcn is not None:
                    self.used.difference_update(range(lcn, lcn + length))

    def reuse(self, number, name, parent=5, is_dir=True):
        spec = self.specs[number]
        if spec["in_use"]:
            self.delete(number)
        pseq = 5 if parent == 5 else self.specs[parent]["seq"]
        spec.update(in_use=True, is_dir=is_dir, names=[(parent, pseq, name, 3)], streams={})

    def _records_for(self, spec):
        number = spec["number"]
        flags = (1 if spec["in_use"] else 0) | (2 if spec["is_dir"] else 0)
        fn_flags = FLAG_DIRECTORY if spec["is_dir"] else FLAG_ARCHIVE
        default = spec["streams"].get("")
        size = default["size"] if default else 0
        names = [file_name(parent, pseq, name, spec["fn_created"], ns, fn_flags, size, 1 + i)
                 for i, (parent, pseq, name, ns) in enumerate(spec["names"])]
        attrs = [std_info(spec["si_created"], spec["si_modified"], 0 if spec["is_dir"] else FLAG_ARCHIVE)]
        extra = {}
        if spec.get("extension_names"):
            ext = spec["ext_number"]
            moved = [file_name(parent, pseq, name, spec["fn_created"], ns, fn_flags, size, 8 + i)
                     for i, (parent, pseq, name, ns) in enumerate(spec["extension_names"])]
            attrs.append(attribute_list([(0x10, number, spec["seq"], 0), (0x30, number, spec["seq"], 1),
                                         (0x30, ext, 1, 8)]))
            attrs += names
            extra[ext] = make_record(ext, moved, seq=1, flags=flags & 1, base=number, base_seq=spec["seq"])
        elif spec["name_in_extension"]:
            ext = spec["ext_number"]
            attrs.append(attribute_list([(0x10, number, spec["seq"], 0), (0x30, ext, 1, 1),
                                         (0x80, number, spec["seq"], 4)]))
            extra[ext] = make_record(ext, names, seq=1, flags=flags & 1, base=number, base_seq=spec["seq"])
        else:
            attrs += names
        attr_id = 4
        for stream in sorted(spec["streams"]):
            st = spec["streams"][stream]
            if st.get("resident"):
                attrs.append(resident_attr(0x80, st["content"], attr_id, stream))
            else:
                attrs.append(nonresident_attr(0x80, st["runs"], st["size"], attr_id, stream, st["flags"]))
            attr_id += 1
        if spec["is_dir"]:
            attrs.append(index_root())
        if spec["reparse"] is not None:
            attrs.append(resident_attr(0xC0, struct.pack("<IHH", spec["reparse"], 16, 0) + b"\x00" * 16, 10))
        extra[number] = make_record(number, attrs, seq=spec["seq"], flags=flags, links=len(spec["names"]))
        return extra

    def _system_records(self):
        now = filetime(0)
        out = {}

        def system(number, name, attrs, flags=1):
            seq = number if number else 1
            base = [std_info(now, None, 0x06),
                    file_name(5, 5, name, now, 3, FLAG_DIRECTORY if flags & 2 else 0x06)]
            out[number] = make_record(number, base + attrs, seq=seq, flags=flags)

        system(0, "$MFT", [nonresident_attr(0x80, [(self.mft_lcn, self.mft_clusters)],
                                            self.mft_records * RECORD, 4)])
        system(1, "$MFTMirr", [nonresident_attr(0x80, [(self.mirr_lcn, 1)], 4 * RECORD, 4)])
        system(2, "$LogFile", [resident_attr(0x80, b"", 4)])
        system(3, "$Volume", [resident_attr(0x60, self.label.encode("utf-16le"), 4),
                              resident_attr(0x70, struct.pack("<QBBH", 0, 3, 1, 0), 5),
                              resident_attr(0x80, b"", 6)])
        system(4, "$AttrDef", [resident_attr(0x80, b"", 4)])
        system(5, ".", [index_root()], flags=3)
        system(6, "$Bitmap", [nonresident_attr(0x80, [(self.bitmap_lcn, 1)], self.clusters // 8, 4)])
        system(7, "$Boot", [nonresident_attr(0x80, [(0, 1)], CLUSTER, 4)])
        system(8, "$BadClus", [resident_attr(0x80, b"", 4)])
        system(9, "$Secure", [resident_attr(0x80, b"", 4)])
        system(10, "$UpCase", [resident_attr(0x80, b"", 4)])
        system(11, "$Extend", [index_root()], flags=3)
        for number in range(12, 24):
            out[number] = make_record(number, [std_info(now, None, 0x06)], seq=number)
        return out

    def boot_sector(self):
        bs = bytearray(SECTOR)
        bs[0:3] = b"\xEB\x52\x90"
        bs[3:11] = b"NTFS    "
        struct.pack_into("<H", bs, 0x0B, SECTOR)
        bs[0x0D] = CLUSTER // SECTOR
        bs[0x15] = 0xF8
        struct.pack_into("<Q", bs, 0x28, self.clusters * CLUSTER // SECTOR)
        struct.pack_into("<Q", bs, 0x30, self.mft_lcn)
        struct.pack_into("<Q", bs, 0x38, self.mirr_lcn)
        struct.pack_into("<b", bs, 0x40, -10)
        struct.pack_into("<b", bs, 0x44, 1)
        struct.pack_into("<Q", bs, 0x48, 0x1122334455667788)
        bs[510:512] = b"\x55\xAA"
        return bytes(bs)

    def mft_bytes(self):
        records = self._system_records()
        for number in sorted(self.specs):
            records.update(self._records_for(self.specs[number]))
        records.update(self.raw_records)
        if max(records) >= self.mft_records:
            raise ValueError("too many records for the fixture $MFT")
        out = bytearray(self.mft_records * RECORD)
        for number, raw in records.items():
            out[number * RECORD:(number + 1) * RECORD] = raw
        return bytes(out)

    def build(self):
        image = bytearray(self.data)
        mft = self.mft_bytes()
        image[self.mft_lcn * CLUSTER:self.mft_lcn * CLUSTER + len(mft)] = mft
        image[self.mirr_lcn * CLUSTER:self.mirr_lcn * CLUSTER + 4 * RECORD] = mft[:4 * RECORD]
        bitmap = bytearray(CLUSTER)
        for lcn in self.used:
            bitmap[lcn >> 3] |= 1 << (lcn & 7)
        image[self.bitmap_lcn * CLUSTER:(self.bitmap_lcn + 1) * CLUSTER] = bitmap
        image[0:SECTOR] = self.boot_sector()
        return bytes(image)


def wrap_mbr(volume, start_sector=128):
    disk = bytearray(start_sector * SECTOR) + volume
    struct.pack_into("<B3xB3xII", disk, 446, 0x80, 0x07, start_sector, len(volume) // SECTOR)
    disk[510:512] = b"\x55\xAA"
    return bytes(disk)


def wrap_mbr_extended(volume):
    ext, second, start = 1024, 512, 64
    volume_sector = ext + second + start
    disk = bytearray(volume_sector * SECTOR) + volume
    struct.pack_into("<B3xB3xII", disk, 446, 0, 0x83, 128, 64)
    struct.pack_into("<B3xB3xII", disk, 462, 0, 0x05, ext, second + start + len(volume) // SECTOR)
    disk[510:512] = b"\x55\xAA"
    first_ebr = ext * SECTOR
    struct.pack_into("<B3xB3xII", disk, first_ebr + 446, 0, 0x83, 8, 8)
    struct.pack_into("<B3xB3xII", disk, first_ebr + 462, 0, 0x05, second, start + len(volume) // SECTOR)
    disk[first_ebr + 510:first_ebr + 512] = b"\x55\xAA"
    second_ebr = (ext + second) * SECTOR
    struct.pack_into("<B3xB3xII", disk, second_ebr + 446, 0, 0x07, start, len(volume) // SECTOR)
    disk[second_ebr + 510:second_ebr + 512] = b"\x55\xAA"
    return bytes(disk)


def wrap_mbr_extended_third_entry(volume):
    ext, start = 1024, 64
    sectors = len(volume) // SECTOR
    second = start + sectors
    disk = bytearray((ext + start) * SECTOR) + volume + bytearray(64 * SECTOR)
    struct.pack_into("<B3xB3xII", disk, 446, 0, 0x05, ext, second + 64)
    disk[510:512] = b"\x55\xAA"
    first_ebr = ext * SECTOR
    struct.pack_into("<B3xB3xII", disk, first_ebr + 446, 0, 0x83, 8, 8)
    struct.pack_into("<B3xB3xII", disk, first_ebr + 462, 0, 0x07, start, sectors)
    struct.pack_into("<B3xB3xII", disk, first_ebr + 478, 0, 0x05, second, 64)
    disk[first_ebr + 510:first_ebr + 512] = b"\x55\xAA"
    second_ebr = (ext + second) * SECTOR
    struct.pack_into("<B3xB3xII", disk, second_ebr + 446, 0, 0x83, 8, 8)
    disk[second_ebr + 510:second_ebr + 512] = b"\x55\xAA"
    return bytes(disk)


def wrap_gpt(volume, start_sector=2048, sector_size=SECTOR):
    sectors = len(volume) // sector_size
    disk = bytearray(start_sector * sector_size) + volume + bytearray(34 * sector_size)
    struct.pack_into("<B3xB3xII", disk, 446, 0, 0xEE, 1, 0xFFFFFFFF)
    disk[510:512] = b"\x55\xAA"
    header = bytearray(SECTOR)
    header[0:8] = b"EFI PART"
    struct.pack_into("<IIIIQQQQ", header, 8, 0x00010000, 92, 0, 0, 1, len(disk) // sector_size - 1, 34,
                     len(disk) // sector_size - 34)
    struct.pack_into("<QIII", header, 72, 2, 128, 128, 0)
    disk[sector_size:sector_size + SECTOR] = header
    entry = bytearray(128)
    entry[0:16] = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
    entry[16:32] = hashlib.md5(b"fixture").digest()
    struct.pack_into("<QQ", entry, 32, start_sector, start_sector + sectors - 1)
    entry[56:56 + 40] = "Basic data partition".encode("utf-16le")
    disk[2 * sector_size:2 * sector_size + 128] = entry
    return bytes(disk)


def foreign_boot_sector(kind):
    bs = bytearray(SECTOR)
    bs[0:3] = b"\xEB\x58\x90"
    if kind == "bitlocker":
        bs[3:11] = b"-FVE-FS-"
    elif kind == "exfat":
        bs[3:11] = b"EXFAT   "
    elif kind == "refs":
        bs[3:11] = b"ReFS\x00\x00\x00\x00"
    elif kind == "fat32":
        bs[3:11] = b"MSDOS5.0"
        bs[0x52:0x5A] = b"FAT32   "
    bs[510:512] = b"\x55\xAA"
    return bytes(bs)


def build_standard():
    v = Volume()
    r = {}
    r["users"] = v.add_dir("Users")
    r["alice"] = v.add_dir("alice", r["users"])
    r["note"] = v.add_file("note.txt", b"resident content for alice\r\n", r["alice"])
    r["windows"] = v.add_dir("Windows")
    r["temp"] = v.add_dir("Temp", r["windows"])
    r["evil"] = v.add_file("evil.exe", b"MZ" + pattern("evil", 9000), r["temp"],
                           ads={"Zone.Identifier": b"[ZoneTransfer]\r\nZoneId=3\r\n",
                                "payload": pattern("payload", 6000)})
    r["frag"] = v.add_file("frag.bin", pattern("frag", 40000), fragments=4)
    r["sparse"] = v.add_file("sparse.bin", layout=[pattern("s1", 5000), 6, pattern("s2", 8192), 3,
                                                   pattern("s3", 100)])
    text = b"".join(b"line %06d the quick brown fox jumps over the lazy dog\r\n" % i for i in range(4000))
    r["comp_text"] = v.add_file("comp.txt", text, compressed=True)
    mixed = b"A" * 70000 + pattern("mixed", 66000) + b"\x00" * 140000 + b"tail " * 3000
    r["comp_mixed"] = v.add_file("comp_mixed.bin", mixed, compressed=True)
    r["hard"] = v.add_file("orig.txt", pattern("hard", 5000), r["alice"])
    v.add_link(r["hard"], "alias.txt", r["temp"])
    r["unicode"] = v.add_file("北京-чай-Süß.txt", pattern("uni", 4500))
    r["stomp"] = v.add_file("stomped.dll", pattern("stomp", 5000), r["temp"],
                            si_created=filetime(-90000000), fn_created=filetime(500))
    r["subsec"] = v.add_file("whole_second.zip", pattern("sub", 5000), si_created=filetime(700, 0),
                             fn_created=filetime(600), si_modified=filetime(701, 0))
    r["wof"] = v.add_file("wof.dll", pattern("wof", 5000), reparse=TAG_WOF)
    r["extname"] = v.add_file("name_in_extension.vhd", pattern("ext", 20000), r["alice"], fragments=3,
                              name_in_extension=True)

    r["del_ok"] = v.add_file("deleted_ok.doc", pattern("del_ok", 12000), r["alice"])
    v.delete(r["del_ok"])
    r["del_res"] = v.add_file("deleted_resident.txt", b"small deleted file", r["alice"])
    v.delete(r["del_res"])
    r["del_realloc"] = v.add_file("deleted_realloc.doc", pattern("del_realloc", 9000))
    v.delete(r["del_realloc"])
    r["newer"] = v.add_file("newer.bin", pattern("newer", 9000), runs=v.runs_of(r["del_realloc"]))
    r["del_partial"] = v.add_file("deleted_partial.doc", pattern("del_partial", 30000), fragments=2)
    v.delete(r["del_partial"])
    r["newer2"] = v.add_file("newer2.bin", pattern("newer2", 4000), runs=v.runs_of(r["del_partial"])[:1])

    r["staging"] = v.add_dir("staging")
    r["staging_sub"] = v.add_dir("sub", r["staging"])
    r["payload"] = v.add_file("payload.exe", b"MZ" + pattern("payload.exe", 7000), r["staging"])
    r["tool"] = v.add_file("tool.ps1", pattern("tool", 5000), r["staging_sub"])
    for key in ("tool", "payload", "staging_sub", "staging"):
        v.delete(r[key])

    r["old_dir"] = v.add_dir("old_dir")
    r["lost"] = v.add_file("lost.txt", pattern("lost", 5000), r["old_dir"])
    v.delete(r["lost"])
    v.reuse(r["old_dir"], "replacement_dir")

    r["contested_old"] = v.add_file("contested_old.txt", pattern("contested_old", 8000))
    v.delete(r["contested_old"])
    r["contested_new"] = v.add_file("contested_new.txt", pattern("contested_new", 8000),
                                    runs=v.runs_of(r["contested_old"]))
    v.delete(r["contested_new"])
    return v, r
