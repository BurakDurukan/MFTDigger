#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MFTDigger.py - NTFS $MFT triage tool for incident responders
=========================================================

Pure Python 3.8+, standard library only. Works on Windows, Linux and macOS.
Author: Burak Durukan

Input sources
  * Live logical volume     Windows: \\\\.\\C:        Linux: /dev/sda2      macOS: /dev/rdisk2s1
  * Live physical disk      Windows: \\\\.\\PhysicalDrive0   Linux: /dev/sda   (NTFS partition auto-detected)
  * Raw disk / volume image dd / raw / .001 (E01 is NOT supported - convert with ewfexport / FTK Imager)
  * Standalone $MFT file    e.g. C/$MFT collected by KAPE / velociraptor / Invoke-WinTriage

Commands
  info        Volume / $MFT summary and partition table
  dump        Dump every MFT record (CSV / JSONL / bodyfile)
  search      Find records by name / path / regex / extension / time / state, print location
  export      Extract a file's $DATA (or an ADS) from disk, with hash + metadata sidecar
  extract-mft Copy the raw $MFT out of the volume for other tools

Everything that goes wrong is reported on stderr - the tool never silently
hides an error, because in IR a missing record is evidence too.
"""

import argparse
import csv
import datetime as _dt
import fnmatch
import hashlib
import io
import json
import os
import platform
import re
import struct
import sys
import time

__version__ = "1.4.0"
TOOL_NAME = "MFTDigger"

ATTR_STANDARD_INFORMATION = 0x10
ATTR_ATTRIBUTE_LIST = 0x20
ATTR_FILE_NAME = 0x30
ATTR_OBJECT_ID = 0x40
ATTR_SECURITY_DESCRIPTOR = 0x50
ATTR_VOLUME_NAME = 0x60
ATTR_VOLUME_INFORMATION = 0x70
ATTR_DATA = 0x80
ATTR_INDEX_ROOT = 0x90
ATTR_INDEX_ALLOCATION = 0xA0
ATTR_BITMAP = 0xB0
ATTR_REPARSE_POINT = 0xC0
ATTR_EA_INFORMATION = 0xD0
ATTR_EA = 0xE0
ATTR_LOGGED_UTILITY_STREAM = 0x100
ATTR_END = 0xFFFFFFFF

ATTR_NAMES = {
    0x10: "$STANDARD_INFORMATION", 0x20: "$ATTRIBUTE_LIST", 0x30: "$FILE_NAME",
    0x40: "$OBJECT_ID", 0x50: "$SECURITY_DESCRIPTOR", 0x60: "$VOLUME_NAME",
    0x70: "$VOLUME_INFORMATION", 0x80: "$DATA", 0x90: "$INDEX_ROOT",
    0xA0: "$INDEX_ALLOCATION", 0xB0: "$BITMAP", 0xC0: "$REPARSE_POINT",
    0xD0: "$EA_INFORMATION", 0xE0: "$EA", 0x100: "$LOGGED_UTILITY_STREAM",
}

FILE_ATTR_FLAGS = [
    (0x0001, "READONLY"), (0x0002, "HIDDEN"), (0x0004, "SYSTEM"),
    (0x0020, "ARCHIVE"), (0x0040, "DEVICE"), (0x0080, "NORMAL"),
    (0x0100, "TEMPORARY"), (0x0200, "SPARSE"), (0x0400, "REPARSE_POINT"),
    (0x0800, "COMPRESSED"), (0x1000, "OFFLINE"), (0x2000, "NOT_INDEXED"),
    (0x4000, "ENCRYPTED"), (0x8000, "INTEGRITY"), (0x10000000, "DIRECTORY"),
    (0x20000000, "INDEX_VIEW"),
]

ATTRF_COMPRESSED = 0x0001
ATTRF_ENCRYPTED = 0x4000
ATTRF_SPARSE = 0x8000

REPARSE_TAGS = {
    0xA0000003: "MOUNT_POINT", 0xA000000C: "SYMLINK", 0x80000017: "WOF",
    0x8000001B: "APPEXECLINK", 0x9000001A: "CLOUD", 0x80000024: "WCI",
    0x80000018: "WCI_1", 0x80000019: "GLOBAL_REPARSE", 0x8000000B: "DFS",
    0x80000012: "DFSR", 0xC0000004: "HSM", 0x80000006: "HSM2",
    0xA0000019: "NFS", 0x80000014: "DEDUP", 0x80000021: "PROJFS",
    0xA000001D: "LX_SYMLINK", 0x80000023: "AF_UNIX", 0x80000025: "LX_FIFO",
    0x80000026: "LX_CHR", 0x80000027: "LX_BLK",
}

NAMESPACES = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32+DOS"}

MFT_REC_MFT, MFT_REC_MFTMIRR, MFT_REC_LOGFILE, MFT_REC_VOLUME = 0, 1, 2, 3
MFT_REC_ATTRDEF, MFT_REC_ROOT, MFT_REC_BITMAP, MFT_REC_BOOT = 4, 5, 6, 7

EPOCH_DIFF_100NS = 116444736000000000  


_VERBOSE = False


def log(msg):
    sys.stderr.write("[*] %s\n" % msg)
    sys.stderr.flush()


def warn(msg):
    sys.stderr.write("[!] %s\n" % msg)
    sys.stderr.flush()


def err(msg):
    sys.stderr.write("[X] %s\n" % msg)
    sys.stderr.flush()


def dbg(msg):
    if _VERBOSE:
        sys.stderr.write("[d] %s\n" % msg)
        sys.stderr.flush()


class MftError(Exception):
    pass


def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)


def filetime_to_iso(ft):
    
    if ft is None:
        return ""
    if ft == 0:
        return "1601-01-01T00:00:00.0000000Z"
    try:
        us, frac = divmod(ft - EPOCH_DIFF_100NS, 10)
        base = _dt.datetime(1970, 1, 1) + _dt.timedelta(microseconds=us)
        return base.strftime("%Y-%m-%dT%H:%M:%S.%f") + str(frac) + "Z"
    except (OverflowError, ValueError):
        return "INVALID(0x%016X)" % ft


def filetime_to_epoch(ft):
    if not ft:
        return 0
    v = (ft - EPOCH_DIFF_100NS) // 10000000
    return v if v > 0 else 0


def parse_user_time(s):
    
    if not s:
        return None
    s = s.strip().replace(" ", "T").rstrip("Z")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M", "%Y-%m-%d"):
        try:
            d = _dt.datetime.strptime(s, fmt)
            delta = d - _dt.datetime(1970, 1, 1)
            return int(delta.total_seconds() * 10000000) + EPOCH_DIFF_100NS
        except ValueError:
            continue
    raise argparse.ArgumentTypeError("Unrecognised time '%s' (use YYYY-MM-DD[THH:MM[:SS]])" % s)


def flags_to_text(value, table=FILE_ATTR_FLAGS):
    names = [n for bit, n in table if value & bit]
    return "|".join(names)


def hexdump(data, base=0, width=16):
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hx = " ".join("%02x" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %-*s  %s" % (base + i, width * 3, hx, asc))
    return "\n".join(lines)


def human_size(n):
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return "%.1f %s" % (n, unit) if unit != "B" else "%d B" % n
        n /= 1024.0
    return str(n)


def is_admin():
    try:
        if os.name == "nt":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except Exception:
        return False


def lznt1_decompress(data, out_size):
    out = bytearray()
    pos = 0
    n = len(data)
    while pos + 2 <= n and len(out) < out_size:
        hdr = data[pos] | (data[pos + 1] << 8)
        pos += 2
        if hdr == 0:
            break
        size = (hdr & 0xFFF) + 1
        chunk = data[pos:pos + size]
        pos += size
        if not (hdr & 0x8000):
            out += chunk
            continue
        cout = bytearray()
        cpos = 0
        clen = len(chunk)
        while cpos < clen:
            flags = chunk[cpos]
            cpos += 1
            for bit in range(8):
                if cpos >= clen:
                    break
                if not (flags >> bit) & 1:
                    cout.append(chunk[cpos])
                    cpos += 1
                else:
                    if cpos + 1 >= clen:
                        cpos = clen
                        break
                    token = chunk[cpos] | (chunk[cpos + 1] << 8)
                    cpos += 2
                    p = len(cout) - 1
                    l_mask = 0xFFF
                    o_shift = 12
                    while p >= 0x10:
                        l_mask >>= 1
                        o_shift -= 1
                        p >>= 1
                    length = (token & l_mask) + 3
                    disp = (token >> o_shift) + 1
                    if disp > len(cout):
                        raise MftError("LZNT1: back-reference beyond buffer (corrupt data)")
                    for _ in range(length):
                        cout.append(cout[-disp])
        if len(cout) < 4096 and pos < n:
            cout += b"\x00" * (4096 - len(cout))
        out += cout
    if len(out) < out_size:
        out += b"\x00" * (out_size - len(out))
    return bytes(out[:out_size])


class RawSource:

    ALIGN = 4096

    def __init__(self, path, base_offset=0):
        self.path = path
        self.base = base_offset
        self.fh = None
        self.size = None
        self._open()

    def _open(self):
        try:
            self.fh = open(self.path, "rb", buffering=0)
        except PermissionError:
            raise MftError("Permission denied opening %s - run as Administrator / root" % self.path)
        except FileNotFoundError:
            raise MftError("Not found: %s" % self.path)
        except OSError as e:
            raise MftError("Cannot open %s: %s" % (self.path, e))
        try:
            st = os.fstat(self.fh.fileno())
            if st.st_size:
                self.size = st.st_size
        except OSError:
            pass
        if not self.size:
            try:
                self.size = self.fh.seek(0, os.SEEK_END)
                self.fh.seek(0)
            except OSError:
                self.size = None
        if self.size == 0:
            self.size = None

    def read(self, offset, length):
        if length <= 0:
            return b""
        abs_off = self.base + offset
        start = abs_off - (abs_off % self.ALIGN)
        end = abs_off + length
        end_al = end + (-end % self.ALIGN)
        try:
            self.fh.seek(start)
            buf = self.fh.read(end_al - start)
        except (OSError, OverflowError, ValueError) as e:
            try:
                self.fh.seek(abs_off)
                buf = self.fh.read(length)
                if buf is None:
                    buf = b""
                return buf
            except (OSError, OverflowError, ValueError):
                raise MftError("Read error at offset %d (%d bytes): %s" % (abs_off, length, e))
        if buf is None:
            buf = b""
        return buf[abs_off - start: abs_off - start + length]

    def close(self):
        try:
            if self.fh:
                self.fh.close()
        except OSError:
            pass


def is_ntfs_boot_sector(b):
    return len(b) >= 512 and b[3:11] == b"NTFS    " and b[510:512] == b"\x55\xAA"


GPT_MAX_ENTRIES = 1024


def find_partitions(src):
    parts = []
    try:
        mbr = src.read(0, 512)
    except MftError:
        return parts
    if len(mbr) < 512 or mbr[510:512] != b"\x55\xAA":
        return parts
    gpt = False
    for i in range(4):
        e = mbr[446 + i * 16: 446 + (i + 1) * 16]
        ptype = e[4]
        lba = struct.unpack("<I", e[8:12])[0]
        cnt = struct.unpack("<I", e[12:16])[0]
        if ptype == 0xEE:
            gpt = True
        if ptype == 0 or cnt == 0:
            continue
        parts.append({"index": len(parts), "start_offset": lba * 512, "length": cnt * 512,
                      "type": "MBR:0x%02X" % ptype, "ntfs": False})
    if gpt:
        parts = []
        try:
            hdr = src.read(512, 512)
            if hdr[:8] == b"EFI PART":
                entries_lba = struct.unpack("<Q", hdr[72:80])[0]
                n_entries = struct.unpack("<I", hdr[80:84])[0]
                entry_size = struct.unpack("<I", hdr[84:88])[0]

                if entry_size < 128 or entry_size > 4096 or entry_size % 8:
                    warn("GPT header: implausible entry size %d - assuming 128" % entry_size)
                    entry_size = 128
                if n_entries > GPT_MAX_ENTRIES:
                    warn("GPT header claims %d entries - only the first %d are read (corrupt or tampered header?)"
                         % (n_entries, GPT_MAX_ENTRIES))
                    n_entries = GPT_MAX_ENTRIES
                table = src.read(entries_lba * 512, n_entries * entry_size)
                for i in range(n_entries):
                    e = table[i * entry_size:(i + 1) * entry_size]
                    if len(e) < 56 or e[:16] == b"\x00" * 16:
                        continue
                    first = struct.unpack("<Q", e[32:40])[0]
                    last = struct.unpack("<Q", e[40:48])[0]
                    name = e[56:128].decode("utf-16le", "replace").rstrip("\x00")
                    parts.append({"index": len(parts), "start_offset": first * 512,
                                  "length": (last - first + 1) * 512,
                                  "type": "GPT:%s" % (name or "?"), "ntfs": False})
        except MftError:
            pass
    for p in parts:
        try:
            p["ntfs"] = is_ntfs_boot_sector(src.read(p["start_offset"], 512))
        except MftError:
            p["ntfs"] = False
    return parts



def parse_data_runs(buf):
    runs = []
    pos = 0
    lcn = 0
    n = len(buf)
    while pos < n:
        hdr = buf[pos]
        pos += 1
        if hdr == 0:
            break
        len_sz = hdr & 0x0F
        off_sz = hdr >> 4
        if len_sz == 0 or pos + len_sz + off_sz > n:
            raise MftError("Malformed data run header 0x%02X at %d" % (hdr, pos - 1))
        length = int.from_bytes(buf[pos:pos + len_sz], "little")
        pos += len_sz
        if off_sz == 0:
            runs.append((None, length))  
        else:
            delta = int.from_bytes(buf[pos:pos + off_sz], "little", signed=True)
            pos += off_sz
            lcn += delta
            if lcn < 0:
                raise MftError("Negative LCN in data run (corrupt run list)")
            runs.append((lcn, length))
    return runs


def runs_to_text(runs):
    return ";".join(("SPARSE:%d" % l) if lcn is None else ("%d:%d" % (lcn, l)) for lcn, l in runs)



class Attribute:
    __slots__ = ("type", "name", "flags", "id", "resident", "value", "start_vcn", "end_vcn",
                 "runs", "alloc_size", "real_size", "init_size", "comp_unit", "offset", "length",
                 "value_offset")

    def __init__(self):
        self.type = 0
        self.name = ""
        self.flags = 0
        self.id = 0
        self.resident = True
        self.value = b""
        self.start_vcn = 0
        self.end_vcn = 0
        self.runs = []
        self.alloc_size = 0
        self.real_size = 0
        self.init_size = 0
        self.comp_unit = 0
        self.offset = 0
        self.length = 0
        self.value_offset = 0

    @property
    def type_name(self):
        return ATTR_NAMES.get(self.type, "0x%X" % self.type)

    @property
    def size(self):
        return len(self.value) if self.resident else self.real_size


class FileNameAttr:
    __slots__ = ("parent_ref", "parent_seq", "created", "modified", "mft_modified", "accessed",
                 "alloc_size", "real_size", "flags", "reparse", "namespace", "name")

    def __init__(self):
        self.parent_ref = 0
        self.parent_seq = 0
        self.created = self.modified = self.mft_modified = self.accessed = 0
        self.alloc_size = self.real_size = 0
        self.flags = 0
        self.reparse = 0
        self.namespace = 0
        self.name = ""


class StdInfoAttr:
    __slots__ = ("created", "modified", "mft_modified", "accessed", "flags", "usn", "owner_id",
                 "security_id")

    def __init__(self):
        self.created = self.modified = self.mft_modified = self.accessed = 0
        self.flags = 0
        self.usn = 0
        self.owner_id = 0
        self.security_id = 0


class IndexRootAttr:
    
    __slots__ = ("type", "collation_rule", "bytes_per_index_record", "clusters_per_index_record",
                 "entries_offset", "index_length", "alloc_length", "has_subnodes")

    def __init__(self):
        self.type = 0
        self.collation_rule = 0
        self.bytes_per_index_record = 0
        self.clusters_per_index_record = 0
        self.entries_offset = 0
        self.index_length = 0
        self.alloc_length = 0
        self.has_subnodes = False


class MftRecord:
    

    def __init__(self, number):
        self.number = number
        self.raw = b""
        self.valid = False
        self.error = ""
        self.signature = ""
        self.seq = 0
        self.lsn = 0
        self.link_count = 0
        self.flags = 0
        self.bytes_used = 0
        self.bytes_alloc = 0
        self.base_ref = 0
        self.base_seq = 0
        self.next_attr_id = 0
        self.stored_number = None
        self.fixup_ok = True
        self.attributes = []
        self.std_info = None
        self.file_names = []
        self.attr_list_refs = []
        self.reparse_tag = None
        self.object_id = None
        self.ext_records = []  
        self.index_root = None

    @property
    def in_use(self):
        return bool(self.flags & 0x01)

    @property
    def is_dir(self):
        return bool(self.flags & 0x02)

    @property
    def is_extension(self):
        return self.base_ref != 0

    @property
    def has_attr_list(self):
        return any(a.type == ATTR_ATTRIBUTE_LIST for a in self.attributes)

    def best_file_name(self):
        
        best = None
        best_rank = 99
        for fn in self.file_names:
            rank = {3: 0, 1: 1, 0: 2, 2: 3}.get(fn.namespace, 4)
            if rank < best_rank:
                best, best_rank = fn, rank
        return best

    def data_attrs(self):
        return [a for a in self.attributes if a.type == ATTR_DATA]

    def get_data_attr(self, stream_name=""):
        parts = [a for a in self.attributes if a.type == ATTR_DATA and a.name == stream_name]
        parts.sort(key=lambda a: a.start_vcn)
        return parts

    def ads_names(self):
        return sorted({a.name for a in self.attributes if a.type == ATTR_DATA and a.name})

    def extension(self):
        fn = self.best_file_name()
        if not fn or "." not in fn.name:
            return ""
        return fn.name.rsplit(".", 1)[1].lower()


def apply_fixup(buf, sector_size=512):
    
    if len(buf) < 0x30:
        return buf, False
    usa_off, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt < 2 or usa_off + usa_cnt * 2 > len(buf):
        return buf, False
    buf = bytearray(buf)
    usn = buf[usa_off:usa_off + 2]
    ok = True

    stride = len(buf) // (usa_cnt - 1)
    if stride <= 0 or stride % 256:
        stride = sector_size
    for i in range(1, usa_cnt):
        sec_end = i * stride
        if sec_end > len(buf):
            ok = False
            break
        if buf[sec_end - 2:sec_end] != usn:
            ok = False
        buf[sec_end - 2:sec_end] = buf[usa_off + i * 2: usa_off + i * 2 + 2]
    return bytes(buf), ok


def parse_attributes(buf, attr_off, record_number):
    
    pos = attr_off
    n = len(buf)
    while pos + 8 <= n:
        atype, alen = struct.unpack_from("<II", buf, pos)
        if atype == ATTR_END or atype == 0:
            break
        if alen < 16 or pos + alen > n:
            raise MftError("Attribute 0x%X at +%d has bad length %d" % (atype, pos, alen))
        a = Attribute()
        a.type = atype
        a.length = alen
        a.offset = pos
        nonres, name_len = struct.unpack_from("<BB", buf, pos + 8)
        name_off, a.flags, a.id = struct.unpack_from("<HHH", buf, pos + 10)
        if name_len:
            a.name = buf[pos + name_off: pos + name_off + name_len * 2].decode("utf-16le", "replace")
        if nonres == 0:
            a.resident = True
            vlen, voff = struct.unpack_from("<IH", buf, pos + 16)
            if voff + vlen > alen:
                vlen = max(0, alen - voff)
                a.value = buf[pos + voff: pos + voff + vlen]
            else:
                a.value = buf[pos + voff: pos + voff + vlen]
            a.value_offset = pos + voff
            a.real_size = a.alloc_size = a.init_size = len(a.value)
        else:
            a.resident = False
            (a.start_vcn, a.end_vcn, runs_off, a.comp_unit) = struct.unpack_from("<QQHH", buf, pos + 16)
            (a.alloc_size, a.real_size, a.init_size) = struct.unpack_from("<QQQ", buf, pos + 40)
            try:
                a.runs = parse_data_runs(buf[pos + runs_off: pos + alen])
            except MftError as e:
                raise MftError("Record %d attr %s: %s" % (record_number, a.type_name, e))
        yield a
        pos += alen


def parse_file_name(value):
    fn = FileNameAttr()
    if len(value) < 66:
        raise MftError("$FILE_NAME too short (%d bytes)" % len(value))
    ref = struct.unpack_from("<Q", value, 0)[0]
    fn.parent_ref = ref & 0xFFFFFFFFFFFF
    fn.parent_seq = ref >> 48
    (fn.created, fn.modified, fn.mft_modified, fn.accessed,
     fn.alloc_size, fn.real_size, fn.flags, fn.reparse) = struct.unpack_from("<QQQQQQII", value, 8)
    name_len, fn.namespace = struct.unpack_from("<BB", value, 64)
    fn.name = value[66:66 + name_len * 2].decode("utf-16le", "replace")
    return fn


def parse_std_info(value):
    si = StdInfoAttr()
    if len(value) < 48:
        raise MftError("$STANDARD_INFORMATION too short (%d bytes)" % len(value))
    (si.created, si.modified, si.mft_modified, si.accessed, si.flags) = struct.unpack_from("<QQQQI", value, 0)
    if len(value) >= 72:
        si.owner_id, si.security_id = struct.unpack_from("<II", value, 48)
        si.usn = struct.unpack_from("<Q", value, 64)[0]
    return si


def parse_index_root(value):
    idx = IndexRootAttr()
    if len(value) < 32:
        raise MftError("$INDEX_ROOT too short (%d bytes)" % len(value))
    (idx.type, idx.collation_rule, idx.bytes_per_index_record,
     idx.clusters_per_index_record) = struct.unpack_from("<IIIB3x", value, 0)
    (idx.entries_offset, idx.index_length, idx.alloc_length, flags) = struct.unpack_from("<IIIB3x", value, 16)
    idx.has_subnodes = bool(flags & 0x01)
    return idx


def parse_attribute_list(value):

    entries = []
    pos = 0
    n = len(value)
    while pos + 26 <= n:
        atype, elen = struct.unpack_from("<IH", value, pos)
        if atype == 0 or elen < 26:
            break
        if atype not in ATTR_NAMES or elen & 7 or pos + elen > n:
            raise MftError("invalid $ATTRIBUTE_LIST entry at +%d (type=0x%X len=%d) - stale or corrupt" %
                           (pos, atype, elen))
        name_len, name_off = struct.unpack_from("<BB", value, pos + 6)
        start_vcn, ref, aid = struct.unpack_from("<QQH", value, pos + 8)
        if name_len and (name_off < 26 or name_off + name_len * 2 > elen):
            raise MftError("invalid $ATTRIBUTE_LIST entry name at +%d - stale or corrupt" % pos)
        name = ""
        if name_len:
            name = value[pos + name_off: pos + name_off + name_len * 2].decode("utf-16le", "replace")
        entries.append((atype, name, start_vcn, ref & 0xFFFFFFFFFFFF, ref >> 48, aid))
        pos += elen
    return entries


def parse_record(buf, number, sector_size=512):
    rec = MftRecord(number)
    rec.raw = buf
    if len(buf) < 0x30:
        rec.error = "record too short"
        return rec
    sig = buf[0:4]
    rec.signature = sig.decode("ascii", "replace")
    if sig == b"\x00\x00\x00\x00":
        rec.error = "empty (never used)"
        return rec
    if sig not in (b"FILE", b"BAAD"):
        rec.error = "bad signature %r" % sig
        return rec
    buf, rec.fixup_ok = apply_fixup(buf, sector_size)
    if sig == b"BAAD":
        rec.error = "BAAD signature (chkdsk marked record corrupt)"
    (rec.lsn,) = struct.unpack_from("<Q", buf, 8)
    (rec.seq, rec.link_count, attr_off, rec.flags, rec.bytes_used, rec.bytes_alloc,
     base_ref, rec.next_attr_id) = struct.unpack_from("<HHHHIIQH", buf, 16)
    rec.base_ref = base_ref & 0xFFFFFFFFFFFF
    rec.base_seq = base_ref >> 48
    if attr_off >= 0x30:
        rec.stored_number = struct.unpack_from("<I", buf, 0x2C)[0]
    if attr_off < 0x30 or attr_off >= len(buf):
        rec.error = "bad attribute offset %d" % attr_off
        return rec
    try:
        for a in parse_attributes(buf, attr_off, number):
            rec.attributes.append(a)
    except MftError as e:
        rec.error = str(e)
    rec.valid = True
    _post_process(rec)
    return rec


def _post_process(rec):
    rec.file_names = []
    rec.std_info = None
    rec.reparse_tag = None
    rec.attr_list_refs = []
    rec.index_root = None
    for a in rec.attributes:
        try:
            if a.type == ATTR_FILE_NAME and a.resident:
                rec.file_names.append(parse_file_name(a.value))
            elif a.type == ATTR_STANDARD_INFORMATION and a.resident and rec.std_info is None:
                rec.std_info = parse_std_info(a.value)
            elif a.type == ATTR_REPARSE_POINT and a.resident and len(a.value) >= 4:
                rec.reparse_tag = struct.unpack_from("<I", a.value, 0)[0]
            elif a.type == ATTR_OBJECT_ID and a.resident and len(a.value) >= 16:
                g = a.value[:16]
                rec.object_id = "%08x-%04x-%04x-%s-%s" % (
                    struct.unpack("<I", g[0:4])[0], struct.unpack("<H", g[4:6])[0],
                    struct.unpack("<H", g[6:8])[0], g[8:10].hex(), g[10:16].hex())
            elif a.type == ATTR_INDEX_ROOT and a.resident and a.name == "$I30" and rec.index_root is None:
                rec.index_root = parse_index_root(a.value)
        except MftError as e:
            if not rec.error:
                rec.error = str(e)



class MftSource:
    record_size = 1024
    record_count = 0
    sector_size = 512
    cluster_size = None
    volume = None
    kind = "?"
    read_errors = 0

    def read_record_raw(self, n):
        raise NotImplementedError

    def record_offset(self, n):
        raise NotImplementedError

    def iter_raw(self, start=0, end=None, hasher=None):
        end = self.record_count if end is None else min(end, self.record_count)
        for n in range(start, end):
            try:
                raw = self.read_record_raw(n)
            except MftError as e:
                self.read_errors += 1
                warn("Record %d unreadable: %s" % (n, e))
                raw = b""
            if hasher is not None:
                hasher.update(raw)
            yield n, raw


class MftFileSource(MftSource):
    kind = "mft-file"

    def __init__(self, path):
        self.path = path
        self.read_errors = 0
        self.fh = open(path, "rb")
        self.size = os.fstat(self.fh.fileno()).st_size
        head = self.fh.read(0x30)
        if head[:4] not in (b"FILE", b"BAAD"):
            raise MftError("%s does not start with a FILE record - not an $MFT file" % path)
        alloc = struct.unpack_from("<I", head, 0x1C)[0]
        if alloc not in (1024, 4096, 512, 2048):
            warn("Unusual record size %d in %s, assuming 1024" % (alloc, path))
            alloc = 1024
        self.record_size = alloc
        self.record_count = self.size // alloc
        if self.size % alloc:
            warn("$MFT file size %d is not a multiple of %d - trailing partial record ignored" % (self.size, alloc))

    def read_record_raw(self, n):
        self.fh.seek(n * self.record_size)
        return self.fh.read(self.record_size)

    def record_offset(self, n):
        return n * self.record_size

    def iter_raw(self, start=0, end=None, hasher=None):
        end = self.record_count if end is None else min(end, self.record_count)
        rs = self.record_size
        n = 0 if hasher is not None else start
        per_chunk = max(1, (4 * 1024 * 1024) // rs)
        while n < end:
            take = min(per_chunk, end - n)
            self.fh.seek(n * rs)
            data = self.fh.read(take * rs)
            if not data:
                break
            if hasher is not None:
                hasher.update(data)
            for i in range(len(data) // rs):
                if n >= start:
                    yield n, data[i * rs:(i + 1) * rs]
                n += 1
            if len(data) < take * rs:
                break
        if hasher is not None and end == self.record_count:
            self.fh.seek(self.record_count * rs)
            hasher.update(self.fh.read())

    def close(self):
        self.fh.close()


class NtfsVolume:

    def __init__(self, src):
        self.src = src
        bs = src.read(0, 512)
        if not is_ntfs_boot_sector(bs):
            raise MftError("No NTFS boot sector at offset %d (OEM=%r)" % (src.base, bs[3:11]))
        self.bytes_per_sector = struct.unpack_from("<H", bs, 0x0B)[0]
        self.sectors_per_cluster = bs[0x0D]
        if self.sectors_per_cluster > 0x80:  
            self.sectors_per_cluster = 1 << (256 - self.sectors_per_cluster)
        self.cluster_size = self.bytes_per_sector * self.sectors_per_cluster
        self.total_sectors = struct.unpack_from("<Q", bs, 0x28)[0]
        self.mft_lcn = struct.unpack_from("<Q", bs, 0x30)[0]
        self.mftmirr_lcn = struct.unpack_from("<Q", bs, 0x38)[0]
        cpr = struct.unpack_from("<b", bs, 0x40)[0]
        self.record_size = (1 << (-cpr)) if cpr < 0 else cpr * self.cluster_size
        cpi = struct.unpack_from("<b", bs, 0x44)[0]
        self.index_size = (1 << (-cpi)) if cpi < 0 else cpi * self.cluster_size
        self.serial = struct.unpack_from("<Q", bs, 0x48)[0]
        self.volume_size = self.total_sectors * self.bytes_per_sector
        if self.cluster_size == 0 or self.record_size == 0:
            raise MftError("Boot sector reports zero cluster/record size - corrupt")

        def pow2(v):
            return v > 0 and v & (v - 1) == 0
        if not (pow2(self.bytes_per_sector) and 256 <= self.bytes_per_sector <= 4096):
            raise MftError("Boot sector: implausible bytes/sector %d - corrupt or not NTFS" % self.bytes_per_sector)
        if not (pow2(self.cluster_size) and self.cluster_size <= 2 * 1024 * 1024):
            raise MftError("Boot sector: implausible cluster size %d - corrupt" % self.cluster_size)
        if not (pow2(self.record_size) and 256 <= self.record_size <= 65536):
            raise MftError("Boot sector: implausible MFT record size %d - corrupt" % self.record_size)
        self.total_clusters = self.volume_size // self.cluster_size

    def read_clusters(self, lcn, count):
        return self.src.read(lcn * self.cluster_size, count * self.cluster_size)

    def lcn_offset(self, lcn):
        return lcn * self.cluster_size


MIRROR_RECORDS = 4  


class MftVolumeSource(MftSource):
    kind = "volume"

    def __init__(self, vol):
        self.vol = vol
        self.volume = vol
        self.record_size = vol.record_size
        self.sector_size = vol.bytes_per_sector
        self.cluster_size = vol.cluster_size
        self.read_errors = 0
        self.mirror_used = set()
        rec0, why = self._load_record0(primary=True)
        if rec0 is None:
            mrec0, mwhy = self._load_record0(primary=False)
            if mrec0 is None:
                raise MftError("$MFT record 0 at LCN %d invalid: %s; $MFTMirr copy at LCN %d also unusable: %s"
                               % (vol.mft_lcn, why, vol.mftmirr_lcn, mwhy))
            warn("$MFT record 0 at LCN %d is unusable (%s) - using the $MFTMirr copy at LCN %d. "
                 "The primary $MFT is damaged or was tampered with; run `verify` and preserve the image."
                 % (vol.mft_lcn, why, vol.mftmirr_lcn))
            self.mirror_used.add(0)
            rec0 = mrec0
        data = [a for a in rec0.attributes if a.type == ATTR_DATA and a.name == ""]
        self.runs = []
        self.mft_size = 0
        for a in data:
            self.runs.extend(a.runs)
            self.mft_size = max(self.mft_size, a.real_size)
        self._build_run_table()
        if any(a.type == ATTR_ATTRIBUTE_LIST for a in rec0.attributes):
            self._merge_attr_list(rec0)
            self._build_run_table()
        self.record_count = self.mft_size // self.record_size
        self.mft_record0 = rec0

    def _mirror_offset(self, n):
        return self.vol.mftmirr_lcn * self.vol.cluster_size + n * self.record_size

    def _load_record0(self, primary):
        lcn = self.vol.mft_lcn if primary else self.vol.mftmirr_lcn
        if not primary and (lcn == 0 or lcn == self.vol.mft_lcn):
            return None, "no separate mirror location in boot sector"
        try:
            raw = self.vol.src.read(lcn * self.vol.cluster_size, self.vol.record_size)
        except MftError as e:
            return None, str(e)
        rec = parse_record(raw, 0, self.vol.bytes_per_sector)
        if not rec.valid:
            return None, rec.error
        if rec.stored_number not in (None, 0):
            return None, "record number field says %d, not 0" % rec.stored_number
        data = [a for a in rec.attributes if a.type == ATTR_DATA and a.name == ""]
        if not data or data[0].resident or not data[0].runs:
            return None, "no non-resident $DATA attribute"
        return rec, None

    def _build_run_table(self):
        self._run_table = []
        vcn = 0
        for lcn, length in self.runs:
            self._run_table.append((vcn, lcn, length))
            vcn += length

    def _merge_attr_list(self, rec0):
        al = [a for a in rec0.attributes if a.type == ATTR_ATTRIBUTE_LIST][0]
        try:
            value = al.value if al.resident else self._read_runs_simple(al.runs, al.real_size)
            seen = set()
            for atype, name, svcn, ref, seq, aid in parse_attribute_list(value):
                if atype == ATTR_DATA and name == "" and ref != 0 and ref not in seen:
                    seen.add(ref)
                    raw = self.read_record_raw(ref)
                    ext = parse_record(raw, ref, self.sector_size)
                    for a in ext.attributes:
                        if a.type == ATTR_DATA and a.name == "":
                            self.runs.extend(a.runs)
                            self.mft_size = max(self.mft_size, a.real_size)
        except MftError as e:
            warn("Could not merge $MFT attribute list: %s" % e)

    def _read_runs_simple(self, runs, size):
        out = bytearray()
        for lcn, length in runs:
            if lcn is None:
                out += b"\x00" * (length * self.cluster_size)
            else:
                out += self.vol.read_clusters(lcn, length)
        return bytes(out[:size])

    def record_offset(self, n):
        vcn_needed, inner = divmod(n * self.record_size, self.cluster_size)
        for vcn, lcn, length in self._run_table:
            if vcn <= vcn_needed < vcn + length:
                if lcn is None:
                    raise MftError("record %d is in a sparse $MFT run" % n)
                return (lcn + (vcn_needed - vcn)) * self.cluster_size + inner
        raise MftError("record %d beyond $MFT runs" % n)

    def _read_primary(self, n):
        if self.record_size > self.cluster_size:
            
            out = bytearray()
            for i in range(self.record_size // self.cluster_size):
                vcn_needed = (n * self.record_size) // self.cluster_size + i
                for vcn, lcn, length in self._run_table:
                    if vcn <= vcn_needed < vcn + length:
                        if lcn is None:
                            raise MftError("record %d is in a sparse $MFT run" % n)
                        out += self.vol.read_clusters(lcn + (vcn_needed - vcn), 1)
                        break
                else:
                    raise MftError("record %d beyond $MFT runs" % n)
            return bytes(out)
        return self.vol.src.read(self.record_offset(n), self.record_size)

    def read_mirror_raw(self, n):
        if n >= MIRROR_RECORDS:
            raise MftError("$MFTMirr only holds records 0-%d" % (MIRROR_RECORDS - 1))
        if self.vol.mftmirr_lcn == 0:
            raise MftError("boot sector has no $MFTMirr location")
        return self.vol.src.read(self._mirror_offset(n), self.record_size)

    def read_record_raw(self, n):
        try:
            data = self._read_primary(n)
            err_txt = None if data[:4] in (b"FILE", b"BAAD") else "bad signature %r" % data[:4]
        except MftError as e:
            data, err_txt = None, str(e)
        if err_txt is None:
            return data
        if n < MIRROR_RECORDS:
            try:
                mirror = self.read_mirror_raw(n)
            except MftError:
                mirror = b""
            stored = None
            if len(mirror) >= 0x30 and struct.unpack_from("<H", mirror, 0x14)[0] >= 0x30:
                stored = struct.unpack_from("<I", mirror, 0x2C)[0]
            if mirror[:4] in (b"FILE", b"BAAD") and stored in (None, n):
                if n not in self.mirror_used:
                    warn("Record %d: primary copy unusable (%s) - using $MFTMirr copy" % (n, err_txt))
                self.mirror_used.add(n)
                return mirror
        if data is None:
            raise MftError(err_txt)
        return data   

    def verify_mirror(self):
        
        out = []
        for n in range(min(MIRROR_RECORDS, self.record_count)):
            try:
                p = self._read_primary(n)
            except MftError as e:
                out.append((n, "PRIMARY_UNREADABLE", str(e)))
                continue
            try:
                m = self.read_mirror_raw(n)
            except MftError as e:
                out.append((n, "MIRROR_UNREADABLE", str(e)))
                continue
            p_ok = p[:4] in (b"FILE", b"BAAD")
            m_ok = m[:4] in (b"FILE", b"BAAD")
            if not p_ok or not m_ok:
                out.append((n, "PRIMARY_INVALID" if not p_ok else "MIRROR_INVALID",
                            "signatures primary=%r mirror=%r" % (p[:4], m[:4])))
                continue
            if p == m:
                out.append((n, "MATCH", "byte-identical"))
                continue
            pf, _ = apply_fixup(p, self.sector_size)
            mf, _ = apply_fixup(m, self.sector_size)
            if pf == mf:
                out.append((n, "MATCH", "identical after fixup (update sequence number differs)"))
                continue
            diffs = [i for i in range(min(len(pf), len(mf))) if pf[i] != mf[i]]
            first = diffs[0] if diffs else min(len(pf), len(mf))
            out.append((n, "DIFFERENT", "%d byte(s) differ after fixup, first at +0x%X" % (len(diffs), first)))
        return out

    def iter_raw(self, start=0, end=None, hasher=None):

        end = self.record_count if end is None else min(end, self.record_count)
        n = 0
        carry = b""
        rs = self.record_size
        chunk_clusters = max(1, (4 * 1024 * 1024) // self.cluster_size)
        for lcn, length in self.runs:
            done = 0
            while done < length and n < end:
                take = min(chunk_clusters, length - done)
                if lcn is None:
                    data = b"\x00" * (take * self.cluster_size)
                else:
                    try:
                        data = self.vol.read_clusters(lcn + done, take)
                    except MftError as e:
                        self.read_errors += 1
                        warn("Read failure in $MFT at LCN %d (%d clusters): %s - records skipped" %
                             (lcn + done, take, e))
                        data = b"\x00" * (take * self.cluster_size)
                    if len(data) < take * self.cluster_size:
                        self.read_errors += 1
                        warn("Short read in $MFT at LCN %d: got %d of %d bytes (truncated image?) - zero-filled" %
                             (lcn + done, len(data), take * self.cluster_size))
                        data += b"\x00" * (take * self.cluster_size - len(data))
                done += take
                if carry:
                    data = carry + data
                    carry = b""
                full = (len(data) // rs) * rs
                pos = 0
                while pos < full and n < end:
                    rec = data[pos:pos + rs]
                    if hasher is not None:
                        hasher.update(rec)
                    if n >= start:
                        yield n, rec
                    n += 1
                    pos += rs
                carry = data[full:]
            if n >= end:
                break

    def close(self):
        self.vol.src.close()

def open_source(path, offset=None, partition=None):
    try:
        with open(path, "rb") as fh:
            head = fh.read(512)
    except PermissionError:
        raise MftError("Permission denied: %s (run as Administrator / root for raw devices)" % path)
    except FileNotFoundError:
        raise MftError("Not found: %s" % path)
    except OSError as e:
        raise MftError("Cannot open %s: %s" % (path, e))

    if head[:4] in (b"FILE", b"BAAD") and offset is None and partition is None:
        log("Input looks like a standalone $MFT file")
        return MftFileSource(path)

    src = RawSource(path, 0)
    if offset is not None:
        src.base = offset
        vol = NtfsVolume(src)
        return MftVolumeSource(vol)

    if is_ntfs_boot_sector(head):
        vol = NtfsVolume(src)
        return MftVolumeSource(vol)

    parts = find_partitions(src)
    ntfs_parts = [p for p in parts if p["ntfs"]]
    if not parts:
        raise MftError("%s is neither an NTFS volume, a partitioned disk, nor an $MFT file" % path)
    if partition is not None:
        if partition >= len(parts):
            raise MftError("Partition index %d out of range (found %d)" % (partition, len(parts)))
        p = parts[partition]
        if not p["ntfs"]:
            raise MftError("Partition %d (%s) is not NTFS" % (partition, p["type"]))
    else:
        if not ntfs_parts:
            raise MftError("No NTFS partition found in %s. Partitions: %s" %
                           (path, ", ".join("%d=%s@%d" % (p["index"], p["type"], p["start_offset"]) for p in parts)))
        p = ntfs_parts[0]
        if len(ntfs_parts) > 1:
            warn("Multiple NTFS partitions found, using #%d (%s @ %d). Use --partition to pick another: %s" %
                 (p["index"], p["type"], p["start_offset"],
                  ", ".join("#%d@%d" % (q["index"], q["start_offset"]) for q in ntfs_parts)))
    log("Using partition #%d (%s) at byte offset %d" % (p["index"], p["type"], p["start_offset"]))
    src.base = p["start_offset"]
    vol = NtfsVolume(src)
    return MftVolumeSource(vol)


class PathResolver:

    ORPHAN = "$OrphanFiles"

    def __init__(self):
        self.index = {}
        self._cache = {5: ""}

    def add(self, rec):
        fn = rec.best_file_name()
        if fn is None or rec.is_extension:
            return
        self.index[rec.number] = (fn.parent_ref, fn.parent_seq, fn.name, rec.seq, rec.in_use)

    def parent_matches(self, child_parent_ref, child_parent_seq):
        p = self.index.get(child_parent_ref)
        if p is None:
            return False
        return p[3] == child_parent_seq

    def resolve(self, number, depth=0):
        if number in self._cache:
            return self._cache[number]
        if number == MFT_REC_ROOT:
            return ""
        entry = self.index.get(number)
        if entry is None:
            return "%s/<unknown-%d>" % (self.ORPHAN, number)
        parent_ref, parent_seq, name, _seq, _inuse = entry
        path = self._join(number, parent_ref, parent_seq, name, depth)
        self._cache[number] = path
        return path

    def resolve_for(self, number, fn):
        if number == MFT_REC_ROOT:
            return ""
        return self._join(number, fn.parent_ref, fn.parent_seq, fn.name, 0)

    def _join(self, number, parent_ref, parent_seq, name, depth):
        if depth > 255 or parent_ref == number:
            return "%s/<loop>/%s" % (self.ORPHAN, name)
        if parent_ref == MFT_REC_ROOT:
            proot = self.index.get(MFT_REC_ROOT)
            if proot is not None and proot[3] != parent_seq:
                return "%s/<parent-%d-seq-mismatch>/%s" % (self.ORPHAN, parent_ref, name)
            return name
        pentry = self.index.get(parent_ref)
        if pentry is None:
            return "%s/<parent-%d-missing>/%s" % (self.ORPHAN, parent_ref, name)
        if pentry[3] != parent_seq:
            return "%s/<parent-%d-seq-mismatch>/%s" % (self.ORPHAN, parent_ref, name)
        ppath = self.resolve(parent_ref, depth + 1)
        return (ppath + "/" + name) if ppath else name

DUMP_FIELDS = [
    "record", "seq", "in_use", "is_dir", "path", "all_paths", "name", "ext", "namespace",
    "size", "alloc_size", "resident", "parent_record",
    "si_created", "si_modified", "si_mft_modified", "si_accessed",
    "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed",
    "si_flags", "fn_flags", "ads_count", "ads_names", "has_attr_list", "reparse_tag",
    "object_id", "usn", "lsn", "link_count", "base_record", "ext_records",
    "si_before_fn", "si_subsec_zero", "suspicious", "compressed", "encrypted", "sparse",
    "clusters_free", "mft_offset", "data_runs", "fixup_ok", "error",
]


def record_to_row(rec, resolver, mft, include_runs=True, bitmap=None):
    fn = rec.best_file_name()
    si = rec.std_info
    data = rec.get_data_attr("")
    size = 0
    alloc = 0
    resident = ""
    runs_txt = ""
    comp = enc = sparse = False
    if data:
        d0 = data[0]
        resident = "yes" if d0.resident else "no"
        size = d0.real_size if not d0.resident else len(d0.value)
        alloc = d0.alloc_size if not d0.resident else len(d0.value)
        if include_runs:
            allruns = []
            for d in data:
                allruns.extend(d.runs)
            runs_txt = runs_to_text(allruns)
        comp = bool(d0.flags & ATTRF_COMPRESSED)
        enc = bool(d0.flags & ATTRF_ENCRYPTED)
        sparse = bool(d0.flags & ATTRF_SPARSE)
    elif fn:
        size = fn.real_size
        alloc = fn.alloc_size
    path = resolver.resolve(rec.number) if fn else ""
    name = fn.name if fn else ""
    if rec.is_extension:
        path = "<extension-of-%d>" % rec.base_ref
    si_before_fn = False
    si_subsec_zero = False
    if si and fn:
        if si.created and fn.created and si.created < fn.created:
            si_before_fn = True
        if si.created and si.created % 10000000 == 0 and si.modified % 10000000 == 0:
            si_subsec_zero = True
    ads = rec.ads_names()
    suspicious = []
    if si_before_fn:
        suspicious.append("SI<FN")
    if si_subsec_zero:
        suspicious.append("SI_SUBSEC_ZERO")
    if ads:
        suspicious.append("ADS")
    if not rec.in_use and rec.valid and fn:
        suspicious.append("DELETED")
    if rec.error:
        suspicious.append("PARSE_ERROR")
    if rec.stored_number is not None and rec.stored_number != rec.number and rec.stored_number != 0:
        suspicious.append("RECNUM_MISMATCH")
    if not rec.fixup_ok:
        suspicious.append("FIXUP_FAIL")
    try:
        mft_off = mft.record_offset(rec.number)
    except MftError:
        mft_off = ""


    all_paths = []
    if fn and not rec.is_extension:
        long_parents = {(f.parent_ref, f.parent_seq) for f in rec.file_names if f.namespace != 2}
        ordered = [fn] + [f for f in rec.file_names if f is not fn]
        for fn_attr in ordered:
            if fn_attr.namespace == 2 and (fn_attr.parent_ref, fn_attr.parent_seq) in long_parents:
                continue
            p = resolver.resolve_for(rec.number, fn_attr)
            if p not in all_paths:
                all_paths.append(p)
    all_paths_str = "|".join(all_paths)

    clusters_free = ""
    if bitmap is not None and not rec.in_use and data and not data[0].resident:
        clusters_free = bitmap.runs_state([r for d in data for r in d.runs])

    return {
        "record": rec.number,
        "seq": rec.seq,
        "in_use": "yes" if rec.in_use else "no",
        "is_dir": "yes" if rec.is_dir else "no",
        "path": path,
        "all_paths": all_paths_str,
        "name": name,
        "ext": rec.extension(),
        "namespace": NAMESPACES.get(fn.namespace, str(fn.namespace)) if fn else "",
        "size": size,
        "alloc_size": alloc,
        "resident": resident,
        "parent_record": fn.parent_ref if fn else "",
        "si_created": filetime_to_iso(si.created) if si else "",
        "si_modified": filetime_to_iso(si.modified) if si else "",
        "si_mft_modified": filetime_to_iso(si.mft_modified) if si else "",
        "si_accessed": filetime_to_iso(si.accessed) if si else "",
        "fn_created": filetime_to_iso(fn.created) if fn else "",
        "fn_modified": filetime_to_iso(fn.modified) if fn else "",
        "fn_mft_modified": filetime_to_iso(fn.mft_modified) if fn else "",
        "fn_accessed": filetime_to_iso(fn.accessed) if fn else "",
        "si_flags": flags_to_text(si.flags) if si else "",
        "fn_flags": flags_to_text(fn.flags) if fn else "",
        "ads_count": len(ads),
        "ads_names": "|".join(ads),
        "has_attr_list": "yes" if rec.has_attr_list else "no",
        "reparse_tag": ("0x%08X(%s)" % (rec.reparse_tag, REPARSE_TAGS.get(rec.reparse_tag, "?"))) if rec.reparse_tag else "",
        "object_id": rec.object_id or "",
        "usn": si.usn if si else "",
        "lsn": rec.lsn,
        "link_count": rec.link_count,
        "base_record": rec.base_ref if rec.is_extension else "",
        "ext_records": "|".join(str(x) for x in rec.ext_records),
        "si_before_fn": "yes" if si_before_fn else "no",
        "si_subsec_zero": "yes" if si_subsec_zero else "no",
        "suspicious": "|".join(suspicious),
        "compressed": "yes" if comp else "no",
        "encrypted": "yes" if enc else "no",
        "sparse": "yes" if sparse else "no",
        "clusters_free": clusters_free,
        "mft_offset": mft_off,
        "data_runs": runs_txt,
        "fixup_ok": "yes" if rec.fixup_ok else "no",
        "error": rec.error,
    }



class VolumeBitmap:


    def __init__(self, data, total_clusters):
        self.data = data
        self.total_clusters = total_clusters

    def is_allocated(self, lcn):
        return bool(self.data[lcn >> 3] & (1 << (lcn & 7)))

    def count_allocated(self, lcn, length):
        end = lcn + length
        if lcn < 0 or end > len(self.data) * 8:
            raise IndexError(lcn)
        first, last = lcn >> 3, (end - 1) >> 3
        v = int.from_bytes(self.data[first:last + 1], "little") >> (lcn & 7)
        v &= (1 << length) - 1
        return bin(v).count("1")

    def runs_state(self, runs):
        total = allocated = 0
        for lcn, length in runs:
            if lcn is None or length <= 0:
                continue
            try:
                allocated += self.count_allocated(lcn, length)
            except IndexError:
                return "?"
            total += length
        if total == 0:
            return ""
        if allocated == 0:
            return "yes"
        if allocated == total:
            return "no"
        return "partial"


class Engine:
    def __init__(self, mft):
        self.mft = mft
        self.resolver = PathResolver()
        self.stats = {"records": 0, "valid": 0, "in_use": 0, "deleted": 0, "empty": 0, "errors": 0,
                      "dirs": 0, "ads": 0, "extensions": 0, "bad_attrlist": 0, "bad_attrlist_deleted": 0}
        self._bad_attrlist_samples = []
        self._bad_attrlist_deleted_samples = []
        self._indexed = False
        self._ext_map = {} 
        self.mft_sha256 = None
        self.mft_hash_note = "not computed"
        self._bitmap = None
        self._bitmap_loaded = False

    @property
    def mft_hash_scope(self):
        if self.mft.volume is None:
            return "entire input file (standalone $MFT)"
        return ("$MFT stream: %d records x %d bytes read through its $DATA runs "
                "(equals sha256 of `extract-mft` output; this is NOT a hash of the disk image)"
                % (self.mft.record_count, self.mft.record_size))

    def custody(self):

        d = {
            "tool": "%s %s" % (TOOL_NAME, __version__),
            "command_line": " ".join(sys.argv),
            "source": engine_source_path,
            "mft_sha256": self.mft_sha256,
            "mft_sha256_scope": self.mft_hash_scope,
        }
        if self.mft_sha256 is None:
            d["mft_sha256_note"] = self.mft_hash_note
        if getattr(self.mft, "mirror_used", None):
            d["mirror_records_used"] = sorted(self.mft.mirror_used)
        return d

    @property
    def volume_bitmap(self):
        if self._bitmap_loaded:
            return self._bitmap
        self._bitmap_loaded = True
        vol = self.mft.volume
        if vol is None:
            return None
        try:
            rec = self.get_record(MFT_REC_BITMAP, merge=True)
            fn = rec.best_file_name()
            if not rec.valid or not rec.in_use or (fn and fn.name != "$Bitmap"):
                raise MftError("record 6 is not an in-use $Bitmap (%s)" % (rec.error or (fn.name if fn else "no name")))
            parts = rec.get_data_attr("")
            if not parts:
                raise MftError("$Bitmap has no $DATA")
            data = self.read_attr_data(rec, parts)
            need = (vol.total_clusters + 7) // 8
            if len(data) < need:
                warn("$Bitmap is %d bytes but the volume has %d clusters (%d bytes needed) - "
                     "clusters beyond it are reported as '?'" % (len(data), vol.total_clusters, need))
            self._bitmap = VolumeBitmap(data, vol.total_clusters)
            dbg("$Bitmap loaded: %d bytes" % len(data))
        except MftError as e:
            warn("Cannot load volume $Bitmap - clusters_free column left empty: %s" % e)
            self._bitmap = None
        return self._bitmap

    def build_index(self, progress=True):
        if self._indexed:
            return
        t0 = time.time()
        total = self.mft.record_count
        hasher = hashlib.sha256()
        errors_before = self.mft.read_errors
        self.mft_hash_note = "index pass did not complete"
        for n, raw in self.mft.iter_raw(hasher=hasher):
            if not raw or raw[:4] not in (b"FILE", b"BAAD"):
                continue
            try:
                rec = parse_record(raw, n, self.mft.sector_size)
            except MftError as e:
                warn("Record %d: %s" % (n, e))
                continue
            if not rec.valid:
                continue
            if rec.is_extension:
                self._ext_map.setdefault(rec.base_ref, []).append(n)
            else:
                self.resolver.add(rec)
            if progress and n and n % 200000 == 0:
                log("  index pass: %d / %d records" % (n, total))
        bad = self.mft.read_errors - errors_before
        if bad:
            self.mft_sha256 = None
            self.mft_hash_note = ("%d read error(s) during the $MFT pass - unreadable data was replaced, "
                                  "so a hash would not describe the evidence and is withheld" % bad)
            warn("$MFT hash withheld: " + self.mft_hash_note)
        else:
            self.mft_sha256 = hasher.hexdigest()
            self.mft_hash_note = ""
        self._indexed = True
        dbg("index built: %d names, %d extension records in %.1fs" %
            (len(self.resolver.index), sum(len(v) for v in self._ext_map.values()), time.time() - t0))

    def _merge_extensions(self, rec):
        if rec.is_extension:
            return
        refs = {}
        al = [a for a in rec.attributes if a.type == ATTR_ATTRIBUTE_LIST]
        if al:
            try:
                a = al[0]
                value = a.value if a.resident else self.read_attr_data(rec, a)
                for atype, name, svcn, ref, seq, aid in parse_attribute_list(value):
                    if ref != rec.number and ref != 0:
                        refs.setdefault(ref, seq)
            except MftError as e:
                self._note_bad_attrlist(rec, "$ATTRIBUTE_LIST unusable: %s" % e)
        for r in self._ext_map.get(rec.number, []):
            refs.setdefault(r, None)
        for ref in sorted(refs):
            if ref >= self.mft.record_count:
                self._note_bad_attrlist(rec, "$ATTRIBUTE_LIST points outside $MFT (%d)" % ref)
                continue
            try:
                ext = parse_record(self.mft.read_record_raw(ref), ref, self.mft.sector_size)
            except MftError as e:
                warn("Record %d: extension %d unreadable: %s" % (rec.number, ref, e))
                continue
            if not ext.valid or ext.base_ref != rec.number:
                continue
            if refs[ref] is not None and ext.seq != refs[ref]:
                dbg("Record %d: extension %d sequence mismatch (%d != %d)" % (rec.number, ref, ext.seq, refs[ref]))
                continue
            rec.ext_records.append(ref)
            for a in ext.attributes:
                if a.type in (ATTR_STANDARD_INFORMATION, ATTR_ATTRIBUTE_LIST):
                    continue
                rec.attributes.append(a)
        if rec.ext_records:
            _post_process(rec)

    def get_record(self, n, merge=True):
        if n < 0 or n >= self.mft.record_count:
            raise MftError("Record %d out of range (0..%d)" % (n, self.mft.record_count - 1))
        rec = parse_record(self.mft.read_record_raw(n), n, self.mft.sector_size)
        if merge and rec.valid:
            self._merge_extensions(rec)
        return rec

    def iter_records(self, merge=True, progress=True):
        total = self.mft.record_count
        for n, raw in self.mft.iter_raw():
            self.stats["records"] += 1
            if progress and n and n % 200000 == 0:
                log("  parse pass: %d / %d records" % (n, total))
            if not raw or raw[:4] == b"\x00\x00\x00\x00":
                self.stats["empty"] += 1
                continue
            try:
                rec = parse_record(raw, n, self.mft.sector_size)
            except MftError as e:
                self.stats["errors"] += 1
                warn("Record %d: %s" % (n, e))
                continue
            if not rec.valid:
                self.stats["errors"] += 1
                continue
            self.stats["valid"] += 1
            if rec.is_extension:
                self.stats["extensions"] += 1
            elif merge:
                self._merge_extensions(rec)
            if rec.error:
                self.stats["errors"] += 1
            if rec.in_use:
                self.stats["in_use"] += 1
            else:
                self.stats["deleted"] += 1
            if rec.is_dir:
                self.stats["dirs"] += 1
            if rec.ads_names():
                self.stats["ads"] += 1
            yield rec

    def _note_bad_attrlist(self, rec, why):
        if rec.in_use:
            self.stats["bad_attrlist"] += 1
            self._bad_attrlist_samples.append(rec.number)
        else:
            self.stats["bad_attrlist_deleted"] += 1
            self._bad_attrlist_deleted_samples.append(rec.number)
        dbg("Record %d (%s): %s" % (rec.number, "in use" if rec.in_use else "deleted", why))

    def report_anomalies(self):
        n = self.stats.get("bad_attrlist", 0)
        if n:
            sample = ", ".join(str(x) for x in self._bad_attrlist_samples[:8])
            warn("%d IN-USE record(s) have an unusable $ATTRIBUTE_LIST - on a live volume this can be an "
                 "unflushed cluster, on an image it means corruption or tampering. Extension attributes were "
                 "skipped. Samples: %s%s. Inspect: record <source> N --hex -v" %
                 (n, sample, " ..." if n > 8 else ""))
        d = self.stats.get("bad_attrlist_deleted", 0)
        if d:
            sample = ", ".join(str(x) for x in self._bad_attrlist_deleted_samples[:5])
            log("%d DELETED record(s) had a non-resident $ATTRIBUTE_LIST whose cluster has since been reused "
                "by another file (expected after deletion; their names/data lived in extension records and are "
                "not recoverable from $MFT). Samples: %s%s" % (d, sample, " ..." if d > 5 else ""))

    def read_attr_data(self, rec, attr_parts, max_bytes=None, progress_cb=None, output_file=None):
        sink = output_file if output_file is not None else io.BytesIO()
        written = self._read_attr_into(rec, attr_parts, sink, max_bytes, progress_cb)
        if output_file is not None:
            return written
        return sink.getvalue()

    def _read_attr_into(self, rec, attr_parts, sink, max_bytes, progress_cb):
        if isinstance(attr_parts, Attribute):
            attr_parts = [attr_parts]
        if not attr_parts:
            raise MftError("no attribute to read")
        first = attr_parts[0]
        if first.resident:
            value = first.value if max_bytes is None else first.value[:max_bytes]
            sink.write(value)
            return len(value)
        vol = self.mft.volume
        if vol is None:
            raise MftError("Attribute is non-resident and the input is a standalone $MFT file - "
                           "the file content lives on the volume, not in $MFT. Point the tool at the "
                           "volume/image to export it.")
        real_size = first.real_size
        init_size = first.init_size
        runs = []
        for p in sorted(attr_parts, key=lambda a: a.start_vcn):
            runs.extend(p.runs)
        limit = real_size if max_bytes is None else min(real_size, max_bytes)
        if first.flags & ATTRF_COMPRESSED:
            return self._read_compressed(vol, runs, limit, first.comp_unit or 4, progress_cb, sink)
        written = 0
        cs = vol.cluster_size
        chunk_clusters = max(1, (8 * 1024 * 1024) // cs)
        for lcn, length in runs:
            if written >= limit:
                break
            remaining_clusters = length
            cur = lcn
            while remaining_clusters > 0 and written < limit:
                take = min(chunk_clusters, remaining_clusters)
                need = min(take * cs, limit - written)
                if lcn is None or written >= init_size:
                    data = b"\x00" * need
                else:
                    data = vol.read_clusters(cur, take)[:need]
                    if len(data) < need:
                        raise MftError("short read at LCN %d: got %d of %d bytes (truncated image or "
                                       "run list points past the volume end)" % (cur, len(data), need))
                    if written + len(data) > init_size:
                        keep = init_size - written
                        data = data[:keep] + b"\x00" * (len(data) - keep)
                if lcn is not None:
                    cur += take
                sink.write(data)
                written += len(data)
                remaining_clusters -= take
                if progress_cb:
                    progress_cb(written, limit)
        return written

    def _read_compressed(self, vol, runs, limit, comp_unit_exp, progress_cb, sink):
        cs = vol.cluster_size
        if not 1 <= comp_unit_exp <= 8:
            raise MftError("implausible compression unit 2^%d clusters (corrupt attribute header)" % comp_unit_exp)
        unit = 1 << comp_unit_exp
        unit_bytes = unit * cs
        def iter_units():
            buf = []
            for lcn, length in runs:
                for i in range(length):
                    buf.append(None if lcn is None else lcn + i)
                    if len(buf) == unit:
                        yield buf
                        buf = []
            if buf:
                yield buf
        written = 0
        for u, chunk in enumerate(iter_units()):
            if written >= limit:
                break
            allocated = [c for c in chunk if c is not None]
            if not allocated:
                data = b"\x00" * unit_bytes
            elif len(allocated) == unit:
                data = b"".join(vol.read_clusters(c, 1) for c in allocated)
            else:
                raw = b"".join(vol.read_clusters(c, 1) for c in allocated)
                try:
                    data = lznt1_decompress(raw, unit_bytes)
                except MftError as e:
                    raise MftError("compression unit %d: %s" % (u, e))
            data = data[:limit - written]
            sink.write(data)
            written += len(data)
            if progress_cb:
                progress_cb(written, limit)
        return written


HTML_HEAD = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>MFTDigger report - %(title)s</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--bg:#f6f7f9;--fg:#1c2128;--muted:#6b7280;--line:#d8dde3;--card:#fff;--acc:#1f5fbf;
--del:#b42318;--delbg:#fdecec;--warn:#9a6700;--warnbg:#fff4d6;--ok:#1a7f37;--okbg:#e6f6ea;--sel:#eaf1fb}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--fg:#e6e8eb;--muted:#9aa4b2;--line:#2b323b;--card:#161b22;
--acc:#6ea8ff;--del:#ff7b72;--delbg:#3a1a1a;--warn:#e3b341;--warnbg:#3a2f12;--ok:#56d364;--okbg:#12301a;--sel:#1f2a3a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:13px/1.45 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header{padding:14px 18px;border-bottom:1px solid var(--line);background:var(--card)}
h1{font-size:16px;margin:0 0 4px}.meta{color:var(--muted);font-size:12px}.meta b{color:var(--fg)}
.bar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:10px}
input[type=search]{flex:1;min-width:240px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font-size:13px}
button{padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);cursor:pointer;font-size:12px}
button.on{background:var(--acc);color:#fff;border-color:var(--acc)}
.stats{display:flex;gap:14px;font-size:12px;color:var(--muted);margin-top:8px;flex-wrap:wrap}.stats b{color:var(--fg)}
main{padding:0 18px 40px}table{width:100%%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);margin-top:14px}
th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;white-space:nowrap}
th{background:var(--bg);font-weight:600;cursor:pointer;user-select:none;position:sticky;z-index:3;font-size:12px;top:0}
th .s{color:var(--muted);font-size:10px;margin-left:3px}
td.path{white-space:normal;word-break:break-all;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;max-width:640px}
td.num{text-align:right;font-variant-numeric:tabular-nums}td.ts{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px}
tr.r{cursor:pointer}tr.r:hover{background:var(--sel)}tr.del td.path{color:var(--del);text-decoration:line-through;text-decoration-color:rgba(180,35,24,.35)}
.b{display:inline-block;padding:1px 6px;border-radius:4px;font-size:10.5px;font-weight:600;margin-right:3px;letter-spacing:.2px}
.b.del{background:var(--delbg);color:var(--del)}.b.ok{background:var(--okbg);color:var(--ok)}.b.w{background:var(--warnbg);color:var(--warn)}.b.d{background:var(--sel);color:var(--acc)}
tr.det td{background:var(--bg);white-space:normal;padding:10px 14px;font-size:12px}
.det .g{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:4px 24px}.det .k{color:var(--muted);display:inline-block;min-width:130px}
.det code{font-family:ui-monospace,Menlo,Consolas,monospace;background:var(--card);padding:2px 6px;border-radius:4px;border:1px solid var(--line);display:inline-block;margin-top:6px;word-break:break-all;white-space:normal}
.foot{color:var(--muted);font-size:11px;margin-top:14px}#more{margin-top:10px}
</style></head><body>
<header><h1>MFTDigger &mdash; %(title)s</h1>
<div class="meta">source <b>%(source)s</b> &middot; generated <b>%(generated)s</b> &middot; %(tool)s &middot; %(kind)s</div>
<div class="bar"><input id="q" type="search" placeholder="filter: path, name, indicator, extension, record number...  (regex allowed with /re/)">
<button data-f="all" class="on">All</button><button data-f="inuse">In use</button><button data-f="deleted">Deleted</button>
<button data-f="susp">Indicators</button><button data-f="ads">ADS</button><button data-f="ts">Timestomp</button><button data-f="dir">Dirs</button>
<button id="csv" title="download the currently visible rows as CSV">Export visible CSV</button></div>
<div class="stats" id="st"></div></header>
<main><table id="t"><thead><tr>
<th data-k="record">Record<span class="s"></span></th><th data-k="state">State<span class="s"></span></th>
<th data-k="path">Path<span class="s"></span></th><th data-k="size">Size<span class="s"></span></th>
<th data-k="si_created">$SI Created<span class="s"></span></th><th data-k="si_modified">$SI Modified<span class="s"></span></th>
<th data-k="fn_created">$FN Created<span class="s"></span></th><th data-k="ind">Indicators<span class="s"></span></th>
<th data-k="loc">Location<span class="s"></span></th></tr></thead><tbody id="tb"></tbody></table>
<button id="more" hidden>Show more rows</button>
<div class="foot">Timestamps are UTC. $SI = $STANDARD_INFORMATION (user-modifiable), $FN = $FILE_NAME (kernel-maintained).
Location: R = resident in MFT record; otherwise first LCN and run count. Click a row for full details and the export command.
SI_SUBSEC_ZERO (whole-second $SI) is shown but not counted as a timestomp indicator: archive extraction and many copy tools produce it.</div></main>
<script id="d" type="text/plain">
"""

HTML_TAIL = r"""</script>
<script>
var SRC=__SRC__;
(function(){
var rows=[],lines=document.getElementById('d').textContent.split('\n');
for(var i=0;i<lines.length;i++){var l=lines[i].trim();if(!l)continue;try{rows.push(JSON.parse(l))}catch(e){}}
rows.forEach(function(r,i){r._i=i;r.state=r.in_use==='yes'?'in use':'deleted';r.ind=r.suspicious||'';
r.loc=r.resident==='yes'?'R':(r.data_runs?(r.data_runs.split(';')[0].split(':')[0]+' ('+r.data_runs.split(';').length+')'):'');
r._s=(r.path+' '+r.name+' '+r.ind+' '+r.ext+' '+r.record+' '+r.ads_names+' '+r.reparse_tag).toLowerCase();});
var view=rows.slice(),sortK='record',sortD=1,filt='all',q='',PAGE=2000,shown=0;
var tb=document.getElementById('tb'),st=document.getElementById('st'),more=document.getElementById('more');
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function hs(n){n=+n||0;var u=['B','KB','MB','GB','TB'],i=0;while(n>=1024&&i<4){n/=1024;i++}return (i?n.toFixed(1):n)+' '+u[i]}
function badges(r){var o='';o+=r.in_use==='yes'?'<span class="b ok">IN USE</span>':'<span class="b del">DELETED</span>';if(r.is_dir==='yes')o+='<span class="b d">DIR</span>';return o}
function ind(r){if(!r.ind)return '';return r.ind.split('|').filter(function(x){return x&&x!=='DELETED'}).map(function(x){return '<span class="b w">'+esc(x)+'</span>'}).join('')}
function apply(){var rx=null;if(q.length>2&&q[0]==='/'&&q[q.length-1]==='/'){try{rx=new RegExp(q.slice(1,-1),'i')}catch(e){}}
view=rows.filter(function(r){
 if(filt==='inuse'&&r.in_use!=='yes')return false;if(filt==='deleted'&&r.in_use!=='no')return false;
 if(filt==='susp'&&!/SI<FN|RECNUM|FIXUP|PARSE/.test(r.ind))return false;
 if(filt==='ads'&&!(r.ads_count>0))return false;if(filt==='ts'&&r.si_before_fn!=='yes')return false;
 if(filt==='dir'&&r.is_dir!=='yes')return false;
 if(rx)return rx.test(r.path)||rx.test(r.name)||rx.test(r.ind);if(q)return r._s.indexOf(q)>=0;return true});
view.sort(function(a,b){var x=a[sortK],y=b[sortK];if(sortK==='size'||sortK==='record'){x=+x||0;y=+y||0}else{x=String(x==null?'':x).toLowerCase();y=String(y==null?'':y).toLowerCase()}return (x<y?-1:x>y?1:0)*sortD});
tb.innerHTML='';shown=0;render();
var d=rows.filter(function(r){return r.in_use==='no'}).length,s=rows.filter(function(r){return /SI<FN/.test(r.ind)}).length,a=rows.filter(function(r){return r.ads_count>0}).length;
st.innerHTML='showing <b>'+view.length+'</b> of <b>'+rows.length+'</b> rows &middot; deleted <b>'+d+'</b> &middot; timestomp indicators <b>'+s+'</b> &middot; with ADS <b>'+a+'</b>';
document.querySelectorAll('th .s').forEach(function(e){e.textContent=''});var th=document.querySelector('th[data-k="'+sortK+'"] .s');if(th)th.textContent=sortD>0?'\u25B2':'\u25BC'}
function render(){var h='',end=Math.min(view.length,shown+PAGE);for(var i=shown;i<end;i++){var r=view[i];
h+='<tr class="r'+(r.in_use==='no'?' del':'')+'" data-i="'+r._i+'"><td class="num">'+r.record+'</td><td>'+badges(r)+'</td><td class="path">'+esc(r.path||r.name||'')+'</td><td class="num" title="'+r.size+' bytes">'+hs(r.size)+'</td><td class="ts">'+esc(r.si_created)+'</td><td class="ts">'+esc(r.si_modified)+'</td><td class="ts">'+esc(r.fn_created)+'</td><td>'+ind(r)+'</td><td class="ts">'+esc(r.loc)+'</td></tr>'}
tb.insertAdjacentHTML('beforeend',h);shown=end;more.hidden=shown>=view.length;more.textContent='Show more rows ('+(view.length-shown)+' remaining)'}
function detail(r){var keys=Object.keys(r).filter(function(k){return k[0]!=='_'&&k!=='state'&&k!=='ind'&&k!=='loc'});var g='';
keys.forEach(function(k){g+='<div><span class="k">'+esc(k)+'</span> '+esc(r[k])+'</div>'});
return '<div class="det"><div class="g">'+g+'</div><code>MFTDigger.py export '+esc(SRC)+' --record '+r.record+(r.ads_count>0?' --ads':'')+' -o evidence/</code></div>'}
tb.addEventListener('click',function(e){var tr=e.target.closest('tr.r');if(!tr)return;var nx=tr.nextElementSibling;if(nx&&nx.classList.contains('det')){nx.remove();return}
var r=rows[+tr.dataset.i],d=document.createElement('tr');d.className='det';d.innerHTML='<td colspan="9">'+detail(r)+'</td>';tr.after(d)});
document.querySelectorAll('th').forEach(function(th){th.addEventListener('click',function(){var k=th.dataset.k;if(sortK===k)sortD=-sortD;else{sortK=k;sortD=1}apply()})});
document.querySelectorAll('.bar button[data-f]').forEach(function(b){b.addEventListener('click',function(){document.querySelectorAll('.bar button[data-f]').forEach(function(x){x.classList.remove('on')});b.classList.add('on');filt=b.dataset.f;apply()})});
var t;document.getElementById('q').addEventListener('input',function(e){clearTimeout(t);t=setTimeout(function(){q=e.target.value.toLowerCase().trim();apply()},150)});
more.addEventListener('click',render);
document.getElementById('csv').addEventListener('click',function(){var cols=Object.keys(rows[0]||{}).filter(function(k){return k[0]!=='_'&&k!=='state'&&k!=='ind'&&k!=='loc'});
var out=[cols.join(',')];view.forEach(function(r){out.push(cols.map(function(k){var v=String(r[k]==null?'':r[k]);return /[",\n]/.test(v)?'"'+v.replace(/"/g,'""')+'"':v}).join(','))});
var b=new Blob([out.join('\n')],{type:'text/csv'}),a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='MFTDigger_visible.csv';a.click()});
apply();})();
</script></body></html>
"""

MD_COLS = [("record", "Record"), ("state", "State"), ("path", "Path"), ("size", "Size"),
           ("si_created", "$SI Created"), ("si_modified", "$SI Modified"), ("fn_created", "$FN Created"),
           ("ads_names", "ADS"), ("suspicious", "Indicators"), ("loc", "Location")]


GRID_COLUMNS = ["record", "in_use", "is_dir", "path", "size", "si_created", "si_modified", "si_mft_modified",
                "fn_created", "ads_names", "suspicious", "clusters_free", "resident", "si_flags", "data_runs"]


def open_grid(csv_path, title, all_columns=False):
    import subprocess
    import shutil
    if os.name != "nt":
        raise MftError("--format grid needs Windows PowerShell (Out-GridView). Use --format html elsewhere.")
    cols = "*" if all_columns else ",".join(GRID_COLUMNS)
    ps = (
        "$ErrorActionPreference='Stop';"
        "$r = Import-Csv -LiteralPath '%s' -Encoding UTF8 | ForEach-Object {"
        " foreach ($c in 'record','seq','size','alloc_size','ads_count','link_count') {"
        "  if ($_.PSObject.Properties[$c] -and $_.$c -match '^-?\\d+$') { $_.$c = [int64]$_.$c } };"
        " $_ } | Select-Object %s | Out-GridView -Title '%s' -PassThru;"
        "$r | ForEach-Object { $_.record }"
    ) % (csv_path.replace("'", "''"), cols, title.replace("'", "''"))
    for exe in ("powershell.exe", "pwsh.exe"):
        if not shutil.which(exe):
            continue
        try:
            res = subprocess.run([exe, "-NoProfile", "-NonInteractive", "-Command", ps],
                                 capture_output=True, text=True)
        except OSError as e:
            warn("%s failed to start: %s" % (exe, e))
            continue
        if res.returncode != 0:
            msg = (res.stderr or "").strip().splitlines()
            if exe == "powershell.exe" or "Out-GridView" not in " ".join(msg):
                raise MftError("Out-GridView failed: %s" % (msg[-1] if msg else "unknown error"))
            continue
        return [int(x) for x in res.stdout.split() if x.strip().isdigit()]
    raise MftError("No PowerShell with Out-GridView found (Windows PowerShell 5.1 has it built in; "
                   "PowerShell 7 needs Install-Module Microsoft.PowerShell.GraphicalTools)")


class RowWriter:
    def __init__(self, fmt, out, fields=DUMP_FIELDS, title="", source="", kind="", max_rows=0):
        self.fmt = fmt
        self.out = out
        self.title = title
        self.grid_path = None
        self.selected = []
        if fmt == "grid":
            import tempfile
            fd, self.grid_path = tempfile.mkstemp(prefix="MFTDigger_grid_", suffix=".csv")
            self.out = out = io.TextIOWrapper(os.fdopen(fd, "wb"), encoding="utf-8-sig", newline="")
            fmt = "csv"
            self.fmt = "csv"
            self._is_grid = True
        else:
            self._is_grid = False
        self.fields = fields
        self.count = 0
        self.max_rows = max_rows
        self.truncated = False
        self.source = source
        if fmt == "csv":
            self.w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
            self.w.writeheader()
        elif fmt == "tsv":
            self.w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore", delimiter="\t",
                                    lineterminator="\n")
            self.w.writeheader()
        elif fmt == "html":
            out.write(HTML_HEAD % {
                "title": _html_esc(title), "source": _html_esc(source), "kind": _html_esc(kind),
                "generated": _utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
                "tool": "%s %s" % (TOOL_NAME, __version__)})
        elif fmt == "md":
            out.write("# MFTDigger report — %s\n\n" % title)
            out.write("- Source: `%s` (%s)\n- Generated: %s UTC\n- Tool: %s %s\n\n" % (
                source, kind, _utcnow().strftime("%Y-%m-%d %H:%M:%S"), TOOL_NAME, __version__))
            out.write("| " + " | ".join(h for _, h in MD_COLS) + " |\n")
            out.write("|" + "|".join("---:" if k in ("record", "size") else "---" for k, _ in MD_COLS) + "|\n")

    def write(self, row):
        self.count += 1
        if self.max_rows and self.count > self.max_rows:
            self.truncated = True
            return
        if self.fmt in ("csv", "tsv"):
            self.w.writerow(row)
        elif self.fmt == "jsonl":
            self.out.write(json.dumps({k: row.get(k) for k in self.fields}, ensure_ascii=False) + "\n")
        elif self.fmt == "body":
            self._body(row)
        elif self.fmt == "html":
            s = json.dumps({k: row.get(k) for k in self.fields}, ensure_ascii=False)
            self.out.write(s.replace("</", "<\\/") + "\n")
        elif self.fmt == "md":
            self._md(row)

    def close(self):
        if self._is_grid:
            self.out.close()
            log("Grid data: %s (%d rows) - opening Out-GridView, close the window when done" %
                (self.grid_path, self.count))
            self.selected = open_grid(self.grid_path, "MFTDigger - %s (%d rows)" % (self.title, self.count),
                                      all_columns=_GRID_ALL)
            if self.selected:
                recs = ",".join(str(r) for r in self.selected)
                log("Selected %d record(s): %s" % (len(self.selected), recs))
                sys.stderr.write("    export: %s export %s --record %s --include-deleted -o evidence/\n" %
                                 (os.path.basename(sys.argv[0]), _quote(engine_source_path or "<source>"), recs))
            return
        if self.fmt == "html":
            self.out.write(HTML_TAIL.replace("__SRC__", json.dumps(self.source).replace("</", "<\\/")))
        elif self.fmt == "md":
            self.out.write("\n_%d row(s)%s. Timestamps UTC. Location: R = resident, else first LCN (run count)._\n" % (
                min(self.count, self.max_rows) if self.max_rows else self.count,
                ", truncated at --max-rows" if self.truncated else ""))
        if self.truncated:
            warn("%s output truncated at %d rows (--max-rows); %d matching rows were not written" %
                 (self.fmt, self.max_rows, self.count - self.max_rows))

    def _md(self, row):
        r = dict(row)
        r["state"] = ("DIR " if row["is_dir"] == "yes" else "") + ("in use" if row["in_use"] == "yes" else "**DELETED**")
        r["size"] = human_size(row["size"])
        runs = row.get("data_runs") or ""
        r["loc"] = "R" if row["resident"] == "yes" else (("%s (%d)" % (runs.split(";")[0].split(":")[0], len(runs.split(";")))) if runs else "")
        cells = []
        for k, _ in MD_COLS:
            v = str(r.get(k, "") or "")
            v = v.replace("|", "\\|").replace("\n", " ")
            if k == "path":
                v = "`%s`" % v if v else ""
            cells.append(v)
        self.out.write("| " + " | ".join(cells) + " |\n")

    def _body(self, row):
        path = "/" + row["path"] if row["path"] else "/"
        if row["in_use"] == "no":
            path += " (deleted)"
        mode = "d/drwxrwxrwx" if row["is_dir"] == "yes" else "r/rrwxrwxrwx"
        inode = "%s-128-%s" % (row["record"], row["seq"])

        def ep(iso):
            if not iso or iso.startswith("INVALID") or iso.startswith("1601"):
                return 0
            try:
                d = _dt.datetime.strptime(iso[:19], "%Y-%m-%dT%H:%M:%S")
                return int((d - _dt.datetime(1970, 1, 1)).total_seconds())
            except ValueError:
                return 0
        self.out.write("0|%s|%s|%s|0|0|%s|%d|%d|%d|%d\n" % (
            path, inode, mode, row["size"], ep(row["si_accessed"]), ep(row["si_modified"]),
            ep(row["si_mft_modified"]), ep(row["si_created"])))
        if row["fn_created"]:
            self.out.write("0|%s ($FILE_NAME)|%s|%s|0|0|%s|%d|%d|%d|%d\n" % (
                path, inode, mode, row["size"], ep(row["fn_accessed"]), ep(row["fn_modified"]),
                ep(row["fn_mft_modified"]), ep(row["fn_created"])))


def _html_esc(s):
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def open_output(path):
    if not path or path == "-":
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline=""), True



def _iter_dump_file(path):
    ints = ("record", "seq", "size", "alloc_size", "ads_count", "link_count")
    with open(path, "r", encoding="utf-8", newline="") as fh:
        head = fh.read(4096)
        fh.seek(0)
        if head.lstrip().startswith("{"):
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)
        else:
            delim = "\t" if "\t" in head.splitlines()[0] else ","
            for row in csv.DictReader(fh, delimiter=delim):
                for k in ints:
                    v = row.get(k, "")
                    row[k] = int(v) if str(v).strip().lstrip("-").isdigit() else 0
                yield row


def cmd_report(args):
    pred = _row_filter_from_args(args)
    out, close = open_output(args.output)
    title = "report from %s: %s" % (os.path.basename(args.input), " ".join(_criteria_text(args)))
    writer = RowWriter(args.format, out, title=title, source=args.input, kind="dump-file",
                       max_rows=_max_rows(args))
    n = 0
    try:
        for row in _iter_dump_file(args.input):
            if pred(row):
                writer.write(row)
                n += 1
                if args.limit and n >= args.limit:
                    break
        writer.close()
    finally:
        if close:
            out.close()
    log("Report: %d row(s) -> %s" % (n, os.path.abspath(args.output) if args.output != "-" else "stdout"))
    _maybe_open(args)
    return 0 if n else 2


def cmd_info(args, engine):
    mft = engine.mft
    print("%s v%s  |  %s %s  |  Python %s" % (TOOL_NAME, __version__, platform.system(),
                                              platform.release(), platform.python_version()))
    print("Input          : %s" % args.source)
    print("Input kind     : %s" % mft.kind)
    if mft.volume:
        v = mft.volume
        print("Partition off. : %d bytes" % v.src.base)
        print("Bytes/sector   : %d" % v.bytes_per_sector)
        print("Cluster size   : %d bytes (%d sectors)" % (v.cluster_size, v.sectors_per_cluster))
        print("Volume size    : %s (%d sectors)" % (human_size(v.volume_size), v.total_sectors))
        print("Serial number  : %016X" % v.serial)
        print("$MFT LCN       : %d  (byte offset %d)" % (v.mft_lcn, v.lcn_offset(v.mft_lcn)))
        print("$MFTMirr LCN   : %d%s" % (v.mftmirr_lcn, "  (USED as fallback for record(s) %s - primary damaged!)" %
                                            ",".join(map(str, sorted(mft.mirror_used))) if mft.mirror_used else ""))
        print("$MFT size      : %s (%d records of %d bytes)" % (human_size(mft.mft_size), mft.record_count, mft.record_size))
        print("$MFT runs      : %d fragment(s): %s" % (len(mft.runs), runs_to_text(mft.runs)[:200]))
        try:
            vrec = engine.get_record(MFT_REC_VOLUME)
            for a in vrec.attributes:
                if a.type == ATTR_VOLUME_NAME:
                    print("Volume label   : %s" % a.value.decode("utf-16le", "replace"))
                if a.type == ATTR_VOLUME_INFORMATION and len(a.value) >= 12:
                    maj, mn, fl = struct.unpack_from("<BBH", a.value, 8)
                    print("NTFS version   : %d.%d  flags=0x%04X%s" % (maj, mn, fl, "  (DIRTY)" if fl & 1 else ""))
        except MftError as e:
            warn("Cannot read $Volume record: %s" % e)
        if args.partitions:
            parts = find_partitions(RawSource(args.source, 0))
            if parts:
                print("\nPartition table:")
                for p in parts:
                    print("  #%d  %-24s start=%-14d size=%-12s %s" % (
                        p["index"], p["type"], p["start_offset"], human_size(p["length"]),
                        "NTFS" if p["ntfs"] else ""))
    else:
        print("$MFT file size : %s" % human_size(mft.size))
        print("Record size    : %d" % mft.record_size)
        print("Record count   : %d" % mft.record_count)
        print("NOTE           : standalone $MFT - non-resident file content cannot be exported")
    if args.stats:
        log("Counting records (full pass)...")
        engine.build_index()
        for _ in engine.iter_records(merge=False):
            pass
        s = engine.stats
        print("\nRecord statistics:")
        print("  total slots    : %d" % s["records"])
        print("  valid records  : %d" % s["valid"])
        print("  in use         : %d" % s["in_use"])
        print("  deleted/free   : %d" % s["deleted"])
        print("  never used     : %d" % s["empty"])
        print("  directories    : %d" % s["dirs"])
        print("  extension recs : %d" % s["extensions"])
        print("  with ADS       : %d" % s["ads"])
        print("  parse errors   : %d" % s["errors"])
        print("  bad attr lists : %d in use (investigate), %d deleted (cluster reused - expected)" %
              (s["bad_attrlist"], s["bad_attrlist_deleted"]))
        print("  $MFT sha256    : %s" % (engine.mft_sha256 or "withheld - %s" % engine.mft_hash_note))
        print("  hash scope     : %s" % engine.mft_hash_scope)
        engine.report_anomalies()
    return 0


def _row_filter_from_args(args):
    checks = []
    if getattr(args, "in_use_only", False):
        checks.append(lambda r: r["in_use"] == "yes")
    if getattr(args, "deleted_only", False):
        checks.append(lambda r: r["in_use"] == "no" and r["name"])
    if getattr(args, "dirs_only", False):
        checks.append(lambda r: r["is_dir"] == "yes")
    if getattr(args, "files_only", False):
        checks.append(lambda r: r["is_dir"] == "no")
    if getattr(args, "ads_only", False):
        checks.append(lambda r: r["ads_count"] > 0)
    subsec = getattr(args, "include_subsec", False)
    if getattr(args, "suspicious", False):
        checks.append(lambda r: "SI<FN" in r["suspicious"] or (subsec and "SI_SUBSEC_ZERO" in r["suspicious"])
                      or "RECNUM_MISMATCH" in r["suspicious"] or "FIXUP_FAIL" in r["suspicious"])
    if getattr(args, "timestomp", False):
        checks.append(lambda r: r["si_before_fn"] == "yes" or (subsec and r["si_subsec_zero"] == "yes"))
    if getattr(args, "ext", None):
        exts = {e.lower().lstrip(".") for e in args.ext.split(",")}
        checks.append(lambda r: r["ext"] in exts)
    if getattr(args, "min_size", None) is not None:
        checks.append(lambda r: r["size"] >= args.min_size)
    if getattr(args, "max_size", None) is not None:
        checks.append(lambda r: r["size"] <= args.max_size)
    if getattr(args, "name", None):
        pats = [p.lower() for p in args.name]
        checks.append(lambda r: any(fnmatch.fnmatchcase(r["name"].lower(), p) for p in pats))
    if getattr(args, "path", None):
        needles = [p.lower().replace("\\", "/").strip("/") for p in args.path]
        checks.append(lambda r: any(nd in r["path"].lower() or nd in (r.get("all_paths") or "").lower()
                                    for nd in needles))
    if getattr(args, "regex", None):
        try:
            rx = re.compile(args.regex, re.IGNORECASE)
        except re.error as e:
            raise MftError("Bad regex: %s" % e)
        checks.append(lambda r: bool(rx.search(r["path"]) or rx.search(r["name"])))
    if getattr(args, "record", None):
        wanted = set()
        for tok in args.record:
            for part in tok.split(","):
                part = part.strip()
                if "-" in part:
                    a, b = part.split("-", 1)
                    wanted.update(range(int(a), int(b) + 1))
                elif part:
                    wanted.add(int(part))
        checks.append(lambda r: r["record"] in wanted)
    ts_field = getattr(args, "time_field", "any")
    after = getattr(args, "after", None)
    before = getattr(args, "before", None)
    if after or before:
        a_iso = filetime_to_iso(after) if after else None
        b_iso = filetime_to_iso(before) if before else None
        if ts_field == "any":
            fields = ["si_created", "si_modified", "si_mft_modified", "si_accessed",
                      "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed"]
        else:
            fields = [ts_field]

        def in_window(r):
            for f in fields:
                v = r.get(f)
                if not v or v.startswith("INVALID"):
                    continue
                if a_iso and v < a_iso:
                    continue
                if b_iso and v > b_iso:
                    continue
                return True
            return False
        checks.append(in_window)

    def pred(row):
        return all(c(row) for c in checks)
    return pred


def cmd_dump(args, engine):
    out, close = open_output(args.output)
    pred = _row_filter_from_args(args)
    engine.build_index()
    bitmap = engine.volume_bitmap
    writer = RowWriter(args.format, out, title="MFT dump", source=args.source, kind=engine.mft.kind,
                       max_rows=_max_rows(args))
    t0 = time.time()
    try:
        for rec in engine.iter_records(merge=not args.no_merge):
            if rec.is_extension and not args.include_extension:
                continue
            row = record_to_row(rec, engine.resolver, engine.mft, include_runs=not args.no_runs, bitmap=bitmap)
            if pred(row):
                writer.write(row)
        writer.close()
    finally:
        if close:
            out.close()
    engine.report_anomalies()
    s = engine.stats
    log("Dump complete: %d rows written (%d slots, %d valid, %d in use, %d deleted, %d errors) in %.1fs" %
        (writer.count, s["records"], s["valid"], s["in_use"], s["deleted"], s["errors"], time.time() - t0))
    _write_output_manifest(args, engine, min(writer.count, writer.max_rows) if writer.max_rows else writer.count,
                           writer.truncated)
    if args.output and args.output != "-":
        log("Output: %s" % os.path.abspath(args.output))
        _maybe_open(args)
    return 0


def _write_output_manifest(args, engine, rows, truncated=False):
    out = getattr(args, "output", "-")
    if not out or out == "-" or getattr(args, "format", "") == "grid":
        if engine.mft_sha256:
            log("$MFT sha256: %s" % engine.mft_sha256)
        return
    m = engine.custody()
    m.update({
        "generated_at": _utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "command": args.cmd, "output_file": os.path.basename(out), "format": args.format,
        "rows_written": rows,
        "truncated": truncated,
        "criteria": _criteria_text(args),
        "stats": dict(engine.stats),
    })
    try:
        h = hashlib.sha256()
        with open(out, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        m["output_sha256"] = h.hexdigest()
    except OSError as e:
        m["output_sha256"] = None
        warn("could not hash output file: %s" % e)
    path = out + ".manifest.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(m, fh, indent=2, ensure_ascii=False)
    log("Manifest: %s ($MFT sha256 %s)" % (os.path.abspath(path), engine.mft_sha256 or "withheld"))


def _maybe_open(args):
    if getattr(args, "open", False) and args.format == "html" and args.output not in (None, "-"):
        try:
            import webbrowser
            webbrowser.open("file:///" + os.path.abspath(args.output).replace("\\", "/"))
        except Exception as e:
            warn("could not open browser: %s" % e)


def _print_location(row, rec, engine):
    mft = engine.mft
    vol = mft.volume
    lines = []
    lines.append("=" * 78)
    state = "IN USE" if rec.in_use else "DELETED"
    kind = "DIR " if rec.is_dir else "FILE"
    lines.append("[%s] %s  record %d (seq %d)  %s" % (kind, state, rec.number, rec.seq, row["path"] or "<root>"))
    lines.append("  size %s (%d bytes, alloc %d)   resident=%s   flags: %s" %
                 (human_size(row["size"]), row["size"], row["alloc_size"], row["resident"] or "n/a", row["si_flags"] or "-"))
    lines.append("  $SI  C:%s  M:%s  E:%s  A:%s" % (row["si_created"], row["si_modified"], row["si_mft_modified"], row["si_accessed"]))
    lines.append("  $FN  C:%s  M:%s  E:%s  A:%s" % (row["fn_created"], row["fn_modified"], row["fn_mft_modified"], row["fn_accessed"]))
    if len(rec.file_names) > 1:
        lines.append("  names: %s" % ", ".join("%s(%s)" % (f.name, NAMESPACES.get(f.namespace, "?")) for f in rec.file_names))
    if row.get("all_paths") and "|" in row["all_paths"]:
        lines.append("  hard links: %s" % row["all_paths"].replace("|", "  |  "))
    if row.get("clusters_free"):
        lines.append("  $Bitmap: clusters still free = %s%s" % (row["clusters_free"], {
            "yes": "  (content probably intact)", "no": "  (all reallocated - content belongs to another file)",
            "partial": "  (partly overwritten)", "?": "  (outside $Bitmap)"}.get(row["clusters_free"], "")))
    lines.append("  MFT record offset: %s%s" % (
        row["mft_offset"], "" if vol is None else "  (physical: %d)" % (row["mft_offset"] + vol.src.base) if row["mft_offset"] != "" else ""))
    data = rec.get_data_attr("")
    if data:
        d0 = data[0]
        if d0.resident:
            lines.append("  $DATA: RESIDENT inside MFT record at +%d (%d bytes)" % (d0.value_offset, len(d0.value)))
        else:
            allruns = []
            for d in data:
                allruns.extend(d.runs)
            lines.append("  $DATA: NON-RESIDENT, %d run(s)%s%s" % (
                len(allruns), ", COMPRESSED" if d0.flags & ATTRF_COMPRESSED else "",
                ", ENCRYPTED(EFS)" if d0.flags & ATTRF_ENCRYPTED else ""))
            for i, (lcn, length) in enumerate(allruns[:args_max_runs]):
                if lcn is None:
                    lines.append("    run %d: SPARSE %d cluster(s)" % (i, length))
                elif vol:
                    off = vol.lcn_offset(lcn)
                    lines.append("    run %d: LCN %d  x%d cluster(s)  -> volume offset %d (0x%X), physical %d, %d bytes" %
                                 (i, lcn, length, off, off, off + vol.src.base, length * vol.cluster_size))
                else:
                    lines.append("    run %d: LCN %d  x%d cluster(s)" % (i, lcn, length))
            if len(allruns) > args_max_runs:
                lines.append("    ... %d more run(s)" % (len(allruns) - args_max_runs))
    ads = rec.ads_names()
    if ads:
        for name in ads:
            parts = rec.get_data_attr(name)
            p0 = parts[0]
            lines.append("  ADS ':%s'  %s  %d bytes" % (name, "resident" if p0.resident else "non-resident", p0.size))
    if row["reparse_tag"]:
        lines.append("  reparse: %s" % row["reparse_tag"])
    if rec.ext_records:
        lines.append("  extension records: %s" % ", ".join(str(x) for x in rec.ext_records))
    if row["suspicious"]:
        lines.append("  ! indicators: %s" % row["suspicious"])
    if rec.error:
        lines.append("  ! parse error: %s" % rec.error)
    lines.append("  export: %s export %s --record %d -o <dir>" % (
        os.path.basename(sys.argv[0]), _quote(engine_source_path), rec.number))
    return "\n".join(lines)


args_max_runs = 8
engine_source_path = ""
_GRID_ALL = False


def _quote(s):
    return '"%s"' % s if " " in s else s


def _max_rows(args):
    mr = getattr(args, "max_rows", None)
    if mr is None:
        return 100000 if args.format in ("html", "md") else 0
    return mr


def _criteria_text(args):
    parts = []
    for k in ("name", "path", "regex", "record", "ext", "after", "before", "min_size", "max_size"):
        v = getattr(args, k, None)
        if v is None or v is False or v == []:
            continue
        if k in ("after", "before"):
            v = filetime_to_iso(v)[:19]
        parts.append("--%s %s" % (k.replace("_", "-"), " ".join(v) if isinstance(v, list) else v))
    for k in ("deleted_only", "in_use_only", "dirs_only", "files_only", "ads_only", "timestomp", "suspicious",
              "include_subsec"):
        if getattr(args, k, False):
            parts.append("--" + k.replace("_", "-"))
    return parts or ["(all records)"]


def cmd_search(args, engine):
    if not any([args.name, args.path, args.regex, args.record, args.ext, args.deleted_only, args.ads_only,
                args.suspicious, args.timestomp, args.after, args.before, args.min_size is not None,
                args.max_size is not None]):
        raise MftError("search needs at least one criterion (--name/--path/--regex/--record/--ext/"
                       "--deleted-only/--ads-only/--timestomp/--after/--before/--min-size/--max-size)")
    pred = _row_filter_from_args(args)
    engine.build_index()
    bitmap = engine.volume_bitmap
    out, close = open_output(args.output)
    title = "search: " + " ".join(_criteria_text(args))
    writer = (RowWriter(args.format, out, title=title, source=args.source, kind=engine.mft.kind,
                        max_rows=_max_rows(args)) if args.format != "text" else None)
    hits = 0
    t0 = time.time()
    try:
        for rec in engine.iter_records(merge=not args.no_merge):
            if rec.is_extension:
                continue
            row = record_to_row(rec, engine.resolver, engine.mft, bitmap=bitmap)
            if not pred(row):
                continue
            hits += 1
            if writer:
                writer.write(row)
            else:
                out.write(_print_location(row, rec, engine) + "\n")
            if args.limit and hits >= args.limit:
                log("Limit of %d hits reached" % args.limit)
                break
        if writer:
            writer.close()
    finally:
        if close:
            out.close()
    engine.report_anomalies()
    log("Search finished: %d hit(s) in %.1fs" % (hits, time.time() - t0))
    if writer:
        _write_output_manifest(args, engine, min(writer.count, writer.max_rows) if writer.max_rows else writer.count,
                               writer.truncated)
    else:
        _write_output_manifest(args, engine, hits)
    if args.output and args.output != "-":
        log("Output: %s" % os.path.abspath(args.output))
        _maybe_open(args)
    return 0 if hits else 2


def _safe_name(name):
    bad = '<>:"/\\|?*\x00'
    s = "".join("_" if c in bad or ord(c) < 32 else c for c in name)
    return s.strip(" .") or "unnamed"


def _find_export_targets(args, engine):
    targets = []
    if args.record:
        for tok in args.record:
            for part in tok.split(","):
                part = part.strip()
                if part:
                    targets.append(int(part))
        return targets
    engine.build_index()
    want_path = [p.lower().replace("\\", "/").strip("/") for p in (args.path or [])]
    want_path = [re.sub(r"^[a-z]:/", "", p) for p in want_path]
    want_name = [p.lower() for p in (args.name or [])]
    for rec in engine.iter_records(merge=False, progress=True):
        if rec.is_extension or not rec.file_names:
            continue
        if not args.include_deleted and not rec.in_use:
            continue
        p = engine.resolver.resolve(rec.number).lower()
        nm = rec.best_file_name().name.lower()
        if want_path and p in want_path:
            targets.append(rec.number)
        elif want_name and any(fnmatch.fnmatchcase(nm, w) for w in want_name):
            targets.append(rec.number)
    return targets


EXPORT_OK_STATUSES = ("ok", "directory")


class _HashingWriter:

    def __init__(self, fh):
        self.fh = fh
        self.n = 0
        self.head = b""
        self.sha256 = hashlib.sha256()
        self.sha1 = hashlib.sha1()
        self.md5 = hashlib.md5()

    def write(self, b):
        self.fh.write(b)
        self.n += len(b)
        if len(self.head) < 8:
            self.head += b[:8 - len(self.head)]
        self.sha256.update(b)
        self.sha1.update(b)
        self.md5.update(b)
        return len(b)


def cmd_export(args, engine):
    if not (args.record or args.path or args.name):
        raise MftError("export needs --record N, --path 'Dir/file.ext' or --name 'pattern'")
    os.makedirs(args.out, exist_ok=True)
    engine.build_index()
    targets = _find_export_targets(args, engine)
    if not targets:
        err("No matching record found")
        return 2
    if len(targets) > args.max_files:
        raise MftError("%d matches exceed --max-files %d; narrow the criteria" % (len(targets), args.max_files))
    log("Exporting %d record(s) to %s" % (len(targets), os.path.abspath(args.out)))
    manifest_path = os.path.join(args.out, "export_manifest.jsonl")
    ok = 0
    failed = []
    with open(manifest_path, "a", encoding="utf-8") as manifest:
        for n in targets:
            try:
                res = _export_one(args, engine, n)
            except (MftError, OverflowError, ValueError, struct.error, IndexError) as e:
                err("Record %d: %s" % (n, e))
                res = dict(engine.custody(), record=n, status="error", error=str(e),
                           exported_at=_utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"))
            manifest.write(json.dumps(res, ensure_ascii=False) + "\n")
            if res.get("status") in EXPORT_OK_STATUSES:
                ok += 1
            else:
                failed.append("%d(%s)" % (n, res.get("status")))
    if failed:
        err("Export: %d/%d record(s) NOT exported completely: %s - see warnings in %s" %
            (len(failed), len(targets), ", ".join(failed[:20]) + (" ..." if len(failed) > 20 else ""),
             manifest_path))
    log("Export done: %d/%d succeeded. Manifest: %s" % (ok, len(targets), manifest_path))
    return 0 if ok == len(targets) else 1


def _export_one(args, engine, n):
    rec = engine.get_record(n, merge=True)
    if not rec.valid:
        raise MftError("record invalid: %s" % rec.error)
    row = record_to_row(rec, engine.resolver, engine.mft, bitmap=engine.volume_bitmap)
    fn = rec.best_file_name()
    base_name = _safe_name(fn.name) if fn else "record_%d" % n
    stem = "%06d_%s" % (n, base_name)
    result = engine.custody()
    result.update({
        "exported_at": _utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "record": n, "seq": rec.seq, "path": row["path"], "all_paths": row["all_paths"], "name": row["name"],
        "in_use": rec.in_use, "is_dir": rec.is_dir, "status": "ok", "warnings": [],
        "streams": [],
        "mft_record_offset": row["mft_offset"],
        "timestamps": {k: row[k] for k in ("si_created", "si_modified", "si_mft_modified", "si_accessed",
                                            "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed")},
        "flags": row["si_flags"], "indicators": row["suspicious"],
    })
    if n in getattr(engine.mft, "mirror_used", ()):
        msg = "primary MFT record unusable - this record was read from $MFTMirr"
        result["warnings"].append(msg)
        warn("Record %d: %s" % (n, msg))
    if not rec.in_use:
        cf = row["clusters_free"]
        result["clusters_free"] = cf
        if cf == "yes":
            msg = ("record is DELETED; $Bitmap shows all its clusters still FREE - content is probably intact, "
                   "verify with file signature / hash")
        elif cf == "no":
            msg = ("record is DELETED and $Bitmap shows ALL its clusters REALLOCATED - the exported bytes "
                   "belong to whatever file reused them, not to this one")
        elif cf == "partial":
            msg = ("record is DELETED and $Bitmap shows SOME of its clusters reallocated - content is "
                   "partly overwritten")
        else:
            msg = ("record is DELETED - clusters may have been reused; content is best-effort carving, "
                   "verify with file signature / hash")
        result["warnings"].append(msg)
        warn("Record %d: %s" % (n, msg))

    if not args.no_raw_record:
        rr_path = os.path.join(args.out, stem + ".mftrecord.bin")
        with open(rr_path, "wb") as fh:
            fh.write(rec.raw)
        result["raw_record_file"] = os.path.basename(rr_path)
        result["raw_record_sha256"] = hashlib.sha256(rec.raw).hexdigest()

    if rec.is_dir and not rec.ads_names() and not args.stream:
        result["status"] = "directory"
        result["warnings"].append("directory record: no $DATA stream (index attributes only); raw record saved")
        _write_sidecar(args, stem, result)
        log("Record %d is a directory - metadata + raw record saved" % n)
        return result

    streams = []
    if args.stream is not None:
        streams = [args.stream]
    else:
        streams = [""] + (rec.ads_names() if args.ads else [])
    incomplete = False
    for sname in streams:
        parts = rec.get_data_attr(sname)
        if not parts:
            msg = "stream '%s' not found in record" % (sname or "$DATA")
            result["warnings"].append(msg)
            warn("Record %d: %s (available: %s)" % (n, msg, ", ".join(["<default>"] + rec.ads_names())))
            incomplete = True
            continue
        p0 = parts[0]
        out_name = stem if sname == "" else "%s__ADS_%s" % (stem, _safe_name(sname))
        out_path = os.path.join(args.out, out_name)
        size = p0.size
        if args.max_size and size > args.max_size:
            result["warnings"].append("stream '%s' (%d bytes) exceeds --max-size; skipped" % (sname, size))
            warn("Record %d: stream %s is %s > --max-size; skipped" % (n, sname or "$DATA", human_size(size)))
            incomplete = True
            continue
        if not p0.resident and engine.mft.volume is None:
            msg = ("stream '%s' is non-resident: its content lives on the volume, not in a standalone $MFT - "
                   "point the tool at the volume/image to export it" % (sname or "$DATA"))
            result["warnings"].append(msg)
            err("Record %d: %s" % (n, msg))
            incomplete = True
            continue
        if p0.flags & ATTRF_ENCRYPTED:
            result["warnings"].append("stream '%s' is EFS-encrypted; raw ciphertext exported" % sname)
            warn("Record %d: EFS encrypted - exporting ciphertext only" % n)
        if sname == "" and rec.reparse_tag in (0x80000017, 0x80000014):
            what = "WOF/Compact OS" if rec.reparse_tag == 0x80000017 else "Data Deduplication"
            msg = ("$DATA is a %s placeholder (reparse tag 0x%08X): the real content is NOT in this stream "
                   "and is not decoded by this version - the exported bytes are not the file content"
                   % (what, rec.reparse_tag))
            result["warnings"].append(msg)
            warn("Record %d: %s" % (n, msg))
            incomplete = True
        last = [0]

        def progress(done, total):
            if total > 32 * 1024 * 1024 and done - last[0] >= 64 * 1024 * 1024:
                last[0] = done
                log("  %s: %s / %s" % (out_name, human_size(done), human_size(total)))
        t0 = time.time()
        read_error = None
        with open(out_path, "wb") as fh:
            hw = _HashingWriter(fh)
            try:
                engine.read_attr_data(rec, parts, progress_cb=progress, output_file=hw)
            except MftError as e:
                read_error = str(e)
        if read_error:
            partial = out_path + ".partial"
            os.replace(out_path, partial)
            out_path = partial
        allruns = []
        for p in parts:
            allruns.extend(p.runs)
        streaminfo = {
            "stream": sname or "$DATA", "file": os.path.basename(out_path), "bytes": hw.n,
            "declared_size": size, "complete": read_error is None and hw.n == size, "resident": p0.resident,
            "compressed": bool(p0.flags & ATTRF_COMPRESSED), "sparse": bool(p0.flags & ATTRF_SPARSE),
            "encrypted": bool(p0.flags & ATTRF_ENCRYPTED),
            "data_runs": runs_to_text(allruns), "sha256": hw.sha256.hexdigest(), "sha1": hw.sha1.hexdigest(),
            "md5": hw.md5.hexdigest(), "magic": hw.head.hex(), "seconds": round(time.time() - t0, 2),
        }
        if read_error:
            streaminfo["error"] = read_error
            result["warnings"].append("stream '%s': read failed after %d bytes: %s (partial data kept as %s)" %
                                      (sname or "$DATA", hw.n, read_error, os.path.basename(out_path)))
            err("Record %d: stream %s INCOMPLETE - %s" % (n, sname or "$DATA", read_error))
            incomplete = True
        elif hw.n != size:
            streaminfo["warning"] = "read %d bytes but declared size is %d" % (hw.n, size)
            result["warnings"].append(streaminfo["warning"])
            err("Record %d: stream %s INCOMPLETE - %s" % (n, sname or "$DATA", streaminfo["warning"]))
            incomplete = True
        result["streams"].append(streaminfo)
        log("Record %d -> %s  (%s, sha256 %s)%s" % (n, out_path, human_size(hw.n), streaminfo["sha256"],
                                                    "" if streaminfo["complete"] else "  [INCOMPLETE]"))
    if not result["streams"]:
        result["status"] = "no-data"
    elif incomplete:
        result["status"] = "incomplete"
    elif not rec.in_use and result.get("clusters_free") == "no":
        result["status"] = "reallocated"            
    elif not rec.in_use and result.get("clusters_free") == "partial":
        result["status"] = "partially-reallocated"
    if args.preserve_times and result["streams"]:
        try:
            si = rec.std_info
            if si:
                mt = filetime_to_epoch(si.modified)
                at = filetime_to_epoch(si.accessed)
                for s in result["streams"]:
                    os.utime(os.path.join(args.out, s["file"]), (at, mt))
        except OSError as e:
            result["warnings"].append("could not set timestamps: %s" % e)
    _write_sidecar(args, stem, result)
    return result


def _write_sidecar(args, stem, result):
    side = os.path.join(args.out, stem + ".meta.json")
    with open(side, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
    result["sidecar"] = os.path.basename(side)


def cmd_extract_mft(args, engine):
    mft = engine.mft
    if mft.volume is None:
        raise MftError("input is already a standalone $MFT file")
    out_path = args.output
    log("Copying $MFT (%s) to %s" % (human_size(mft.mft_size), out_path))
    h = hashlib.sha256()
    written = 0
    errors_before = mft.read_errors
    with open(out_path, "wb") as fh:
        for n, raw in mft.iter_raw():
            fh.write(raw)
            h.update(raw)
            written += len(raw)
    bad = mft.read_errors - errors_before
    if bad:
        err("%d read error(s) while copying $MFT - unreadable parts were zero-filled. The copy is NOT a "
            "faithful image of the on-disk $MFT; no .sha256 file written." % bad)
        return 1
    log("Wrote %d bytes, sha256 %s" % (written, h.hexdigest()))
    with open(out_path + ".sha256", "w") as fh:
        fh.write("%s  %s\n" % (h.hexdigest(), os.path.basename(out_path)))
    return 0


def cmd_record(args, engine):
    engine.build_index()
    rec = engine.get_record(args.number, merge=True)
    row = record_to_row(rec, engine.resolver, engine.mft, bitmap=engine.volume_bitmap)
    print(_print_location(row, rec, engine))
    if rec.index_root is not None:
        ir = rec.index_root
        print("  $I30 index root: indexes %s, %d-byte index records, %s (index entries not parsed in this version)" % (
            ATTR_NAMES.get(ir.type, "0x%X" % ir.type), ir.bytes_per_index_record,
            "has $INDEX_ALLOCATION subnodes" if ir.has_subnodes else "small index, all entries resident"))
    print("  attributes:")
    for a in rec.attributes:
        extra = ""
        if a.resident:
            extra = "resident %d bytes" % len(a.value)
        else:
            extra = "non-resident vcn %d-%d real=%d alloc=%d runs=%s" % (
                a.start_vcn, a.end_vcn, a.real_size, a.alloc_size, runs_to_text(a.runs)[:120])
        print("    %-22s id=%-3d name=%-16r flags=0x%04X  %s" % (a.type_name, a.id, a.name, a.flags, extra))
    if args.hex:
        print("  raw record:")
        print(hexdump(rec.raw))
    return 0


def cmd_verify(args, engine):
    mft = engine.mft
    if mft.volume is None:
        raise MftError("verify needs a volume or image ($MFTMirr is not part of a standalone $MFT file)")
    res = mft.verify_mirror()
    names = {0: "$MFT", 1: "$MFTMirr", 2: "$LogFile", 3: "$Volume"}
    bad = 0
    print("$MFT LCN %d  vs  $MFTMirr LCN %d" % (mft.volume.mft_lcn, mft.volume.mftmirr_lcn))
    for n, status, detail in res:
        if status != "MATCH":
            bad += 1
        print("  record %d %-9s %-18s %s" % (n, names.get(n, ""), status, detail))
    if bad:
        warn("%d of %d mirrored record(s) differ from $MFTMirr. On an unmounted image this means corruption or "
             "tampering of the primary $MFT (or of the mirror); on a live volume it can be an unflushed write - "
             "re-check from a snapshot." % (bad, len(res)))
        return 3
    log("$MFTMirr matches the primary $MFT for all %d mirrored record(s)" % len(res))
    return 0



def _add_source_args(p):
    p.add_argument("source", help="volume / disk device, raw image, or standalone $MFT file")
    p.add_argument("--offset", type=int, default=None,
                   help="byte offset of the NTFS volume inside the image/disk (skips partition detection)")
    p.add_argument("--partition", type=int, default=None, help="partition index to use (see `info --partitions`)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug output on stderr")


def _add_filter_args(p, for_search=False):
    g = p.add_argument_group("filters")
    g.add_argument("--name", action="append", metavar="GLOB", help="file name glob (case-insensitive), repeatable")
    g.add_argument("--path", action="append", metavar="SUBSTR", help="path substring, repeatable")
    g.add_argument("--regex", metavar="RE", help="regex matched against full path and name")
    g.add_argument("--record", action="append", metavar="N[,N|A-B]", help="record number(s) / ranges")
    g.add_argument("--ext", metavar="EXT[,EXT]", help="extensions, e.g. exe,dll,ps1")
    g.add_argument("--after", type=parse_user_time, metavar="TIME", help="any timestamp >= TIME (UTC)")
    g.add_argument("--before", type=parse_user_time, metavar="TIME", help="any timestamp <= TIME (UTC)")
    g.add_argument("--time-field", default="any",
                   choices=["any", "si_created", "si_modified", "si_mft_modified", "si_accessed",
                            "fn_created", "fn_modified", "fn_mft_modified", "fn_accessed"],
                   help="which timestamp --after/--before apply to (default: any)")
    g.add_argument("--min-size", type=int, metavar="BYTES")
    g.add_argument("--max-size", type=int, metavar="BYTES")
    g.add_argument("--deleted-only", action="store_true", help="only deleted records (with a name)")
    g.add_argument("--in-use-only", action="store_true", help="only allocated records")
    g.add_argument("--dirs-only", action="store_true")
    g.add_argument("--files-only", action="store_true")
    g.add_argument("--ads-only", action="store_true", help="only records with alternate data streams")
    g.add_argument("--timestomp", action="store_true", help="only $SI created < $FN created (add --include-subsec "
                                                             "for whole-second $SI times)")
    g.add_argument("--suspicious", action="store_true", help="any structural / timestamp indicator")
    g.add_argument("--include-subsec", action="store_true",
                   help="let --timestomp/--suspicious also match SI_SUBSEC_ZERO (whole-second $SI times). Off by "
                        "default: zip/7z/tar extraction, robocopy, FAT/exFAT and network copies and many installers "
                        "produce it legitimately")


def build_parser():
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="NTFS $MFT triage for incident responders: dump, search, export. Stdlib only.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  %(prog)s info \\\\.\\C: --partitions --stats
  %(prog)s dump  /dev/sda2 -o mft.csv
  %(prog)s dump  image.dd --format body -o mft.body        # mactime -b mft.body
  %(prog)s dump  C/$MFT --deleted-only --format jsonl -o deleted.jsonl
  %(prog)s search \\\\.\\C: --name "*.ps1" --after 2024-05-01
  %(prog)s search image.dd --path Users/Public --ads-only
  %(prog)s search /dev/sda2 --timestomp --ext exe,dll
  %(prog)s export \\\\.\\C: --path Windows/Temp/evil.exe -o evidence/
  %(prog)s export image.dd --record 41233 --ads -o evidence/
  %(prog)s report deleted.jsonl --path Users --ext exe,ps1,lnk --format html -o deleted_users.html --open
  %(prog)s report deleted.jsonl --path Users --ext exe,ps1,lnk --format grid       # Out-GridView (Windows)
  %(prog)s search \\\\.\\C: --deleted-only --ext lnk --format grid                    # pick rows -> export cmd
  %(prog)s record image.dd 41233 --hex
  %(prog)s verify image.dd                                  # $MFT records 0-3 vs $MFTMirr
  %(prog)s extract-mft \\\\.\\C: -o C_MFT.bin

exit codes: 0 ok, 1 error / incomplete export, 2 no match, 3 verify mismatch, 130 interrupted
""")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL_NAME, __version__))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("info", help="volume and $MFT summary")
    _add_source_args(s)
    s.add_argument("--partitions", action="store_true", help="list partition table of the disk/image")
    s.add_argument("--stats", action="store_true", help="full pass with record statistics")
    s.set_defaults(func=cmd_info)

    s = sub.add_parser("dump", help="dump every MFT record")
    _add_source_args(s)
    s.add_argument("-o", "--output", default="-", help="output file (default stdout)")
    s.add_argument("--format", choices=["csv", "tsv", "jsonl", "body", "html", "md", "grid"], default="csv",
                   help="grid = open results in PowerShell Out-GridView (Windows)")
    s.add_argument("--max-rows", type=int, default=None,
                   help="row cap for html/md output (default 100000; 0 = unlimited)")
    s.add_argument("--grid-all-columns", action="store_true", help="grid: show every column, not the compact set")
    s.add_argument("--open", action="store_true", help="open the html output in the default browser when done")
    s.add_argument("--include-extension", action="store_true", help="also emit extension records as rows")
    s.add_argument("--no-merge", action="store_true", help="skip $ATTRIBUTE_LIST extension merge (faster)")
    s.add_argument("--no-runs", action="store_true", help="omit data_runs column (smaller output)")
    _add_filter_args(s)
    s.set_defaults(func=cmd_dump)

    s = sub.add_parser("search", help="find records and show where the data lives")
    _add_source_args(s)
    s.add_argument("-o", "--output", default="-", help="output file (default stdout)")
    s.add_argument("--format", choices=["text", "csv", "tsv", "jsonl", "body", "html", "md", "grid"], default="text",
                   help="text = detailed blocks; html = interactive single-file report; md = markdown table; "
                        "grid = PowerShell Out-GridView window (Windows), selected rows -> export command")
    s.add_argument("--max-rows", type=int, default=None,
                   help="row cap for html/md output (default 100000; 0 = unlimited)")
    s.add_argument("--grid-all-columns", action="store_true", help="grid: show every column, not the compact set")
    s.add_argument("--open", action="store_true", help="open the html output in the default browser when done")
    s.add_argument("--no-merge", action="store_true", help="skip $ATTRIBUTE_LIST extension merge (faster)")
    s.add_argument("--limit", type=int, default=0, help="stop after N hits")
    s.add_argument("--max-runs", type=int, default=8, help="data runs to print per hit in text mode")
    _add_filter_args(s, for_search=True)
    s.set_defaults(func=cmd_search)

    s = sub.add_parser("export", help="extract file content from the volume")
    _add_source_args(s)
    s.add_argument("--record", action="append", metavar="N[,N]", help="MFT record number(s)")
    s.add_argument("--path", action="append", metavar="PATH", help="exact path, e.g. Windows/Temp/x.exe")
    s.add_argument("--name", action="append", metavar="GLOB", help="file name glob (may match many)")
    s.add_argument("-o", "--out", default="MFTDigger_export", help="output directory")
    s.add_argument("--stream", default=None, metavar="ADS", help="export only this named stream (ADS)")
    s.add_argument("--ads", action="store_true", help="also export all alternate data streams")
    s.add_argument("--include-deleted", action="store_true", help="let --path/--name match deleted records")
    s.add_argument("--max-files", type=int, default=200, help="safety cap for --name matches")
    s.add_argument("--max-size", type=int, default=0, help="skip streams larger than BYTES (0 = no limit)")
    s.add_argument("--no-raw-record", action="store_true", help="do not save the raw 1 KB MFT record")
    s.add_argument("--preserve-times", action="store_true", help="set exported file mtime/atime from $SI")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("report", help="offline: filter an existing dump/search csv/jsonl into html/md/csv")
    s.add_argument("input", help="csv / tsv / jsonl produced by dump or search")
    s.add_argument("-o", "--output", default="-", help="output file (default stdout)")
    s.add_argument("--format", choices=["html", "md", "csv", "tsv", "jsonl", "body", "grid"], default="html",
                   help="grid = PowerShell Out-GridView window (Windows)")
    s.add_argument("--max-rows", type=int, default=None, help="row cap for html/md (default 100000; 0 = unlimited)")
    s.add_argument("--grid-all-columns", action="store_true", help="grid: show every column, not the compact set")
    s.add_argument("--open", action="store_true", help="open the html output in the default browser when done")
    s.add_argument("--limit", type=int, default=0, help="stop after N matching rows")
    s.add_argument("-v", "--verbose", action="store_true")
    _add_filter_args(s)
    s.set_defaults(func=cmd_report, offline=True)

    s = sub.add_parser("record", help="show one record in detail")
    _add_source_args(s)
    s.add_argument("number", type=int)
    s.add_argument("--hex", action="store_true", help="hexdump the raw record")
    s.set_defaults(func=cmd_record)

    s = sub.add_parser("extract-mft", help="copy the raw $MFT out of the volume")
    _add_source_args(s)
    s.add_argument("-o", "--output", required=True, help="destination file")
    s.set_defaults(func=cmd_extract_mft)

    s = sub.add_parser("verify", help="compare $MFT records 0-3 with $MFTMirr (corruption / tampering check)")
    _add_source_args(s)
    s.set_defaults(func=cmd_verify)
    return p


def main(argv=None):
    global _VERBOSE, args_max_runs, engine_source_path, _GRID_ALL
    parser = build_parser()
    args = parser.parse_args(argv)
    _VERBOSE = args.verbose
    _GRID_ALL = getattr(args, "grid_all_columns", False)
    if getattr(args, "format", "") == "grid" and getattr(args, "output", "-") != "-":
        warn("--format grid ignores -o (data goes to a temp CSV); use --format csv to keep a file")
    if getattr(args, "offline", False):
        engine_source_path = "<source>"
    if getattr(args, "offline", False):
        try:
            return args.func(args)
        except (MftError, OSError, ValueError) as e:
            err(str(e))
            return 1
    args_max_runs = getattr(args, "max_runs", 8)
    engine_source_path = args.source
    if os.name == "nt" and re.match(r"^[A-Za-z]:\\?$", args.source):
        args.source = "\\\\.\\" + args.source.rstrip("\\")
        engine_source_path = args.source
    t0 = time.time()
    try:
        looks_raw = args.source.startswith("\\\\.\\") or args.source.startswith("/dev/")
        if looks_raw and not is_admin():
            warn("Raw device access usually needs Administrator / root privileges")
        mft = open_source(args.source, args.offset, args.partition)
        log("Source: %s  kind=%s  records=%d  record_size=%d%s" % (
            args.source, mft.kind, mft.record_count, mft.record_size,
            ("  cluster=%d" % mft.cluster_size) if mft.cluster_size else ""))
        engine = Engine(mft)
        try:
            rc = args.func(args, engine)
        finally:
            try:
                mft.close()
            except Exception:
                pass
    except MftError as e:
        err(str(e))
        return 1
    except KeyboardInterrupt:
        err("Interrupted")
        return 130
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except OSError as e:
        err(str(e))
        return 1
    dbg("total time %.1fs" % (time.time() - t0))
    return rc



def _run_menu():
    try:
        rc = main(sys.argv[1:])
    except SystemExit as e:          
        rc = e.code if isinstance(e.code, int) else 1
    if rc:
        print("\n[exit code %s] %s" % (rc, {1: "error or incomplete result - read the messages above",
                                              2: "no matching record", 3: "verify found a mismatch",
                                              130: "interrupted"}.get(rc, "")))
    return rc


def print_banner():
    banner = """
    ============================================================================
                    MFT Digger - Rapid Incident Response Tool
               NTFS $MFT Triage with Menu-Driven Interface

    MFTDigger %s - Pure Python 3.8+, standard library only
    Works on Windows, Linux and macOS
    ============================================================================
    """ % __version__
    print(banner)

def print_main_menu():
    print("\n" + "="*60)
    print("                MFT DIGGER - MAIN MENU")
    print("="*60)
    print("1.  Information & Analysis (info)")
    print("2.  Dump MFT Records (dump)")
    print("3.  Search for Records (search)")
    print("4.  Export File Content (export)")
    print("5.  Report Generation (report)")
    print("6.  Record Inspection (record)")
    print("7.  Extract MFT (extract-mft)")
    print("8.  Help & Examples")
    print("9.  Exit/Quit")
    print("="*60)

def print_info_menu():
    print("\n" + "-"*50)
    print("           INFORMATION & ANALYSIS")
    print("-"*50)
    print("1. Basic info")
    print("2. Info with partition table")
    print("3. Info with statistics")
    print("4. Info with partitions & stats")
    print("5. Verify $MFT records 0-3 against $MFTMirr")
    print("6. Back to main menu")
    print("-"*50)

def print_dump_menu():
    print("\n" + "-"*50)
    print("                 DUMP MFT RECORDS")
    print("-"*50)
    print("1. Dump to CSV (default)")
    print("2. Dump to TSV")
    print("3. Dump to JSONL")
    print("4. Dump to bodyfile (for timelining)")
    print("5. Dump to HTML report")
    print("6. Dump to Markdown")
    print("7. Dump deleted only")
    print("8. Dump in-use only")
    print("9. Dump with custom filters")
    print("10. Back to main menu")
    print("-"*50)

def print_search_menu():
    print("\n" + "-"*50)
    print("                 SEARCH RECORDS")
    print("-"*50)
    print("1. Search by filename")
    print("2. Search by path")
    print("3. Search by regex")
    print("4. Search by record number/range")
    print("5. Search by extension")
    print("6. Search deleted files")
    print("7. Search files with ADS")
    print("8. Search by time window")
    print("9. Search for timestomp indicators")
    print("10. Search with custom filters")
    print("11. Back to main menu")
    print("-"*50)

def get_source_input():
    print("\nEnter source (device/image/$MFT file):")
    print("Examples:")
    print("  Windows: \\\\.\\C:  or  C:  (shorthand)")
    print("  Linux:   /dev/sda2")
    print("  macOS:   /dev/rdisk2s1")
    print("  Image:   evidence.dd")
    print("  $MFT:    C/$MFT or MFT.bin")
    source = input("Source: ").strip().strip('"')
    return source if source else None

def get_confirmation(prompt="Continue? (y/N): "):
    response = input(prompt).strip().lower()
    return response in ['y', 'yes']

def run_info_command():
    source = get_source_input()
    if not source:
        print("No source provided.")
        return

    while True:
        print_info_menu()
        choice = input("Select option: ").strip()

        if choice == '1':
            sys.argv = ['MFTDigger.py', 'info', source]
            _run_menu()
        elif choice == '2':
            sys.argv = ['MFTDigger.py', 'info', source, '--partitions']
            _run_menu()
        elif choice == '3':
            sys.argv = ['MFTDigger.py', 'info', source, '--stats']
            _run_menu()
        elif choice == '4':
            sys.argv = ['MFTDigger.py', 'info', source, '--partitions', '--stats']
            _run_menu()
        elif choice == '5':
            sys.argv = ['MFTDigger.py', 'verify', source]
            _run_menu()
        elif choice == '6':
            break
        else:
            print("Invalid option. Please try again.")

def run_dump_command():
    source = get_source_input()
    if not source:
        print("No source provided.")
        return

    while True:
        print_dump_menu()
        choice = input("Select option: ").strip()

        if choice == '1':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '-o', output]
            _run_menu()
        elif choice == '2':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '--format', 'tsv', '-o', output]
            _run_menu()
        elif choice == '3':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '--format', 'jsonl', '-o', output]
            _run_menu()
        elif choice == '4':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '--format', 'body', '-o', output]
            _run_menu()
        elif choice == '5':
            output = input("Output file (required): ").strip()
            if not output:
                print("Output file is required for HTML format.")
                continue
            sys.argv = ['MFTDigger.py', 'dump', source, '--format', 'html', '-o', output, '--open']
            _run_menu()
        elif choice == '6':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '--format', 'md', '-o', output]
            _run_menu()
        elif choice == '7':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '--deleted-only', '-o', output]
            _run_menu()
        elif choice == '8':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'dump', source, '--in-use-only', '-o', output]
            _run_menu()
        elif choice == '9':
            print("\nEnter filters (press Enter to skip):")
            name = input("  --name (glob): ").strip()
            path = input("  --path (substring): ").strip()
            ext = input("  --ext (extensions): ").strip()
            after = input("  --after (date): ").strip()
            before = input("  --before (date): ").strip()

            output = input("Output file (default: stdout): ").strip() or "-"

            sys.argv = ['MFTDigger.py', 'dump', source]
            if name:
                sys.argv.extend(['--name', name])
            if path:
                sys.argv.extend(['--path', path])
            if ext:
                sys.argv.extend(['--ext', ext])
            if after:
                sys.argv.extend(['--after', after])
            if before:
                sys.argv.extend(['--before', before])
            sys.argv.extend(['-o', output])

            _run_menu()
        elif choice == '10':
            break
        else:
            print("Invalid option. Please try again.")

def run_search_command():
    source = get_source_input()
    if not source:
        print("No source provided.")
        return

    while True:
        print_search_menu()
        choice = input("Select option: ").strip()

        if choice == '1':
            name = input("Enter filename pattern (glob, e.g. *.exe): ").strip()
            if not name:
                print("Filename pattern is required.")
                continue
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--name', name, '-o', output]
            _run_menu()
        elif choice == '2':
            path = input("Enter path substring: ").strip()
            if not path:
                print("Path substring is required.")
                continue
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--path', path, '-o', output]
            _run_menu()
        elif choice == '3':
            regex = input("Enter regex pattern: ").strip()
            if not regex:
                print("Regex pattern is required.")
                continue
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--regex', regex, '-o', output]
            _run_menu()
        elif choice == '4':
            record = input("Enter record number(s) or range (e.g. 100,200,500-510): ").strip()
            if not record:
                print("Record specification is required.")
                continue
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--record', record, '-o', output]
            _run_menu()
        elif choice == '5':
            ext = input("Enter extensions (comma-separated, e.g. exe,dll,ps1): ").strip()
            if not ext:
                print("Extensions are required.")
                continue
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--ext', ext, '-o', output]
            _run_menu()
        elif choice == '6':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--deleted-only', '-o', output]
            _run_menu()
        elif choice == '7':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--ads-only', '-o', output]
            _run_menu()
        elif choice == '8':
            print("\nEnter time window (press Enter to skip):")
            after = input("  --after (date, e.g. 2026-09-01): ").strip()
            before = input("  --before (date, e.g. 2026-09-30): ").strip()
            time_field = input("  --time-field (default: any): ").strip() or "any"

            if not after and not before:
                print("At least one time boundary is required.")
                continue

            output = input("Output file (default: stdout): ").strip() or "-"

            sys.argv = ['MFTDigger.py', 'search', source]
            if after:
                sys.argv.extend(['--after', after])
            if before:
                sys.argv.extend(['--before', before])
            if time_field != "any":
                sys.argv.extend(['--time-field', time_field])
            sys.argv.extend(['-o', output])

            _run_menu()
        elif choice == '9':
            output = input("Output file (default: stdout): ").strip() or "-"
            sys.argv = ['MFTDigger.py', 'search', source, '--timestomp', '-o', output]
            _run_menu()
        elif choice == '10':
            print("\nEnter filters (press Enter to skip):")
            name = input("  --name (glob): ").strip()
            path = input("  --path (substring): ").strip()
            regex = input("  --regex (pattern): ").strip()
            ext = input("  --ext (extensions): ").strip()
            record = input("  --record (numbers/ranges): ").strip()
            after = input("  --after (date): ").strip()
            before = input("  --before (date): ").strip()
            time_field = input("  --time-field (default: any): ").strip() or "any"
            deleted_only = input("  --deleted-only? (y/N): ").strip().lower() in ['y', 'yes']
            in_use_only = input("  --in-use-only? (y/N): ").strip().lower() in ['y', 'yes']
            dirs_only = input("  --dirs-only? (y/N): ").strip().lower() in ['y', 'yes']
            files_only = input("  --files-only? (y/N): ").strip().lower() in ['y', 'yes']
            ads_only = input("  --ads-only? (y/N): ").strip().lower() in ['y', 'yes']
            timestomp = input("  --timestomp? (y/N): ").strip().lower() in ['y', 'yes']
            suspicious = input("  --suspicious? (y/N): ").strip().lower() in ['y', 'yes']
            min_size = input("  --min-size (bytes): ").strip()
            max_size = input("  --max-size (bytes): ").strip()

            output = input("Output file (default: stdout): ").strip() or "-"

            sys.argv = ['MFTDigger.py', 'search', source]
            if name:
                sys.argv.extend(['--name', name])
            if path:
                sys.argv.extend(['--path', path])
            if regex:
                sys.argv.extend(['--regex', regex])
            if ext:
                sys.argv.extend(['--ext', ext])
            if record:
                sys.argv.extend(['--record', record])
            if after:
                sys.argv.extend(['--after', after])
            if before:
                sys.argv.extend(['--before', before])
            if time_field != "any":
                sys.argv.extend(['--time-field', time_field])
            if deleted_only:
                sys.argv.append('--deleted-only')
            if in_use_only:
                sys.argv.append('--in-use-only')
            if dirs_only:
                sys.argv.append('--dirs-only')
            if files_only:
                sys.argv.append('--files-only')
            if ads_only:
                sys.argv.append('--ads-only')
            if timestomp:
                sys.argv.append('--timestomp')
            if suspicious:
                sys.argv.append('--suspicious')
            if min_size:
                sys.argv.extend(['--min-size', min_size])
            if max_size:
                sys.argv.extend(['--max-size', max_size])
            sys.argv.extend(['-o', output])

            _run_menu()
        elif choice == '11':
            break
        else:
            print("Invalid option. Please try again.")

def run_export_command():
    source = get_source_input()
    if not source:
        print("No source provided.")
        return

    print("\nSelect target specification:")
    print("1. By record number")
    print("2. By path")
    print("3. By filename pattern")
    choice = input("Select option: ").strip()

    target_args = []
    if choice == '1':
        record = input("Enter record number(s) (comma-separated): ").strip()
        if not record:
            print("Record number is required.")
            return
        target_args = ['--record', record]
    elif choice == '2':
        path = input("Enter exact path: ").strip()
        if not path:
            print("Path is required.")
            return
        target_args = ['--path', path]
    elif choice == '3':
        name = input("Enter filename pattern (glob): ").strip()
        if not name:
            print("Filename pattern is required.")
            return
        target_args = ['--name', name]
    else:
        print("Invalid option.")
        return

    print("\nAdditional options:")
    ads = input("Export ADS also? (y/N): ").strip().lower() in ['y', 'yes']
    stream = input("Export specific ADS stream (leave empty for none): ").strip()
    include_deleted = input("Include deleted records? (y/N): ").strip().lower() in ['y', 'yes']
    max_files = input("Max files (default 200): ").strip() or "200"
    max_size = input("Max size per file in bytes (0=unlimited): ").strip() or "0"
    no_raw_record = input("Do not save raw MFT record? (y/N): ").strip().lower() in ['y', 'yes']
    preserve_times = input("Preserve file timestamps? (y/N): ").strip().lower() in ['y', 'yes']
    out_dir = input("Output directory (default: MFTDigger_export): ").strip() or "MFTDigger_export"

    sys.argv = ['MFTDigger.py', 'export', source] + target_args
    if ads:
        sys.argv.append('--ads')
    if stream:
        sys.argv.extend(['--stream', stream])
    if include_deleted:
        sys.argv.append('--include-deleted')
    if max_files and max_files != "200":
        sys.argv.extend(['--max-files', max_files])
    if max_size and max_size != "0":
        sys.argv.extend(['--max-size', max_size])
    if no_raw_record:
        sys.argv.append('--no-raw-record')
    if preserve_times:
        sys.argv.append('--preserve-times')
    sys.argv.extend(['-o', out_dir])

    _run_menu()

def run_report_command():
    print("\nEnter input file (CSV/TSV/JSONL from dump/search):")
    input_file = input("Input file: ").strip()
    if not input_file:
        print("Input file is required.")
        return

    if not os.path.exists(input_file):
        print(f"File not found: {input_file}")
        return

    print("\nSelect output format:")
    print("1. HTML (interactive report)")
    print("2. Markdown table")
    print("3. CSV")
    print("4. TSV")
    print("5. JSONL")
    print("6. Bodyfile")
    print("7. Grid view (Windows only)")
    format_choice = input("Select format: ").strip()

    format_map = {
        '1': 'html',
        '2': 'md',
        '3': 'csv',
        '4': 'tsv',
        '5': 'jsonl',
        '6': 'body',
        '7': 'grid'
    }

    if format_choice not in format_map:
        print("Invalid format selection.")
        return

    output_format = format_map[format_choice]
    output_file = input("Output file (default: stdout): ").strip() or "-"

    print("\nEnter filters (press Enter to skip):")
    name = input("  --name (glob): ").strip()
    path = input("  --path (substring): ").strip()
    ext = input("  --ext (extensions): ").strip()
    record = input("  --record (numbers/ranges): ").strip()
    after = input("  --after (date): ").strip()
    before = input("  --before (date): ").strip()
    time_field = input("  --time-field (default: any): ").strip() or "any"
    deleted_only = input("  --deleted-only? (y/N): ").strip().lower() in ['y', 'yes']
    in_use_only = input("  --in-use-only? (y/N): ").strip().lower() in ['y', 'yes']
    dirs_only = input("  --dirs-only? (y/N): ").strip().lower() in ['y', 'yes']
    files_only = input("  --files-only? (y/N): ").strip().lower() in ['y', 'yes']
    ads_only = input("  --ads-only? (y/N): ").strip().lower() in ['y', 'yes']
    timestomp = input("  --timestomp? (y/N): ").strip().lower() in ['y', 'yes']
    suspicious = input("  --suspicious? (y/N): ").strip().lower() in ['y', 'yes']
    min_size = input("  --min-size (bytes): ").strip()
    max_size = input("  --max-size (bytes): ").strip()

    limit = input("Limit results (0=no limit): ").strip()
    max_rows = input("Max rows for HTML/MD (default 100000): ").strip() or "100000"
    open_browser = input("Open HTML in browser after generation? (y/N): ").strip().lower() in ['y', 'yes'] if output_format == 'html' else False

    sys.argv = ['MFTDigger.py', 'report', input_file]
    if name:
        sys.argv.extend(['--name', name])
    if path:
        sys.argv.extend(['--path', path])
    if ext:
        sys.argv.extend(['--ext', ext])
    if record:
        sys.argv.extend(['--record', record])
    if after:
        sys.argv.extend(['--after', after])
    if before:
        sys.argv.extend(['--before', before])
    if time_field != "any":
        sys.argv.extend(['--time-field', time_field])
    if deleted_only:
        sys.argv.append('--deleted-only')
    if in_use_only:
        sys.argv.append('--in-use-only')
    if dirs_only:
        sys.argv.append('--dirs-only')
    if files_only:
        sys.argv.append('--files-only')
    if ads_only:
        sys.argv.append('--ads-only')
    if timestomp:
        sys.argv.append('--timestomp')
    if suspicious:
        sys.argv.append('--suspicious')
    if min_size:
        sys.argv.extend(['--min-size', min_size])
    if max_size:
        sys.argv.extend(['--max-size', max_size])
    if limit and limit != "0":
        sys.argv.extend(['--limit', limit])
    if max_rows and max_rows != "100000":
        sys.argv.extend(['--max-rows', max_rows])
    if open_browser:
        sys.argv.append('--open')
    if output_file != "-":
        sys.argv.extend(['-o', output_file])
    sys.argv.extend(['--format', output_format])

    _run_menu()

def run_record_command():
    source = get_source_input()
    if not source:
        print("No source provided.")
        return

    record_num = input("Enter record number: ").strip()
    if not record_num:
        print("Record number is required.")
        return

    hex_dump = input("Include hexdump? (y/N): ").strip().lower() in ['y', 'yes']
    verbose = input("Verbose output? (y/N): ").strip().lower() in ['y', 'yes']

    sys.argv = ['MFTDigger.py', 'record', source, record_num]
    if hex_dump:
        sys.argv.append('--hex')
    if verbose:
        sys.argv.append('-v')

    _run_menu()

def run_extract_mft_command():
    source = get_source_input()
    if not source:
        print("No source provided.")
        return

    output_file = input("Output file for extracted MFT: ").strip()
    if not output_file:
        print("Output file is required.")
        return

    sys.argv = ['MFTDigger.py', 'extract-mft', source, '-o', output_file]
    _run_menu()

def show_help_examples():
    print("\n" + "="*60)
    print("                   HELP & EXAMPLES")
    print("="*60)
    print("\nQUICK START EXAMPLES:")
    print("# What am I looking at?")
    print("MFTDigger.py info evidence.dd --partitions --stats")
    print()
    print("# Dump everything to CSV")
    print("MFTDigger.py dump evidence.dd -o mft.csv")
    print()
    print("# Deleted PowerShell scripts under Users, interactive HTML")
    print("MFTDigger.py search evidence.dd --deleted-only --ext ps1 --path Users --format html -o ps1.html --open")
    print()
    print("# Where exactly is that file?")
    print("MFTDigger.py search evidence.dd --path \"Windows/Temp/update.ps1\"")
    print()
    print("# Pull it out with ADS, hashes and raw MFT record")
    print("MFTDigger.py export evidence.dd --path Windows/Temp/update.ps1 --ads -o evidence/")
    print()
    print("# Re-filter an existing dump without touching disk")
    print("MFTDigger.py report mft.csv --timestomp --ext exe,dll --format md -o timestomp.md")
    print()
    print("="*60)
    print("\nCOMMON IR WORKFLOWS:")
    print()
    print("1. SNAPSHOT FIRST, THEN ANALYZE")
    print("   MFTDigger.py extract-mft \\\\.\\C: -o C_MFT.bin")
    print("   MFTDigger.py dump C_MFT.bin -o C_mft.csv")
    print()
    print("2. ACTIVITY WINDOW")
    print("   MFTDigger.py search evidence.dd --after 2026-05-01T08:00 --before 2026-05-01T12:00 \\")
    print("       --ext exe,dll,ps1,bat,vbs,hta,js,lnk,zip --in-use-only --format html -o window.html --open")
    print()
    print("3. TIMESTOMP HUNT")
    print("   MFTDigger.py search \\\\.\\C: --timestomp --ext exe,dll,sys --path Windows --format csv -o timestomp.csv")
    print()
    print("4. MARK-OF-THE-WEB / DOWNLOAD ORIGIN")
    print("   MFTDigger.py search evidence.dd --ads-only --format csv -o ads.csv")
    print("   MFTDigger.py export evidence.dd --record 41233 --stream Zone.Identifier -o evidence/")
    print()
    print("5. DELETED DOCUMENTS")
    print("   MFTDigger.py search evidence.dd --deleted-only --path Users --ext docx,xlsx,pdf,7z --format grid")
    print("   MFTDigger.py export evidence.dd --record 88123,88130 --include-deleted -o recovered/")
    print()
    print("6. LOCKED EVIDENCE ON LIVE HOST")
    print("   MFTDigger.py export C: --path \"C:\\\\Windows\\\\System32\\\\winevt\\\\Logs\\\\Security.evtx\" -o evtx\\")
    print()
    print("7. SUPER-TIMELINE")
    print("   MFTDigger.py dump evidence.dd --format body -o mft.body")
    print("   mactime -b mft.body -d -z UTC > mft_timeline.csv")
    print()
    print("8. TAMPERING CHECK ($MFT vs $MFTMirr)")
    print("   MFTDigger.py verify evidence.dd")
    print()
    print("9. RECENT LNK FILES")
    print("   MFTDigger.py search evidence.dd --path Recent --ext lnk --format grid")
    print()
    print("="*60)
    input("\nPress Enter to continue...")

def main_menu():
    while True:
        print_banner()
        print_main_menu()

        choice = input("Select an option: ").strip()

        if choice == '1':
            run_info_command()
        elif choice == '2':
            run_dump_command()
        elif choice == '3':
            run_search_command()
        elif choice == '4':
            run_export_command()
        elif choice == '5':
            run_report_command()
        elif choice == '6':
            run_record_command()
        elif choice == '7':
            run_extract_mft_command()
        elif choice == '8':
            show_help_examples()
        elif choice == '9':
            print("\nExiting MFT Digger. Goodbye!")
            break
        else:
            print("Invalid option. Please try again.")
            input("Press Enter to continue...")

COMMANDS = ("info", "dump", "search", "export", "report", "record", "extract-mft", "verify")


def _entry(argv):
    if not argv:
        try:
            main_menu()
        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting...")
            return 130
        except EOFError:
            return 0
        return 0
    if argv == ["--version"]:
        print("%s %s" % (TOOL_NAME, __version__))
        return 0
    if argv in (["-h"], ["--help"]):
        print_banner()
        print("Interactive menu : python MFTDigger.py")
        print("Command line     : python MFTDigger.py <command> [options]   (commands: %s)" % ", ".join(COMMANDS))
        print("Command help     : python MFTDigger.py <command> --help\n")
        build_parser().print_help()
        return 0
    return main(argv)


if __name__ == "__main__":
    sys.exit(_entry(sys.argv[1:]))
