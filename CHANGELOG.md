# Changelog

## 1.5.0

This release is mostly about being able to trust the output. There is a test suite now, and the tool was compared against public forensic images and against other parsers. Several of the fixes below came out of that.

### New

- `clusters_free` can be `contested`, and so can the export status. Two deleted records that claim the same clusters used to be reported as probably intact. The manifest names the other records in `clusters_shared_with` and the one with the latest `$FN` creation time in `clusters_likely_owner`.
- `--clusters-free yes|no|partial|contested` for `dump`, `search` and `report`.
- `--excel-safe` for CSV and TSV. Cells starting with `=`, `+`, `-` or `@` get an apostrophe in front.
- Logical partitions inside an extended MBR partition, and GPT disks with 4096-byte sectors.
- BitLocker, exFAT, ReFS and FAT volumes are named in the error message.
- `export --record` takes ranges (`20-25`).
- `search` works with `--in-use-only`, `--dirs-only`, `--files-only` or `--suspicious` as the only filter.
- Tests in `tests/`: a synthetic NTFS volume builder, 32 public images (DFTT #1, #3, #7, #8, #10, the NIST CFReDS Deleted File Recovery set, the NIST Hacking Case), a volume written through `ntfs-3g`, and comparisons with The Sleuth Kit, MFTECmd, `mft`, `dissect.ntfs`, analyzeMFT and `ntfsundelete`. Details in `tests/README.md`.

### Fixed

Paths and names:

- Deleted files inside a deleted directory lost their path and ended up under `$OrphanFiles/<parent-N-seq-mismatch>/`. NTFS raises the sequence number when it frees a record, and that is taken into account now.
- A file whose `$FILE_NAME` is in an extension record was listed as `$OrphanFiles/<unknown-N>`.
- A directory with its long name in an extension record showed up with the 8.3 name in the paths of its children (`WinSxS/X86_MI~2.0_X/mfc42.dll`).
- An extended partition table with more than one partition was read only up to the first one.
- `info --partitions` on a plain volume printed a nonsense partition table read from the boot sector.

Export:

- Exporting a directory that has an alternate data stream wrote the stream but called the record `incomplete`.
- A file system error on one record stopped the export of everything after it. The record now gets status `error` and the export carries on.
- Very long file and stream names are shortened on disk. The full name stays in the manifest.
- A stream that declares more bytes than the whole volume is skipped unless `--max-size` is given. A crafted record could otherwise fill the disk with zeros.

Robustness:

- An attribute header cut off at the end of a record crashed the whole run with `struct.error`. It is a `PARSE_ERROR` row now.
- If the primary copy of records 0 to 3 is unusable, the row is built from the `$MFTMirr` copy. It used to be dropped.
- On Windows a non-ASCII file name crashed `dump` and `search` with `UnicodeEncodeError` when the output was piped or redirected. Output is always UTF-8 now.
- A file name containing `<!--<script` could break the HTML report.
- Control and bidirectional characters in file names are escaped in terminal output and log lines.
- `--record abc`, `--record 5-`, an empty `report` input and a file that merely starts with `FILE` give an error message, not a traceback.
- `report` wrote a header before failing on an empty input.

### Changed

- Scripts that read `clusters_free` or the export `status` have to handle the new value `contested`.
- An export that includes a contested record exits with 1.

## 1.4.0

Initial public release.
