# MFTDigger

[![tests](https://github.com/BurakDurukan/MFTDigger/actions/workflows/tests.yml/badge.svg)](https://github.com/BurakDurukan/MFTDigger/actions/workflows/tests.yml)

A single Python file that reads the NTFS `$MFT` and lets you dump it, search it and pull files out of it. It only uses the standard library (Python 3.8 or newer), so there is nothing to install: copy `MFTDigger.py` to the analysis box and run it.

It takes a raw disk image, a live volume or a `$MFT` file collected with KAPE or Velociraptor. I wrote it for triage work, where the questions are mostly the same every time: what was on this disk, when did it change, and can I still get the deleted file back?

```
python MFTDigger.py search evidence.dd --deleted-only --ext ps1,lnk --path Users
python MFTDigger.py export evidence.dd --record 41233 --ads -o evidence/
```

The volume is never mounted, and the analysis host can be Windows, Linux or macOS.

## Commands

| Command | What it does |
|---|---|
| `info` | Volume geometry, partition table, record statistics |
| `dump` | Every record to CSV, TSV, JSONL, bodyfile (for `mactime`), a single-file HTML report, Markdown or Out-GridView on Windows |
| `search` | Filter by name glob, path, regex, extension, time window, size, deleted, ADS, timestomp or recoverability (`--clusters-free`). Prints where the record and the data sit on disk |
| `export` | Writes `$DATA` and alternate data streams to disk with SHA256/SHA1/MD5, plus the raw MFT record and a JSON sidecar |
| `record` | One record in detail: attributes, data runs, `$I30` header, hexdump |
| `verify` | Compares `$MFT` records 0 to 3 with `$MFTMirr` |
| `extract-mft` | Copies the raw `$MFT` out of a volume and prints its SHA256 |
| `report` | Re-filters an existing dump into HTML, Markdown or CSV without touching the image again |

Accepted inputs: raw/dd images, live volumes (`\\.\C:`, `/dev/sdX`, `/dev/rdiskN`), whole disks with an MBR (primary and logical partitions) or a GPT (512 and 4096 byte sectors), and a standalone `$MFT`.

Resident and non-resident files, ADS, hard links, sparse files and LZNT1-compressed files are all handled, deleted or not.

## Quick start

```bash
git clone https://github.com/BurakDurukan/MFTDigger.git
cd MFTDigger
python MFTDigger.py                # interactive menu
python MFTDigger.py --help         # command line
```

On a live system you need Administrator or root, otherwise the raw device cannot be opened.

Some things I use it for:

```bash
# What am I looking at?
python MFTDigger.py info evidence.dd --partitions --stats
python MFTDigger.py verify evidence.dd

# Snapshot the $MFT first, then work offline
python MFTDigger.py extract-mft \\.\C: -o C_MFT.bin
python MFTDigger.py dump C_MFT.bin -o mft.csv

# Activity window, interactive HTML report
python MFTDigger.py search evidence.dd --after 2026-05-01T08:00 --before 2026-05-01T12:00 \
    --ext exe,dll,ps1,bat,vbs,hta,js,lnk --format html -o window.html --open

# Timestomp hunt
python MFTDigger.py search evidence.dd --timestomp --ext exe,dll,sys --format csv -o timestomp.csv

# Download origin (Mark-of-the-Web)
python MFTDigger.py search evidence.dd --ads-only --format csv -o ads.csv
python MFTDigger.py export evidence.dd --record 41233 --stream Zone.Identifier -o evidence/

# Deleted documents, recoverable ones only
python MFTDigger.py search evidence.dd --deleted-only --clusters-free yes --ext docx,xlsx,pdf \
    --format jsonl -o deleted.jsonl
python MFTDigger.py export evidence.dd --record 88123,88130 -o recovered/

# Super-timeline
python MFTDigger.py dump evidence.dd --format body -o mft.body
mactime -b mft.body -d -z UTC > mft_timeline.csv
```

## How it behaves

### Paths

The sequence number of every parent is checked. If the parent record has been reused by something else, the file goes under `$OrphanFiles/<parent-N-seq-mismatch>/` rather than getting a path that never existed.

A deleted parent is a different case. NTFS bumps the sequence number when it frees a record, and MFTDigger accounts for that, so `staging/payload.exe` keeps its path even when the whole `staging` directory was deleted with it.

Hard links are all listed in `all_paths`. Names that live in an extension record (`$ATTRIBUTE_LIST`) are picked up too, for files and for directories.

### Deleted files

The `clusters_free` column is worked out from the volume `$Bitmap`:

| Value | Meaning |
|---|---|
| `yes` | every cluster is still free, the content is probably intact |
| `no` | the clusters belong to another file now |
| `partial` | some of them do |
| `contested` | the clusters are free, but another deleted record claims them as well, so the later file most likely overwrote this one |

For a contested record the manifest lists the other records (`clusters_shared_with`) and the one with the latest `$FN` creation time (`clusters_likely_owner`).

Keep in mind that `yes` only says the clusters are unallocated today. Something may have used them in between. Check the file signature or a known hash before you rely on recovered content.

### Timestomp indicators

`--timestomp` looks for `SI<FN`, a `$SI` creation time earlier than the `$FN` one. That is a lead and not proof: a file moved from another volume, or extracted by a tool that preserves timestamps, looks the same.

Whole-second `$SI` times (`SI_SUBSEC_ZERO`) are shown in the output but do not count as a hit by default, because zip extraction and plenty of copy tools produce them. `--include-subsec` turns them on.

### Damaged or odd volumes

If record 0 is damaged the volume is opened through `$MFTMirr`. This is printed and written to the manifest every time it happens.

WOF/Compact OS and Data Deduplication files are placeholders, the real content is somewhere else. They are exported with status `incomplete` and not passed off as the file.

BitLocker, exFAT, ReFS and FAT volumes are recognised and named in the error message.

### File names are evidence, not input

Names come from the disk and can be hostile. Control and bidirectional characters are escaped in terminal output, a name cannot break out of the HTML report, and `--excel-safe` keeps a spreadsheet from evaluating a name as a formula.

A malformed record turns into a `PARSE_ERROR` row and the run goes on. A stream that claims to be larger than the whole volume is skipped unless you pass `--max-size`.

## Manifests

Every export writes `export_manifest.jsonl` and a `<file>.meta.json` next to each file. Every `dump` or `search` that goes to a file gets `<output>.manifest.json`. They contain:

- the tool version and the exact command line
- `mft_sha256` and `mft_sha256_scope`, which says what exactly was hashed
- SHA256/SHA1/MD5 per stream, declared size against bytes written, data runs, `complete: true|false`
- the raw MFT record and its hash
- warnings such as reallocated or contested clusters, a record read from `$MFTMirr`, a placeholder stream

`mft_sha256` is the hash of the `$MFT` stream and not of the disk image. It matches the SHA256 of `extract-mft` output, or of the input file if you gave it a standalone `$MFT`. If any read failed along the way the field is `null` with a note. A partial hash is never written.

Each entry in `export_manifest.jsonl` has a `status`. Only `ok` and `directory` mean success, and anything else also shows up on stderr and in the exit code.

| Status | Meaning |
|---|---|
| `ok` | Every requested stream was written completely |
| `directory` | The record is a directory; metadata and the raw record were saved |
| `incomplete` | A stream is missing, was skipped, could not be read to the end, or is a placeholder |
| `no-data` | Nothing could be written for this record |
| `reallocated` | Deleted, and every cluster now belongs to another file |
| `partially-reallocated` | Deleted, and some clusters now belong to another file |
| `contested` | Deleted, and another deleted record claims the same clusters |
| `error` | The record is invalid or the output could not be written; the remaining records are still exported |

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error, or incomplete / reallocated / contested export |
| 2 | No matching record |
| 3 | `verify` found a mismatch with `$MFTMirr` |
| 130 | Interrupted |

## Testing

```bash
python -m unittest discover -s tests -v
```

The tests need only the standard library. Without any extra data they run against a small NTFS volume that `tests/ntfs_fixture.py` builds byte by byte, so the right answer for every record is known in advance. Everything else is optional and gets skipped when it is missing.

For 1.5.0 I also ran the tool against 32 public forensic images and compared the output with other tools:

- DFTT #1, #3, #7, #8 and #10 by Brian Carrier, which come with published answers
- the 24 NTFS images of the NIST CFReDS Deleted File Recovery set
- the NIST CFReDS Hacking Case, a full Windows XP system disk

`python tests/fetch_images.py --all` downloads the small ones (about 64 MB) and `--large` adds the Hacking Case (4.5 GB). Downloads are checked against a SHA-256.

Results from 2026-11-15:

| Check | Result |
|---|---|
| Published answers of DFTT #1, #3, #7, #8, #10 | 6 of 6 partitions, 8 of 8 keywords, 22 of 22 MD5 values |
| Allocated / deleted state, against `fls` | 15,359 of 15,360 records on 28 images |
| Exported content, against `icat` | 14,344 of 14,344 streams byte-identical (8.56 GB). 726 of them are deleted files and 2,203 are LZNT1-compressed |
| `clusters_free`, against the `$Bitmap` taken with `icat` | 705 of 705 deleted records |
| `$MFT` hash, against `icat 0` | 28 of 28 images |
| Volume written through `ntfs-3g`, hashes recorded while writing | 498 live files, 2 ADS, 41 deleted files, all identical |
| Windows against Linux output | byte-identical |

And record by record against other parsers, on the 31 images that contain NTFS (15,638 records):

| Tool | Outcome |
|---|---|
| The Sleuth Kit 4.12.1 (28 images) | State and ADS names agree on all records but one. 15,268 of 15,360 paths agree; the other 92 are extra names that only `fls` prints |
| MFTECmd 2026.10.6 | 15,445 records. Sequence, state, `$SI` and `$FN` times at 100 ns, LSN, names, parents, ADS and allocated paths all agree. 32 sizes and 1 deleted path differ |
| `mft` 0.10.1 | 2 names and 1 deleted path differ |
| `dissect.ntfs` 3.16 | 2 names, 1 allocated path and 19 deleted paths differ |
| analyzeMFT 3.1.1 | Sequence and state agree. 309 names, 4 timestamps and 4 parents differ |
| ntfsundelete 2022.10.3 (30 volumes) | All 800 deleted records and their names agree. It shows the 52 contested files as 100% recoverable, and 3 deleted compressed files as 0% although they can be recovered |

I went through every one of these differences and wrote them up in [tests/README.md](tests/README.md), together with the image sources and hashes. Most of them come down to long names stored in extension records, which several parsers show as the 8.3 name or not at all. The comparison also turned up three bugs in MFTDigger itself. Those are fixed in 1.5.0, see the [changelog](CHANGELOG.md).

## Limitations

- No E01 support. Convert to raw first with `ewfexport` or FTK Imager.
- Only `$MFT` is read. Deleted names that survive only in directory index slack (`$I30`) are not reported, and `$LogFile`, `$UsnJrnl` and Volume Shadow Copies are not parsed.
- File slack is not exported. A stream is written up to its declared size and the rest of the last cluster is left out.
- If a volume carries a second valid file system next to NTFS (as in DFTT #10), only NTFS is read and there is no warning.
- Encrypted volumes have to be unlocked first. BitLocker is recognised and rejected. EFS files are exported as ciphertext with a warning.
- WOF/Compact OS and Data Deduplication content is not decoded.
- A standalone `$MFT` has no file content and no `$Bitmap`. Only resident streams can be exported from it, and `clusters_free` can only say `contested`.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Author

Burak Durukan, Senior Incident Responder / Senior Threat Detection Engineer
