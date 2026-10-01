# MFTDigger

**NTFS `$MFT` triage for incident responders: dump, search and export in a single Python file. No dependencies.**

MFTDigger reads the Master File Table straight from a disk image, a live volume or a collected `$MFT` file. It rebuilds paths, flags anomalies and exports file content with a chain-of-custody manifest. It is pure Python 3.8+ standard library, so you can copy it to a jump box or an analysis VM and run it immediately. There is nothing to install.

```
python MFTDigger.py search evidence.dd --deleted-only --ext ps1,lnk --path Users
python MFTDigger.py export evidence.dd --record 41233 --ads -o evidence/
```

---

## Why

During triage, the questions are usually simple: *what was on this disk, where is it, when did it change, and can I get it back?* MFTDigger answers them from the `$MFT` alone:

- It does so without mounting the volume, and it works with any OS as the analysis host.
- It handles deleted, resident and non-resident files, ADS, hard links, sparse files and LZNT1-compressed files.
- **It never reports a failure as success.** If an export is incomplete, it says so in the manifest, on stderr and in the exit code.

## Features

| | |
|---|---|
| **Inputs** | Raw/dd images, live volumes (`\\.\C:`, `/dev/sdX`, `/dev/rdiskN`), physical disks with MBR/GPT auto-detection, standalone `$MFT` (KAPE, Velociraptor) |
| **dump** | Every record to CSV, TSV, JSONL, bodyfile (`mactime`), a single-file interactive HTML report, Markdown, or Out-GridView (Windows) |
| **search** | By name glob, path, regex, extension, time window, size, deleted, ADS or timestomp; prints the exact on-disk location |
| **export** | `$DATA` and ADS streamed to disk with SHA256/SHA1/MD5, the raw MFT record and a JSON sidecar |
| **verify** | Compares `$MFT` records 0–3 with `$MFTMirr` (corruption and tampering check) |
| **record** | One record in detail: attributes, data runs, `$I30` header, hexdump |
| **extract-mft** | Copies the raw `$MFT` out of a volume, with its SHA256 |
| **report** | Re-filters an existing dump offline into HTML, Markdown or CSV |

**Forensic details it gets right**

- **Paths**: each parent sequence number is validated, so a reused parent goes to `$OrphanFiles/<parent-N-seq-mismatch>/` instead of producing a made-up path. All hard links are listed in `all_paths`. Directories whose `$FILE_NAME` lives in an extension record (`$ATTRIBUTE_LIST`) are resolved.
- **Deleted files**: the `clusters_free` column comes from the volume `$Bitmap`:
  - `yes`: every cluster is still free, so the content is probably intact.
  - `no`: the clusters have been reallocated, so the bytes belong to another file.
  - `partial`: some clusters have been reallocated.
- **Timestomp indicators**: `SI<FN` (`$SI` created earlier than `$FN` created). Whole-second `$SI` times (`SI_SUBSEC_ZERO`) are reported but are **not** a default hit, because zip extraction and many copy tools produce them legitimately. Add `--include-subsec` to include them.
- **`$MFTMirr` fallback**: if record 0 is damaged, the volume is opened from the mirror. Every fallback is reported and recorded in the manifest.
- **Placeholders**: WOF/Compact OS and Data Deduplication files are flagged as `incomplete`. They are not exported as if the placeholder were the content.

## Quick start

```bash
git clone https://github.com/BurakDurukan/MFTDigger.git
cd MFTDigger
python MFTDigger.py                # interactive menu
python MFTDigger.py --help         # command line
```

On a live system, run it as Administrator or root. Raw device access needs it.

### Common workflows

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

# Deleted documents, recoverable ones only (clusters_free = yes)
python MFTDigger.py dump evidence.dd --deleted-only --format jsonl -o deleted.jsonl
python MFTDigger.py export evidence.dd --record 88123,88130 -o recovered/

# Super-timeline
python MFTDigger.py dump evidence.dd --format body -o mft.body
mactime -b mft.body -d -z UTC > mft_timeline.csv
```

## Chain of custody

Every export writes `export_manifest.jsonl` plus a `<file>.meta.json` sidecar. Every `dump` or `search` written to a file gets `<output>.manifest.json`. These manifests record:

- tool version and the exact command line
- `mft_sha256`, together with `mft_sha256_scope`, which states exactly what was hashed
- per-stream SHA256/SHA1/MD5, declared size versus bytes written, data runs, `complete: true|false`
- the raw 1 KB MFT record and its hash
- warnings, for example: deleted with reallocated clusters, record read from `$MFTMirr`, placeholder stream

`mft_sha256` is the hash of the `$MFT` stream. It is **not** the hash of the disk image. It equals the SHA256 of `extract-mft` output, or of the input file when you analyse a standalone `$MFT`. If any read failed during the pass, the hash is withheld (`null`, with a note). MFTDigger never reports a partial hash.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Error, or incomplete / reallocated export |
| 2 | No matching record |
| 3 | `verify` found a mismatch with `$MFTMirr` |
| 130 | Interrupted |

## Testing

```bash
pip install pytest
python -m pytest -q tests/
```

- `tests/ntfs_fixture.py` builds a synthetic NTFS volume with known answers. It covers fragmented, sparse, LZNT1, hard link, ADS, deleted and reallocated files, parent sequence mismatch, extension-record directories, WOF placeholders, a corrupt record 0, mirror tampering and MBR/GPT wrappers.
- The test suite runs golden-hash export checks, exit-code checks, a menu run and a fuzz pass.
- CI runs on Linux, Windows and macOS with Python 3.8, 3.11 and 3.13.

Version 1.4.0 was also cross-validated against **The Sleuth Kit** on real `ntfs-3g` volumes:

| Check | Result |
|---|---|
| Paths, hard links, sizes, `$SI` timestamps | 6,331 records, no differences from `fls` |
| Export content | 6,282 streams byte-identical to ground truth and to `icat` |
| Deleted files | All 4 recovered with the original hash |
| `clusters_free` | Matches `blkls` on 235 deleted records |
| `$MFT` hash | Matches `icat 0` |
| Fuzzing | 26,000 runs, 0 crashes |
| Memory | A 96 MB export uses about 41 MB RSS (streamed) |

## Limitations

- **E01 is not supported.** Convert to raw first with `ewfexport` or FTK Imager.
- **Live volumes can change while they are being read.** For a consistent view, collect from a VSS snapshot or analyse an image.
- **Not decoded yet**: WOF/Compact OS content (XPRESS/LZX), `$Secure` owner SIDs, INDX entries, `$UsnJrnl`, `$LogFile`, VSS. These files are flagged, not silently returned as zeros.
- The 1.4.0 validation used `ntfs-3g` volumes. Testing on Windows-written volumes and on live `\\.\C:` is the next step.

## Roadmap

1. **Windows correctness**: WOF/XPRESS/LZX decoding, `$Secure` owner SID, Dedup.
2. **More evidence sources**: `$UsnJrnl`, INDX slack, VSS, `$LogFile`.
3. **Integrations**: Timesketch JSONL, Velociraptor artifact, KAPE module, SQLite output.
4. **R&D**:
   - MFT record slack carving
   - distribution-based timestomp detection
   - USN/LSN monotonicity analysis
   - one-command recovery of deleted resident files

## Author

Burak Durukan, Senior Incident Responder / Senior Threat Detection Engineer
