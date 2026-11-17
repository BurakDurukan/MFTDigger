# Tests

```bash
python -m unittest discover -s tests -v
```

Plain `unittest`, standard library only. A test that needs something you do not have (an image, The Sleuth Kit, another parser, root on Linux) is skipped and tells you what is missing.

This file also documents where the test images come from and what came out of the 1.5.0 validation run, including every place where MFTDigger and another tool disagree.

## Layout

| File | Needs | Covers |
|---|---|---|
| `test_units.py` | nothing | Timestamps, data runs, record and attribute parsing, fixup, LZNT1, `$Bitmap` state, shared clusters, path resolution |
| `test_cli.py` | nothing | Every command on the synthetic volume: output formats, search filters, export, manifests, exit codes, `verify`, `$MFTMirr` fallback, MBR/GPT, standalone `$MFT`, the menu, fuzzing |
| `test_hardening.py` | nothing | Partition edge cases, detection of non-NTFS volumes, hostile file names, export failures, oversized streams, names in extension records |
| `test_public_images.py` | downloaded images | Published answers of the DFTT images, baselines and special cases of the NIST images |
| `test_sleuthkit.py` | images, `fls`, `icat` | Comparison with The Sleuth Kit, records and content |
| `test_other_tools.py` | images plus whichever of `mft`, `dissect.ntfs`, analyzeMFT, MFTECmd, `ntfsundelete` is installed | Comparison with those tools |
| `test_ntfs3g.py` | Linux, root, `ntfs-3g`, `mkntfs`, `setfattr` | A real volume with known content |

The Python parsers install with pip:

```bash
python -m pip install mft dissect.ntfs analyzeMFT
```

MFTECmd is picked up from `PATH`, or from the `MFTECMD` environment variable if you point it at the executable.

## The synthetic volume

`ntfs_fixture.py` writes an 8 MB NTFS volume by hand: boot sector, `$MFT`, `$MFTMirr`, `$Bitmap`. Because every byte is put there by the test code, the expected result for each record is known. It holds:

- resident, contiguous, fragmented, sparse and LZNT1-compressed files
- alternate data streams, a hard link with two parents, a non-ASCII name
- a file whose `$FILE_NAME` sits in an extension record
- a WOF placeholder, a record with `$SI` earlier than `$FN`, one with whole-second `$SI` times
- deleted files that are intact, resident, fully reallocated and partially reallocated
- a deleted directory tree and a file whose parent record was reused
- two deleted files claiming the same clusters

Some tests add records of their own, for example a directory that keeps its long name in an extension record and only the 8.3 name in the base record, a directory with an ADS, a 200 character name, or a stream that claims to be bigger than the volume.

The fixture can also wrap the volume in an MBR disk, an extended partition chain or a GPT disk (512 or 4096 byte sectors). Other tests break copies of it on purpose: a tampered mirror, a wiped record 0, a truncated image, a cut-off attribute header.

The fuzz pass mutates 4,000 single records in process and 30 whole images through the command line. `MFTDIGGER_FUZZ_RECORDS` and `MFTDIGGER_FUZZ_IMAGES` raise those numbers.

## Public images

The images are not in this repository. `fetch_images.py` gets them from the publishers and checks the SHA-256 values listed further down.

```bash
python tests/fetch_images.py              # DFTT #7 only (196 KB)
python tests/fetch_images.py --all        # everything except the Hacking Case (about 64 MB)
python tests/fetch_images.py --large      # the NIST Hacking Case (4.5 GB)
python tests/fetch_images.py --list
```

Archives land in `tests/images/`; set `MFTDIGGER_IMAGES` to use another directory. A few practical notes:

- Each NIST DFR image unpacks to 1 GiB. The tests unpack one at a time into a temp directory and remove it afterwards. If an unpacked `.dd` is already in the image directory it is used directly.
- The Hacking Case comes as eight segments. They are joined into a temporary 4.5 GB file, unless `schardt.dd` already exists in the image directory.
- `MFTDIGGER_DFR=dfr-07-one-ntfs,dfr-10-ntfs` restricts the DFR tests to those images, which helps when you are iterating.

All together that is 32 images from three sources, with 15,638 MFT records that produce a row.

### DFTT (Digital Forensics Tool Testing Images)

Published by Brian Carrier at https://dftt.sourceforge.net under the GNU GPL. Each test page gives the expected answers and the MD5 of the image.

| Id | Test | Layout | Image | Bytes | Image MD5 (as published) |
|---|---|---|---|---:|---|
| `dftt7` | [DFTT #7 NTFS Undelete (and leap year) Test #1](https://dftt.sourceforge.net/test7/index.html) | raw NTFS volume, 6 MB, 1024-byte clusters | `7-ntfs-undel.dd` | 6,160,384 | `e7dbb96759d9cd62b729463ebfe61dab` |
| `dftt3` | [DFTT #3 NTFS Keyword Search Test #1](https://dftt.sourceforge.net/test3/index.html) | raw NTFS volume, 8 MB, 512-byte clusters | `ntfs-img-kw-1.dd` | 8,224,768 | `389e42124eb23c5053ff6596976d6710` |
| `dftt8` | [DFTT #8 JPEG Search Test #1](https://dftt.sourceforge.net/test8/index.html) | raw NTFS volume, 10 MB | `8-jpeg-search.dd` | 10,289,152 | `9bdb9c76b80e90d155806a1fc7846db5` |
| `dftt10-disk` | [DFTT #10 NTFS Autodetect Test #1](https://dftt.sourceforge.net/test10/index.html) | MBR disk, two NTFS partitions (type 0x07) at sectors 63 and 96390 | `10-ntfs-disk.dd` | 98,705,408 | `9225ff95b92311a28b2224e9dc324231` |
| `dftt10-part1` | [DFTT #10 NTFS Autodetect Test #1](https://dftt.sourceforge.net/test10/index.html) | raw volume, 47 MB, valid as NTFS and as Ext2 at the same time | `10-ntfs-part1.dd` | 49,319,424 | `6bd741152ccedd50e12623af5eeba803` |
| `dftt10-part2` | [DFTT #10 NTFS Autodetect Test #1](https://dftt.sourceforge.net/test10/index.html) | raw volume, 47 MB, valid as NTFS and as UFS1 at the same time | `10-ntfs-part2.dd` | 49,351,680 | `0b768efb1011b047c9831c1e00d1706c` |
| `dftt1` | [DFTT #1 Extended Partition Test](https://dftt.sourceforge.net/test1/index.html) | MBR disk, three primary FAT16 partitions and three more inside two extended tables; no NTFS | `ext-part-test-2.dd` | 159,989,760 | `ea19519fc310835dd1fc20fc3cf36481` |

| Archive | Bytes | SHA-256 |
|---|---:|---|
| `7-undel-ntfs.zip` | 195,983 | `be2a85eb4e4e210d0c974254483d5ecacd4ea23f1e19f2110249ba306f72b5b7` |
| `3-kwsrch-ntfs.zip` | 6,034,758 | `47dae2f11f01cf52619146ab28062894d5c1e294dcc3eee77431a06607522440` |
| `8-jpeg-search.zip` | 1,944,066 | `fdc681ae976291e47fdd3db3b7958493cbcc8879e867a0fc372e7190de153bdb` |
| `10-ntfs-autodetect.zip` | 674,148 | `ed5954705b28159b39dbe752ecfa4af55338c949203e576c9f67df152ee38641` |
| `1-extend-part.zip` | 167,678 | `771cc763798ed23d85f6362de4adff503bf83c33c56c5ac8dea689a3996c8ce3` |

| Image | SHA-256 |
|---|---|
| `7-ntfs-undel.dd` | `4138cc42148e3381e3c66eb50090f4a30416ae8c20247c2b9bad27cf8c764d88` |
| `ntfs-img-kw-1.dd` | `cad097e8fcf4538a928c980a01bc64dcf36ca062432b0f6d5c3962e3bc0c4060` |
| `8-jpeg-search.dd` | `9c43d6a2dd5132cf6afc29e5c644cde0cb747c64998a68e73f2efb787887b126` |
| `10-ntfs-disk.dd` | `4d2edfe4a8ee0079720a4b9e258ecf59ffa17783465a5a013101614b4ac64049` |
| `10-ntfs-part1.dd` | `d6739c45d652c0eb67e59536e7b9c02b25ca99aaabf500fe9c374bb7f2ae8bc3` |
| `10-ntfs-part2.dd` | `529c607152f8ca25a6f2645e6894a80b303b4f2b352b89bdfef0fde549e3c6e2` |
| `ext-part-test-2.dd` | `b075ed83211765dd14f24390389b77b20ef688d70aaf69385e026b5513bdd8d2` |

What is checked against the published answers:

**#1, extended partitions.** Six FAT16 partitions, three of them inside two extended tables, and one of those tables has three entries. All six have to be listed at the published sectors (63, 52416, 104832, 157311, 209727, 262143). There is no NTFS on this image, it is only here for the partition code.

**#3, keyword search.** Eight of the ten keywords are in file content that an MFT tool can reach: resident and non-resident files, a deleted resident file, a keyword that crosses a fragment boundary, and ADS on files and on directories. Each keyword has to turn up in exactly the exported stream the answer table names, and the MFT records have to be at the published sectors (5409, 5415, 5423). The remaining two keywords are in file slack and in a deleted file whose record was reused. MFTDigger does not export slack, so those are out of reach.

**#7, undelete.** The ten deleted paths, the leap-day timestamps and the nine MD5 values (eight files and one ADS).

**#8, JPEG search.** The thirteen MD5 values, among them two deleted pictures (MFT entries 31 and 32) and one picture hidden in an ADS.

**#10, autodetect.** Both partitions are valid as two file systems at once (NTFS and Ext2, NTFS and UFS1). MFTDigger reads the NTFS side from the disk image and from both partition images and finds `NTFS.TXT`. The rows from the disk image equal the rows from the partition images. It does not tell you that a second file system is there.

### NIST CFReDS, Deleted File Recovery

Page: https://cfreds-archive.nist.gov/dfr-test-images.html
Layout document: https://cfreds-archive.nist.gov/dfr-images/setup-july-10-2012.pdf

US Government work, public domain. Every image is an MBR disk of 1,073,742,336 bytes with one NTFS partition at sector 128.

| Archive | Case | Bytes | SHA-256 |
|---|---|---:|---|
| `dfr-01-ntfs.dd.bz2` | One non-fragmented file | 2,257,102 | `9625d8946bc7712953d0ca7e73e4eaeff26381006951d3f7603d1797b50d19e0` |
| `dfr-01-recycle-ntfs.dd.bz2` | One file from an emptied recycle bin | 2,254,844 | `ca45532085e8e9b2c6ffde2965e1442ffe4eb32cd5a0b3ef28b0b5514be41211` |
| `dfr-02-ntfs.dd.bz2` | File with two fragments | 2,254,407 | `18ff23026ad7ed8fe6d93eca00200b0ede031c6ee4e760f52e62aee397d87844` |
| `dfr-03-ntfs.dd.bz2` | File with multiple fragments | 2,225,194 | `1f836037afa45e97992f6c1e983b0f0b89de1db859ff962d43bb628813bd992e` |
| `dfr-04-ntfs.dd.bz2` | Several non-fragmented files with non-ASCII names | 2,274,867 | `ea057626bfbd419f52b743763ad52c82c4b16bfaecc53b12dc9f0219cedae931` |
| `dfr-05-braid-ntfs.dd.bz2` | Several fragmented files, braided layout | 2,248,651 | `86524dd5a98d710e66905c6087c15a2c046a8fb70c3b2d327dbcb4eb6bcf17a8` |
| `dfr-05-nest-ntfs.dd.bz2` | Several fragmented files, nested layout | 2,248,857 | `26a662dc84a8fd8efb84e0670b107789e26ffae6e098ad6a9116413cf8cef0aa` |
| `dfr-05-ntfs.dd.bz2` | Several fragmented files | 2,223,815 | `d425e26bcec7e9f9667ebc21e683da269e69bd1117d89afc6cce604e06c9f938` |
| `dfr-06-ntfs.dd.bz2` | One large file | 2,190,904 | `4a463ea98d14ba9c37f0e224e683df853c37082247c69c420fb732688ab9574d` |
| `dfr-07-ntfs.dd.bz2` | One overwritten file | 2,239,500 | `45ffe6dd4030d05dacb70e0147c4e73cf3a7e94bd6cf532e4f3c2ce6dcb86360` |
| `dfr-07-one-ntfs.dd.bz2` | One overwritten file, overwriting file deleted as well | 2,234,490 | `7d7ae66abc5e83cec065876612c978a5e25fc29accdf4c8056c454974850894c` |
| `dfr-07-two-ntfs.dd.bz2` | One overwritten file, overwriting file still allocated | 2,229,856 | `13030782980d3f64d372ef00b4575f82f804ac1c45181c0bd1d55aae1faf7ad7` |
| `dfr-08-ntfs.dd.bz2` | Several overwritten files | 2,248,030 | `31adfd92e56cc09b59cbe6991045546c30bf1d12e04ada5ab6aa2c5f527be6e6` |
| `dfr-09-ntfs.dd.bz2` | Large number of files, none overwritten | 2,286,897 | `bf19464bc2f6956dfa0dcf2db1d5fb9a97235a710f319265b77cd15d5d96085c` |
| `dfr-10-ntfs.dd.bz2` | Large number of files, some overwritten | 2,400,749 | `965b8720b04fb5e088585ee4dba37f96ba18138f85a467e85d8ad6d81b6dd98e` |
| `dfr-11-compress-ntfs.dd.bz2` | One directory on a compressed NTFS volume | 2,227,628 | `7f796dec9dccbc7d05c0a1d4e1415dbe2b49eb533a8e667ace68e66fab8b58b9` |
| `dfr-11-mft-ntfs.dd.bz2` | One directory with files small enough to stay resident in the MFT | 2,222,443 | `0645da1fcf0c8b03e16c86a67cad8c41bfbe8ee1713aaba941642b92dc88e046` |
| `dfr-11-ntfs.dd.bz2` | One non-fragmented directory | 2,221,747 | `2490bada431f489ff5830a589f5f694a7ac18585dab127717576dba911b4e10d` |
| `dfr-12-ntfs.dd.bz2` | One fragmented directory | 2,223,577 | `3446b25052c57cfd4f685437debdb9c2b42577caeb9678f922c01daade1624f7` |
| `dfr-13-ntfs.dd.bz2` | Random file system activity | 2,394,856 | `4f2bb529b7803ec89e770d0733ea393f0deb4a43c7d3d6f271fe15f26f6c6856` |
| `dfr-14-ntfs.dd.bz2` | Other file system objects: hard links, alternate data streams | 2,258,155 | `5517a645f5aee480aaf72c82e737b13903f57e0d78bb6a511b3eec4ac445a7de` |
| `dfr-15-ntfs.dd.bz2` | One of each file system object | 2,242,473 | `a455f05cad653297595c5b98514f80e9f97aaa8b264a115f5be497322214af07` |
| `dfr-16-ntfs.dd.bz2` | Large number of files | 2,352,771 | `125af41e6fc60437e268e9def2db95c952095466852863607f49082c7a57566a` |
| `dfr-17-ntfs.dd.bz2` | Deep file paths | 2,268,735 | `bc3ed47c055f4cb6d474c76f489e45e281dbcb8349d8e3c3ccbd9a803a377666` |

Unpacked:

| Image | MD5 | SHA-256 |
|---|---|---|
| `dfr-01-ntfs.dd` | `f39f61c49713476a20bfdbee84c87506` | `c863ccad01804b840a6dfa623a94996ca876e15ded41c6c0d8ae148620eb6493` |
| `dfr-01-recycle-ntfs.dd` | `8ab1be92e42f6bfd855743cadbccf768` | `6a44af0530812edf1a289c539a3c6c7d6b42e1c93e8f60e53287bddb5fdf7efa` |
| `dfr-02-ntfs.dd` | `67ea94b8895633e304b4899a5e03ab6d` | `57e6f37d3312ee4a113a6534a1ffcbd45ad3e0325a509442ac54ae632762d1ef` |
| `dfr-03-ntfs.dd` | `da1dd933e0882e4c35c057b991fab332` | `466db91345fc6f5b47527f4b2cb109305bdabf2caa0883eb60516c26e625b03a` |
| `dfr-04-ntfs.dd` | `a60705609f9a09ee93ac6b56ba9a23a0` | `a590613b3e54e2963e9d95e95c201e4c8d4bcffd19281c4d8c64388f1ab2d8e1` |
| `dfr-05-braid-ntfs.dd` | `8338a700d5accdf0d383e21448c2ed92` | `43f239c3b141a02c20ee2e6adc94e553215a3b35371fa291f7e3d4aa9b562cb7` |
| `dfr-05-nest-ntfs.dd` | `4bc1e83c32a62f3ca9cd60cbd615378e` | `7da808c9d3da75eb437fd175567dc781f6291547fab37bb704773cb31562669c` |
| `dfr-05-ntfs.dd` | `a9b20a7ef054fd11981906b930ca2d97` | `f957f78b200307ef8c49de42309202cbff03c1dc8cea1f4ea1230d8a6eeda27c` |
| `dfr-06-ntfs.dd` | `9e0edddf7f50ed4d26175d72ff5c94cb` | `316988006bc398625729ce9224e3749b18304dfd54a0aa3696d965dc8a8e2287` |
| `dfr-07-ntfs.dd` | `2d717634adb074169d09eab660c4869f` | `d60f4a436239e13a83df8587cbcfef4be316005b822c6bc894ce15a464d9208e` |
| `dfr-07-one-ntfs.dd` | `a0338713cf757e8bbbe74b70f275731f` | `102dbf259804eec55fdc0d6d530f72605392cdff14d72931c4bca65ae47c4aa6` |
| `dfr-07-two-ntfs.dd` | `5fe59cb5217b1d9e6a7e3917fb636070` | `2229eb31b86e5e2dedbee2cf2623c3e5223f107a3778dfd2df9c3c052e7a74f7` |
| `dfr-08-ntfs.dd` | `56a58992bba33bbba90e6bc1ccc8504b` | `7f3b372224c8b7d95fa8caf8c084b9aeea02ed3ecfb432372b041cf6e78bbb29` |
| `dfr-09-ntfs.dd` | `3111e20e540b2930ad3f0f087c87d85b` | `1945ecf30539c99f87fa9ea4615ebebf2fc109d2135c27d1db303423bb8d0d3a` |
| `dfr-10-ntfs.dd` | `88377984f1b2084ad4426fe6597b2adf` | `5db9f671b9da1b2fbb8300409822ae57a66ff8a4fd5b51224de0a13c14fa73be` |
| `dfr-11-compress-ntfs.dd` | `d7cf4e09d83918d4e40217ed01d60d3a` | `fd38b6eeb1ad1b80d303faf2dbfd905c6368c77febdaf2f2ab11e4dbb4e78942` |
| `dfr-11-mft-ntfs.dd` | `f9d6ee756a0a2b69c751df0b401945bb` | `5c19686c2569ae0343c0616439c4b1b1b9fd368ad64b8995f2bae4dce0a7aeb8` |
| `dfr-11-ntfs.dd` | `be8dcd0d07479e0139d97851ee4e2793` | `6f7ab28e317afdfde9cf55ba04a4431a87aee1a0da3a249c8c2314c500f8a4e8` |
| `dfr-12-ntfs.dd` | `c14641e14dc87fffaac9a924149787e0` | `dd2dac9fbcf525996a4fbbc571cf8b75ce8d8f808d82c2f8e136ca6b0705ee31` |
| `dfr-13-ntfs.dd` | `bd0f930a1306affbadf033e581b4e055` | `0df34bf60312614080b890d97b6c21095eab41887ceeb947bef5ae1727d66ccb` |
| `dfr-14-ntfs.dd` | `d0858060ecc951a356d999814f286b28` | `dfe84bbf318d49c0ba9f5ff4c73c2b860cb5ddea4d830ec1461138adaa94e0c6` |
| `dfr-15-ntfs.dd` | `d3dbc4ab8c408ed045cd99ba14938adf` | `ab2112ae8f7a92906a2f9761edb4819c2f4ebce369003acc6381f24ef0954e96` |
| `dfr-16-ntfs.dd` | `67d55e3a575cdd9c39ff35b64f8e4bab` | `eff76084207660ec214ed57afd2d728cd731c6ef5427ec6b87e9a17298eb7bff` |
| `dfr-17-ntfs.dd` | `026022d7dbe7c146318011bbc6f7e179` | `5a0293e2ae4aa9954c7e14f9322c321591ad3ba768daaf7ba49255048863a232` |

The baseline per image, as stored in `tests/data/images.json`. The `clusters_free` column counts deleted records that still have a name.

| Image | Rows | In use | Deleted | `clusters_free` |
|---|---:|---:|---:|---|
| `dfr-01-ntfs` | 67 | 29 | 1 | yes 1 |
| `dfr-01-recycle-ntfs` | 34 | 32 | 2 | n/a 1, yes 1 |
| `dfr-02-ntfs` | 39 | 30 | 1 | yes 1 |
| `dfr-03-ntfs` | 33 | 32 | 1 | yes 1 |
| `dfr-04-ntfs` | 51 | 39 | 12 | yes 12 |
| `dfr-05-braid-ntfs` | 31 | 29 | 2 | yes 2 |
| `dfr-05-nest-ntfs` | 34 | 32 | 2 | yes 2 |
| `dfr-05-ntfs` | 34 | 32 | 2 | yes 2 |
| `dfr-06-ntfs` | 29 | 28 | 1 | yes 1 |
| `dfr-07-ntfs` | 36 | 33 | 3 | contested 2, n/a 1 |
| `dfr-07-one-ntfs` | 32 | 30 | 2 | contested 2 |
| `dfr-07-two-ntfs` | 32 | 31 | 1 | no 1 |
| `dfr-08-ntfs` | 41 | 28 | 13 | contested 6, yes 7 |
| `dfr-09-ntfs` | 290 | 30 | 260 | yes 260 |
| `dfr-10-ntfs` | 811 | 551 | 260 | yes 260 |
| `dfr-11-compress-ntfs` | 41 | 37 | 4 | n/a 1, yes 3 |
| `dfr-11-mft-ntfs` | 39 | 35 | 4 | n/a 4 |
| `dfr-11-ntfs` | 39 | 35 | 4 | n/a 1, yes 3 |
| `dfr-12-ntfs` | 44 | 33 | 11 | n/a 2, yes 9 |
| `dfr-13-ntfs` | 239 | 121 | 118 | contested 42, n/a 5, no 5, partial 18, yes 48 |
| `dfr-14-ntfs` | 47 | 36 | 11 | n/a 5, yes 6 |
| `dfr-15-ntfs` | 38 | 38 | 0 | - |
| `dfr-16-ntfs` | 1058 | 1058 | 0 | - |
| `dfr-17-ntfs` | 117 | 117 | 0 | - |

A few images have a test of their own:

- `dfr-04` has 24 names in Devanagari, Arabic, Persian, Hebrew, Korean, Japanese, Chinese, Cyrillic and German.
- In `dfr-07-one`, `Castor.txt` was overwritten by `Eltanin.txt` and then `Eltanin.txt` was deleted as well. Both come out as `contested`, the export exits with 1, the exported bytes read `File Eltanin.txt`, and `clusters_likely_owner` points at the `Eltanin.txt` record.
- In `dfr-07-two` the overwriting file is still there, so `Castor.txt` is `reallocated`.
- `dfr-10` record 847 is a 988 MB file with 137 runs and its name in an extension record. The path has to be `box/FILL.TXT`.
- `dfr-11-compress`: three deleted LZNT1 files are recovered, and each contains its own name.
- `dfr-09` and `dfr-12`: 260 and 12 deleted files are exported, same check.
- `dfr-17`: paths nine directories deep.

### NIST CFReDS, Hacking Case

Page: https://cfreds-archive.nist.gov/Hacking_Case.html (US Government work, public domain)

A Windows XP laptop (Dell Latitude CPi) imaged in August 2004 with SafeBack/dd in 650 MB segments. MBR disk, one NTFS partition at sector 63, 512-byte clusters.

| | |
|---|---|
| Joined image | 4,871,301,120 bytes |
| MD5, as published | `aee4fcd9301c03b3b054623ca261959a` |
| SHA-256 | `65e2002fed0b286f49541c7e97dcec0dda913d51a063ceeed86782bdacda2312` |
| `$MFT` | 12,305 records, SHA-256 `01ee1ecdf7206b82354cfa51090272df057d04a0114005388791007a98cc2e87` |

| Segment | Bytes | SHA-256 |
|---|---:|---|
| `SCHARDT.001` | 666,238,976 | `358c23312927693a916d0d514e3b44afd45d9358f0622aa0dac7e1e1008a8f0c` |
| `SCHARDT.002` | 666,238,976 | `bef9f7fd39abc1f8e52c7b532b552c7f36c8e5ae8ffb22695cfae3d7a621a292` |
| `SCHARDT.003` | 666,238,976 | `37238e7067145ff3c4b2686bd87d6b14d86f0114af4df1366cb726c84d673b4e` |
| `SCHARDT.004` | 666,238,976 | `b665818259fe34789bae514bd182940c745d73e83527ffb04abac32631d949d3` |
| `SCHARDT.005` | 666,238,976 | `d7f5109fb7ae257945ae69952f5751e49cbe8f920f08cef24b1f0b1e362227fd` |
| `SCHARDT.006` | 666,238,976 | `bcd15a7a7c0522600afee9c83c298072ed9ce2b5a03a4620c21c2b016005148f` |
| `SCHARDT.007` | 666,238,976 | `bcd15a7a7c0522600afee9c83c298072ed9ce2b5a03a4620c21c2b016005148f` |
| `SCHARDT.008` | 207,628,288 | `7a944d162497d5abbbd01899106ebee724cee23b4e8c59e536437b2656d59774` |

(Segments 006 and 007 really do have the same hash.)

This one matters because it is a complete system volume and not a small lab image: 12,183 rows, 767 directories, 2,203 LZNT1-compressed files and 74 records with an `$ATTRIBUTE_LIST`. The tests check the baseline, the `$MFT` hash, `$MFTMirr`, ten paths known from the published case (the `Mr. Evil` profile, the four executables in the recycle bin, `interception`, `irunin.ini`), and that 25 compressed executables decompress to something that starts with `MZ`.

## Results for 1.5.0

Run on 2026-11-15. The suite had 227 tests at that point.

| | Version |
|---|---|
| Windows 11 | Python 3.13.14 |
| Ubuntu 26.04 on WSL2 | Python 3.14.4 |
| The Sleuth Kit | 4.12.1 |
| MFTECmd (Eric Zimmerman), run on Windows | 2026.10.6 |
| `mft` (Omer Ben-Amram, Python bindings of the Rust parser) | 0.10.1 |
| `dissect.ntfs` (Fox-IT) | 3.16 |
| analyzeMFT | 3.1.1 |
| ntfs-3g, mkntfs, ntfsundelete | 2022.10.3 |

### Published answers

| Image | Result |
|---|---|
| DFTT #1 | 6 of 6 partitions at the published sectors |
| DFTT #3 | 8 of 8 reachable keywords in the stream the table names |
| DFTT #7 | 9 of 9 MD5 values, 10 of 10 deleted paths |
| DFTT #8 | 13 of 13 MD5 values |
| DFTT #10 | NTFS read from 3 of 3 images |
| Published image MD5 | 7 of 7 (DFTT #3, #7, #8, the three images of #10 and the Hacking Case) |

### The Sleuth Kit

28 of the 32 images. DFTT #1 has no NTFS, and The Sleuth Kit does not settle on a file system for the three DFTT #10 images.

| Check | Result |
|---|---|
| Allocated / deleted state, against `fls` | 15,359 of 15,360 records agree |
| Alternate data stream names | 15,360 of 15,360 agree |
| Paths and hard links | 15,268 of 15,360 agree, see below |
| Content, against `icat` | 14,344 of 14,344 streams byte-identical (8.56 GB) |
| of which deleted | 726 of 726 |
| of which LZNT1-compressed, Hacking Case | 2,203 files |
| `clusters_free`, against the `$Bitmap` extracted with `icat` | 705 of 705 |
| `$MFT` SHA-256, against `icat 0` | 28 of 28 |
| `$SI` timestamps | all agree except record 0 on 18 images and one reused record, see below |

All of the differences are on the Sleuth Kit side:

- 67 paths in the Hacking Case and 22 in `dfr-10`. `fls` also prints an older name that is still sitting in a directory index, for a record that belongs to a different file by now. Hacking Case record 333 is an example: `fls` shows `txtsetup.sif` next to `WINDOWS/bootstat.dat`, while `istat` shows one `$FILE_NAME` in the record. One of these leftover names is listed as deleted, and that is the single state mismatch.
- 2 paths in DFTT #3 and 1 in `dfr-14`. For a directory with an ADS, `fls` prints an additional `name/.` line.
- Record 0 timestamps. On the NIST DFR images the `$SI` times of `$MFT` are zero. MFTDigger prints 1601-01-01, The Sleuth Kit prints a date in 2076.

A word of caution on the content row. Byte-identical to `icat` is not the same as original content. For an overwritten file both tools simply read the same clusters. That situation is what `contested`, `reallocated` and `partially-reallocated` are for.

The Sleuth Kit also found 372 deleted names in directory index slack. MFTDigger reads only `$MFT` and cannot see those.

### mft, dissect.ntfs and analyzeMFT

31 images. Each parser gets the `$MFT` written by `extract-mft`, and all 15,638 rows are compared. 15,445 of them have a name (14,714 allocated, 731 deleted) and 15,585 have a `$STANDARD_INFORMATION`.

| Check | `mft` 0.10.1 | `dissect.ntfs` 3.16 | analyzeMFT 3.1.1 |
|---|---|---|---|
| Records compared | 15,638 | 15,638 | 15,591 |
| Sequence number, in use, directory | all agree | all agree | all agree |
| `$SI` timestamps | all agree (to 1 µs) | all agree (to 1 µs) | 3 differ (to 1 ms) |
| `$FN` timestamps | all agree | not compared | 1 differs |
| Alternate data stream names | all agree | not compared | not compared |
| File name | 2 differ | 2 differ | 309 differ |
| Parent record | all agree | not compared | 4 differ |
| Path, allocated | all agree | 1 differs | no path in the output |
| Path, deleted | 1 differs | 19 differ | no path in the output |
| Size of the unnamed stream | not compared | all agree | not compared |

Where they differ:

`mft`, 2 names. Hacking Case records 3690 and 3701 are directories with the long name in an extension record. `mft` shows the 8.3 name from the base record (`X86_MI~2.0_X`). MFTDigger and `istat` show the long one.

`mft`, 1 deleted path. DFTT #7 record 38, the file whose parent was reused. Both tools treat it as an orphan and just label it differently.

`dissect.ntfs`, 2 names and 1 path. `dfr-10` record 847 has its only name in an extension record and `dissect.ntfs` returns nothing for it. `dfr-15` record 37 has two hard links and the two tools pick a different one first.

`dissect.ntfs`, 19 deleted paths. 18 are files inside a deleted directory. `dissect.ntfs` prints `<broken_reference>` there because the sequence number of the freed parent no longer matches. MFTDigger resolves the parent and ends up with the same path as The Sleuth Kit. Number 19 is the DFTT #7 orphan again.

analyzeMFT, 309 names. 289 are the 8.3 name where MFTDigger has the long name. In 15 a single character is wrong, always where the name crosses a sector boundary inside the record, which is what you get when the update sequence has not been applied. The last five are the three records in the next paragraph, the extension-record name in `dfr-10` and one hard link.

analyzeMFT, timestamps and parents. Three Hacking Case records (3711, 3713, 6562) come out with impossible values: `Invalid timestamp`, the year 5546, parent 34359742464. Record 9177 has one invalid `$FN` time. `mft` agrees with MFTDigger on all four; The Sleuth Kit and `dissect.ntfs` agree on the three `$SI` values. The fourth parent mismatch is `dfr-10` record 847 again.

analyzeMFT also marks record 0 as `Invalid` on 27 of the 31 images, so record 0 is left out for this tool, and 16 nameless reserved records from two images are missing from its output.

### MFTECmd

31 images, run with `--at --sn` so that every `$FILE_NAME` attribute ends up in the CSV. Timestamps are compared at the full 100 ns.

| Check | Result |
|---|---|
| Records compared | 15,445 of 15,638; the other 193 have no `$FILE_NAME` and are not in the MFTECmd output |
| Sequence number, in use, directory | all agree |
| `$SI` timestamps | all agree |
| `$FN` timestamps | all agree |
| `$LogFile` sequence number | all agree |
| File name and parent record | all agree |
| Alternate data stream names | all agree |
| Path, allocated | all agree |
| Path, deleted | 1 differs |
| Size of the unnamed stream | 32 differ |

The 32 sizes: 31 are `$Secure`, one per image. It has no unnamed stream. MFTECmd puts the size of `$SDS` on the file row, MFTDigger prints 0 and lists `$SDS` as a stream. The other one is Hacking Case record 3675, `WINDOWS/setuplog.txt`. Its `$DATA` attribute is spread over extension records only. MFTECmd shows 0, MFTDigger shows 706,832, and the exported file has the same SHA-256 as the `icat` output.

The deleted path is once more DFTT #7 record 38. MFTECmd calls it `PathUnknown\Directory with ID 0x00000025-00000001`.

MFTECmd leaves a zero timestamp empty where MFTDigger prints 1601-01-01. I counted those as equal.

### ntfsundelete

30 volumes. `ntfsundelete --scan` lists deleted records and how much of each is still free. Images with a partition table need a loop device, so this part wants root.

| Check | Result |
|---|---|
| Deleted records listed by both | 800 of 800 |
| File names | all agree |
| Recoverable, not recoverable, partly recoverable | all agree, apart from the two cases below |
| Deleted files that share clusters with another deleted file | 52, `contested` in MFTDigger, 100% in ntfsundelete |
| Deleted LZNT1-compressed files | 3, recovered by MFTDigger, 0% in ntfsundelete |

ntfsundelete lists 784 more entries. Those are zero-filled MFT slots, and MFTDigger does not print empty slots.

### Bugs this found in MFTDigger

Three, all fixed in 1.5.0, each with a test on the synthetic volume and on the image that exposed it:

- Children of a directory with its long name in an extension record were listed under the 8.3 name. Found on the Hacking Case when `mft` and `dissect.ntfs` were compared.
- Exporting a directory with an ADS wrote the stream but reported `incomplete`. Found on DFTT #3.
- An extended partition table with more than one partition entry was read only up to the first. Found on DFTT #1.

MFTECmd was added last and did not turn up anything new.

### ntfs-3g volume

`test_ntfs3g.py` formats a 256 MB volume, writes files through `ntfs-3g` while recording each SHA-256, deletes one directory tree and unmounts.

| Check | Result |
|---|---|
| Live files, against the hash recorded at write time | 498 of 498 |
| Alternate data streams | 2 of 2 |
| Deleted files, against the hash recorded before deletion | 41 of 41 |
| Compressed layouts (compressible, mixed, incompressible tail, exactly one unit, smaller than a cluster) | 7 of 7 |
| Same volume inside a GPT disk | identical rows |
| Against The Sleuth Kit | 624 records and 550 streams, no difference except the record 0 timestamp |

### Windows and Linux

The `dump` output for `dfr-04`, `dfr-10`, `dfr-13` and the Hacking Case, and the bodyfile for DFTT #7, have the same SHA-256 on Windows (Python 3.13) and Linux (Python 3.14).
