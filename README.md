# `fs2rust` — 24-Tool Pure-Rust Filesystem Search, NTFS/USN/SMART & Structured Data Suite

Part of the **GUAP** Ecosystem (`guap.ca`) • [**Project Hub & Web Documentation: https://guap.ca/fs2rust/**](https://guap.ca/fs2rust/) • [**Project Wiki**](https://github.com/adpaolucci/fs2rust/wiki)

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Rust: 2024](https://img.shields.io/badge/Rust-2024%20(1.88%2B)-orange.svg)](Cargo.toml)
[![Workspace: 9 Crates](https://img.shields.io/badge/Workspace-9%20Crates-emerald.svg)](Cargo.toml)
[![GUI: WinSafe Win32 + Iced 0.14](https://img.shields.io/badge/GUI-WinSafe%20Win32%20%2B%20Iced%200.14-cyan.svg)](crates/fs2rust-win32)
[![MCP: stdio JSON-RPC](https://img.shields.io/badge/MCP-stdio%20JSON--RPC%202.0-purple.svg)](crates/fs2rust-mcp)

Ready-to-submit **WinGet** & **Homebrew** manifests live in [`packaging/`](packaging/README.md).

**`fs2rust`** is a 100% pure-Rust 24-tool filesystem search, NTFS/USN/ATA SMART telemetry, and structured CSV/EXIF/HTML/vCard data suite built on [`guap-kit`](https://github.com/adpaolucci/guap-kit):
1. **`fs2rust-win32`** (**WinSafe `0.0.29`**) — Native zero-GPU Win32 virtual list console (`LVS_OWNERDATA`, ComCtl v6, Per-Monitor DPI v2).
2. **`fs2rust-iced`** (**Iced `0.14`**) — Cross-platform GUI (`wgpu` + `tiny-skia` CPU fallback).
3. **`fs2rust`** — Unified `clap 4.6` CLI (`search`, `ntfs`, `data`, `mcp`, `gui`, `action`, `list`, `export`, `diag`) with `--offline` fixtures, `GuapQuery` filtering, `--dry-run`, and Merkle custody exports.
4. **`fs2rust-mcp`** — Policy-gated JSON-RPC 2.0 (`2024-11-05`) `stdio` MCP server exposing **32 tools** (**24** read-only `TableProvider`s + **8** mutating `ActionCommand`s).

---

## Comparison: `fs2rust` vs. Legacy File & NTFS Utilities

| Capability | `fs2rust` | Legacy Search / Disk / Data Tools | Ad-Hoc PowerShell Scripts |
|---|---|---|---|
| **Unified Coverage** | **24 tools across `search` (6), `ntfs` (11), and `data` (7)** | 24 standalone GUIs | Fragile script pipelines |
| **Pure-Rust Binary Parsers** | **`$UsnJrnl` `USN_RECORD_V2`/`V3`, ATA SMART 512B + NVMe, JPEG/TIFF EXIF, `[MS-SHLLINK]`, HTML, VCF/LDIF** | Mixed closed-source parsers | Missing binary decoders |
| **Single-Pass Multi-Hash** | **MD5, SHA-1, SHA-256, SHA-512, and CRC32 in one I/O pass (`hash_files`)** | Separate passes per tool | High disk I/O overhead |
| **CSV Formula & Custody Safety** | **RFC-4180 formula neutralization + SHA-256/512 Merkle `CustodyManifest`** | Unneutralized CSV cells | No chain of custody |
| **Mutation & Policy Safety** | **`--dry-run` + `ReadOnlyOnly` `-32003` gate before bulk timestamp, `.lnk`, ADS, or drive-letter changes** | Direct file/volume edits | Manual confirmation |

---

## Workspace Architecture (9 Crates)

```text
fs2rust/
├── Cargo.toml                  # 9-crate workspace (Edition 2024, MSRV 1.88, Apache-2.0)
├── deny.toml                   # cargo-deny license & advisory policy
├── mcp.json / smithery.yaml    # Standard MCP & Smithery manifests (32 endpoints)
├── metadata.json               # Machine-readable 24-tool manifest
├── packaging/                  # WinGet & Homebrew manifests
└── crates/
    ├── fs2rust-core/           # `#![forbid(unsafe_code)]` FileSystemOps trait (OS/Mock), PolicyContext, wildcards, FILETIME
    ├── fs2rust-search/         # `#![forbid(unsafe_code)]` 6 search, bulk time, folder report, [MS-SHLLINK], & hash tools + 4 actions
    ├── fs2rust-ntfs/           # 11 NTFS drives, disk counters, ETW file/error watch, SMART, ADS, links, props & USN tools + 4 actions
    ├── fs2rust-data/           # `#![forbid(unsafe_code)]` 7 CSV, table diff, query, EXIF, codegen, HTML2Text & contact tools
    ├── fs2rust-report/         # guap-export integration (7 formats) + SHA-256/512 Merkle CustodyManifest
    ├── fs2rust-mcp/            # Policy-gated MCP JSON-RPC 2.0 stdio server (`fs2rust-mcp`, 32 endpoints)
    ├── fs2rust-cli/            # Unified CLI (`fs2rust`)
    ├── fs2rust-win32/          # Native Win32 GUI (`fs2rust-win32`)
    └── fs2rust-iced/           # Cross-platform Iced 0.14 GUI (`fs2rust-iced`)
```

---

## 24-Tool Matrix & 32 MCP Endpoints

### `fs2rust-search` (6 `#![forbid(unsafe_code)]` Tools + 4 Mutating Actions)
| CLI Subcommand | Diagnostic Scope | Mechanism | MCP Policy |
|---|---|---|---|
| `search files` | File & Content Search | Parallel wildcard/regex search & duplicate grouping | `search_files` |
| `search bulk-time` | Bulk Timestamp & Attributes | Inspect/modify MACB timestamps & DOS attributes | `bulk_file_time` + `bulk_file_time_apply` `[MUT]` |
| `search folder-time` | Folder Timestamp Update | Bottom-up folder timestamp computation | `folder_time_update` + `folder_time_update_apply` `[MUT]` |
| `search report` | Subtree Size Report | Logical size, size-on-disk & file-count aggregator | `folders_report` |
| `search shortcuts` | Shortcut Inspector | `[MS-SHLLINK]` `.lnk` parser & broken target validator | `shortcuts_view` + `shortcuts_fix_target`/`shortcuts_delete` `[MUT]` |
| `search hash` | Multi-Algorithm Hasher | Single-pass MD5, SHA-1, SHA-256, SHA-512 & CRC32 | `hash_files` |

### `fs2rust-ntfs` (11 Tools + 4 Mutating Actions)
| CLI Subcommand | Diagnostic Scope | Mechanism / OS API | MCP Policy |
|---|---|---|---|
| `ntfs drives` | Logical Drives & Mounts | Logical drives, volume GUIDs & `MountedDevices` | `drive_letter_view` + `drive_letter_assign`/`remove` `[MUT]` |
| `ntfs counters` | Disk Performance Counters | `IOCTL_DISK_PERFORMANCE` counters & queue depth | `disk_counters_view` |
| `ntfs file-watch` | File Activity Monitor | ETW `Microsoft-Windows-Kernel-File` monitor | `file_activity_watch` |
| `ntfs folder-watch` | Folder Change Monitor | `ReadDirectoryChangesW` live change stream | `folder_changes_view` |
| `ntfs access-err` | File Access Errors | ETW Kernel-File non-zero `NTSTATUS` failures | `file_access_error_view` |
| `ntfs app-io` | Process I/O Counters | Per-process `GetProcessIoCounters` I/O throughput | `app_read_write_counter` |
| `ntfs smart` | ATA / NVMe S.M.A.R.T. | ATA S.M.A.R.T. 512B checksum & NVMe health log | `disk_smart_view` |
| `ntfs ads` | Alternate Data Streams | NTFS ADS (`FindFirstStreamW` / `$MFT`) | `alternate_stream_view` + `alternate_stream_delete` `[MUT]` |
| `ntfs links` | NTFS Links & Reparse | Symlinks, junctions, reparse points & hardlinks | `ntfs_links_view` |
| `ntfs props` | Shell Property System | Windows Property System (`IPropertyStore`) | `property_system_view` + `property_system_set` `[MUT]` |
| `ntfs usn` | *NTFS USN Journal* | Pure-Rust `$UsnJrnl:$J` `USN_RECORD_V2`/`V3` decoder | `usn_journal_view` |

### `fs2rust-data` (7 `#![forbid(unsafe_code)]` Read-Only Tools)
| CLI Subcommand | Diagnostic Scope | Capabilities | MCP Tool ID |
|---|---|---|---|
| `data csv` | CSV / TSV Viewer | Auto-delimiter & typed CSV/TSV viewer | `fs2rust.data.csv_file_view` |
| `data diff` | Table Diff | Row-keyed CSV/TSV/JSONL table comparison | `fs2rust.data.table_text_compare` |
| `data query` | Tabular Query Evaluator | Tabular boolean/regex filter expression query evaluator | `fs2rust.data.query` |
| `data exif` | EXIF Metadata Viewer | Pure-Rust JPEG APP1/TIFF IFD0/ExifIFD/GPS parser | `fs2rust.data.exif_data_view` |
| `data codegen` | Template Code Generator | Template snippet generator from CSV/JSON rows | `fs2rust.data.simple_code_generator` |
| `data html2text` | HTML-to-Text Extractor | Pure-Rust HTML-to-plaintext & link footnote extractor | `fs2rust.data.html_as_text` |
| `data addr` | Contact Book Reader | Pure-Rust `.vcf` vCard, `.ldif` & contact `.csv` reader | `fs2rust.data.addr_view` |

---

## Usage Examples (CLI, Dual GUI & MCP)

```powershell
# List all 24 tools and 8 policy-gated mutating actions
fs2rust list
fs2rust diag

# Structured data, EXIF, hashing & offline NTFS USN/SMART inspection
fs2rust data csv --offline --path sample_data.csv --format json
fs2rust data diff --offline --left left.csv --right right.csv --format markdown
fs2rust data exif --offline --path photo.jpg --format json
fs2rust search hash --offline --target .\evidence --format csv --export hashes.csv --custody hashes.custody.json
fs2rust --offline --format json ntfs smart
fs2rust --offline --format json ntfs usn

# Policy-gated mutation preview vs confirmation
fs2rust --dry-run action alternate_stream_delete --args '{"file_path":"sample.txt","stream_name":"Zone.Identifier"}'

# Launch GUIs or MCP server
fs2rust gui              # Native Win32 GUI (fs2rust-win32)
fs2rust gui --iced       # Cross-platform Iced 0.14 GUI (fs2rust-iced)
fs2rust mcp --tools      # Dump all 32 MCP tool schemas (24 read-only + 8 mutating)
fs2rust mcp              # Start ReadOnlyOnly JSON-RPC 2.0 stdio server (see mcp.json)
```

---

## Building & Testing

```powershell
cargo test --workspace --offline
cargo build --workspace --release --offline
```

---

## Wiki Documentation

Browse the full [`fs2rust` Project Wiki](https://github.com/adpaolucci/fs2rust/wiki):
- [Architecture](https://github.com/adpaolucci/fs2rust/wiki/Architecture)
- [NTFS, USN, SMART, Data & 24-Tool Matrix](https://github.com/adpaolucci/fs2rust/wiki/NTFS-USN-SMART-Data-and-24-Tool-Matrix)
- [CLI Reference](https://github.com/adpaolucci/fs2rust/wiki/CLI-Reference)
- [Dual-GUI Guide (Win32 & Iced)](https://github.com/adpaolucci/fs2rust/wiki/Dual-GUI-Guide)
- [GUI Framework Decision & Comparison](https://github.com/adpaolucci/fs2rust/wiki/GUI-Framework-Decision-and-Comparison)
- [MCP Server Guide](https://github.com/adpaolucci/fs2rust/wiki/MCP-Server-Guide)
- [Reports & Forensic Exports](https://github.com/adpaolucci/fs2rust/wiki/Reports-and-Forensic-Exports)
- [Validation Rules & Status Codes](https://github.com/adpaolucci/fs2rust/wiki/Validation-Rules-and-Status-Codes)
- [Building, Testing & CI/CD](https://github.com/adpaolucci/fs2rust/wiki/Building-Testing-and-CI-CD)
- [Security & Stability](https://github.com/adpaolucci/fs2rust/wiki/Security-and-Stability)

## License

Licensed under the [**Apache License, Version 2.0**](LICENSE). See [`NOTICE`](NOTICE) for attribution.
